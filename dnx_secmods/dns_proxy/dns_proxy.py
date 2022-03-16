#!/usr/bin/python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import DNS, DNS_CAT, TLD_CAT, CONN
from dnx_gentools.def_namedtuples import DNS_REQUEST_RESULTS

from dnx_iptools.packet_classes import NFQueue

from dns_proxy_server import DNSServer
from dns_proxy_automate import ProxyConfiguration
from dns_proxy_packets import DNSPacket, ProxyResponse
from dns_proxy_log import Log

__all__ = (
    'DNSProxy',
)


CAT_LOOKUP: Callable[[tuple[int]], int] = NotImplemented  # will be assigned by __init__ prior to running
LOCAL_RECORD: Callable[[str], ...] = DNSServer.dns_records.get
PREPARE_AND_SEND = ProxyResponse.prepare_and_send

# =====================
# MAIN DNS PROXY CLASS
# =====================
#   ProxyConfiguration - provides config management between memory and filesystem
#   NFQueue - provides packet data from Linux Netfilter NFQUEUE sub-system
# =====================
class DNSProxy(ProxyConfiguration, NFQueue):

    _packet_parser: ClassVar[ProxyParser] = DNSPacket.netfilter_recv

    __slots__ = ()

    def _setup(self):

        Log.informational(f'{self.__class__.__name__} initialization started.')

        self.__class__.set_proxy_callback(func=inspect)

        self.configure()

        ProxyResponse.setup(Log, self.__class__, protocol_ports=False)

        Log.notice(f'{self.__class__.__name__} initialization complete.')

    # pre-check will filter out invalid packets, ipv6 records, and local dns records
    def _pre_inspect(self, packet: DNSPacket) -> bool:

        # local records will continue directly to the dns server
        if LOCAL_RECORD(packet.qname):
            packet.nfqueue.accept()

        elif (packet.action is CONN.DROP):
            packet.nfqueue.drop()

        elif (packet.qtype in [DNS.A, DNS.NS]):
            return True

        # refusing ipv6 dns record types as policy
        elif (packet.qtype == DNS.AAAA):
            PREPARE_AND_SEND(packet)

            packet.nfqueue.drop()

        return False


# =================
# INSPECTION LOGIC
# =================
# direct references to proxy class data structure methods
_ip_whitelist_get = DNSProxy.whitelist.ip.get
_tld_get = DNSProxy.signatures.tld.get
_enabled_categories = DNSProxy.signatures.en_dns

_dns_whitelist = DNSProxy.whitelist.dns
_dns_blacklist = DNSProxy.blacklist.dns
_dns_keywords  = DNSProxy.signatures.keyword

def inspect(packet: DNSPacket):

    request_results = _inspect(packet)

    if (not request_results.redirect):
        packet.nfqueue.accept()

    else:
        packet.nfqueue.drop()

        PREPARE_AND_SEND(packet)

    Log.log(packet, request_results)

# this is where the system decides whether to block dns query/sinkhole or to allow. notification will be done
# via the request tracker upon returning the signature scan result
def _inspect(packet: DNSPacket) -> DNS_REQUEST_RESULTS:
    # NOTE: request_ident[0] is a string representation of ip addresses. this is currently needed as the whitelists
    #  are stored in this format and we have since moved away from this format on the back end.
    # TODO: in the near-ish future, consider storing ip whitelists as integers to conform to newer standards.
    whitelisted = _ip_whitelist_get(packet.request_identifier[0], False)

    enum_categories = []

    # NOTE: dns whitelist does not override tld blocks at the moment. this is most likely the desired setup
    # TLD (top level domain) block | after first index will pass nested to allow for continue
    if _tld_get(packet.tld):

        return DNS_REQUEST_RESULTS(True, 'tld filter', TLD_CAT[packet.requests[0]])

    category: DNS_CAT
    # signature/ blacklist check.
    for enum_request in packet.requests[1:]:

        # NOTE: allowing malicious category overrides (for false positives)
        if (enum_request in _dns_whitelist):

            return DNS_REQUEST_RESULTS(False, None, None)

        # ip whitelist overrides configured blacklist
        if (not whitelisted and enum_request in _dns_blacklist):

            return DNS_REQUEST_RESULTS(True, 'blacklist', DNS_CAT.time_based)

        # determining the domain category
        category = DNS_CAT(CAT_LOOKUP(enum_request))
        if (category is not DNS_CAT.NONE) and _block_query(category, whitelisted):

            return DNS_REQUEST_RESULTS(True, 'category', category)

        # adding the returned cat to the enum list. this will be used to identify categories for allowed requests.
        enum_categories.append(category)

    # Keyword search within query name will block if match
    req = packet.qname
    keyword_match = [(kwd, cat) for kwd, cat in _dns_keywords if kwd in req]
    if (keyword_match):
        return DNS_REQUEST_RESULTS(True, 'keyword', keyword_match[0][1])

    # pulling the most specific category that is not none otherwise returned value will be DNS_CAT.NONE.
    for category in enum_categories:
        if category is not DNS_CAT.NONE: break

    else: category = DNS_CAT.NONE

    # DEFAULT ACTION | ALLOW
    return DNS_REQUEST_RESULTS(False, None, category)

# grabbing the request category and determining whether the request should be blocked. if so, returns general
# information for further processing
def _block_query(category: DNS_CAT, whitelisted: bool) -> bool:
    # signature match, but blocking is disabled for the category | ALLOW
    if (category not in _enabled_categories):
        return False

    # signature match and not whitelisted or whitelisted and cat is high risk | BLOCK
    if (not whitelisted or category in [DNS_CAT.malicious, DNS_CAT.cryptominer]):
        return True

    # default action | ALLOW
    return False
