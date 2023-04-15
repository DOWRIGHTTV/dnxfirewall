#!/usr/bin/python3

from __future__ import annotations

from threading import Thread

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RUN_FOREVER, INSPECT_PACKET, DONT_INSPECT_PACKET
from dnx_gentools.def_enums import DNS, DNS_CAT, TLD_CAT
from dnx_gentools.def_namedtuples import DNS_REQUEST_RESULTS

from dnx_iptools.packet_classes import NFQueue

from dns_proxy_server import DNSServer
from dns_proxy_automate import ProxyConfiguration
from dns_proxy_packets import DNSPacket, ProxyResponse
from dns_proxy_log import Log

__all__ = (
    'DNSProxy',
)

PREPARE_AND_SEND = ProxyResponse.prepare_and_send

# 1 for 1 match, slice must be same size matching string
# START    ->  ">"
# END      ->  "<"
# AT       ->  ":" (i1:i2 slice)

# membership test
# IN       ->  "?"
# IN START ->  "]" (:i1 slice)
# IN END   ->  "[" (-i1: slice)

# domain rewrites
# no TLD   ->  "@"

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
        self.configure()

        ProxyResponse.setup(Log)

        for i in range(self.DEFAULT_THREAD_COUNT):
            Thread(target=self.inspection_worker, args=(i,)).start()

    def inspection_worker(self, i: int) -> NoReturn:
        Log.informational(f'[proxy/worker][{i}] inspection thread started')

        inspection_queue_get = self.inspection_queue.get

        for _ in RUN_FOREVER:
            packet: DNSPacket = inspection_queue_get()

            # fast path for certain conditions
            if not pre_inspect(packet):
                continue

            request_results = inspect(packet)

            if (not request_results.redirect):
                packet.nfqueue.accept()

            else:
                packet.nfqueue.drop()

                PREPARE_AND_SEND(packet)

            Log.log(packet, request_results)


# =================
# INSPECTION LOGIC
# =================
# will be assigned by __init__ prior to running
CAT_LOOKUP: Callable[[int], int] = NotImplemented
LOCAL_RECORD: Callable[[str], ...] = DNSServer.dns_records.get

# direct references to proxy class data structure methods
_ip_whitelist_get = DNSProxy.whitelist.ip.get
_tld_get = DNSProxy.signatures.tld.get
_enabled_categories = DNSProxy.signatures.en_dns

_dns_whitelist = DNSProxy.whitelist.dns
_dns_blacklist = DNSProxy.blacklist.dns
_dns_keywords  = DNSProxy.signatures.keyword

# pre-check will filter out invalid packets, ipv6 records, and local dns records
def pre_inspect(packet: DNSPacket) -> bool:
    # local records will continue directly to the dns server
    if LOCAL_RECORD(packet.qname):
        packet.nfqueue.accept()

    elif (packet.qtype in [DNS.A, DNS.NS]):
        return INSPECT_PACKET

    # refusing ipv6 dns record types as policy
    # elif (packet.qtype == DNS.AAAA):
    #     PREPARE_AND_SEND(packet)
    #
    #     packet.nfqueue.drop()

    return DONT_INSPECT_PACKET


# this is where the system decides whether to block dns query/sinkhole or to allow.
def inspect(packet: DNSPacket) -> DNS_REQUEST_RESULTS:
    # NOTE: request_ident[0] is a string representation of ip addresses. this is currently needed as the whitelists
    #  are stored in this format and we have since moved away from this format on the back end.
    # TODO: in the near-ish future, consider storing ip whitelists as integers to conform to newer standards.
    whitelisted = _ip_whitelist_get(packet.request_identifier[0], False)

    enum_categories = []

    # TLD (top level domain) block
    # url whitelist does not override tld blocks at the moment.
    if _tld_get(packet.tld):

        return DNS_REQUEST_RESULTS(True, 'tld filter', TLD_CAT[packet.tld])

    category: DNS_CAT
    # signature/ blacklist check.
    for enum_request in packet.requests:

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

    # TODO: expand keyword search to be able to specify locations of sub-string ex. [>start, <end]
    #  (the endian points towards which side has the remainder of the string.)
    # Keyword search within query name will block if match
    req = packet.qname
    if (keyword_match := [(kwd, cat) for kwd, cat in _dns_keywords if kwd in req]):
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
    if (not whitelisted or category in [DNS_CAT.malicious, DNS_CAT.crypto_miner]):
        return True

    # default action | ALLOW
    return False
