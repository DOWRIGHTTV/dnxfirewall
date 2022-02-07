#!/usr/bin/python3

from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_BLACKLIST, DNS_REQUEST_RESULTS, DNS_SIGNATURES, DNS_WHITELIST
from dnx_gentools.signature_operations import generate_domain

from dnx_iptools.dnx_trie_search import generate_recursive_binary_search
from dnx_iptools.packet_classes import NFQueue
from dnx_iptools.protocol_tools import int_to_ip

from dnx_secmods.dns_proxy.dns_proxy_automate import Configuration
from dnx_secmods.dns_proxy.dns_proxy_log import Log
from dnx_secmods.dns_proxy.dns_proxy_packets import ProxyRequest
from dnx_secmods.dns_proxy.dns_proxy_server import DNSServer

LOG_NAME = 'dns_proxy'

dns_record_get = DNSServer.dns_records.get

class DNSProxy(NFQueue):
    # dns | ip
    whitelist = DNS_WHITELIST(
        {}, {}
    )
    blacklist = DNS_BLACKLIST(
        {}
    )
    # en_dns | tld | keyword | NOTE: dns signatures are contained within the binary search extension as a closure
    signatures = DNS_SIGNATURES(
        {DNS_CAT.doh}, {}, []
    )

    _dns_sig_ref = None
    _packet_parser = ProxyRequest.netfilter_recv  # alternate constructor

    __slots__ = (
        '_dns_record_get',
    )

    @classmethod
    def _setup(cls):
        Configuration.proxy_setup(cls)
        cls.set_proxy_callback(func=inspect)

        Log.notice(f'{cls.__name__} initialization complete.')

    # pre-check will filter out invalid packets or local dns records (no tld)
    def _pre_inspect(self, packet: ProxyRequest) -> bool:
        if (packet.qr != DNS.QUERY):
            return False

        if (packet.qtype in [DNS.A, DNS.NS] and not dns_record_get(packet.request)):
            return True

        # refusing ipv6 dns record types as policy
        if (packet.qtype == DNS.AAAA):
            packet.generate_proxy_response()
            send_to_client(packet)

        return False

# GENERAL PROXY FUNCTIONS
def send_to_client(packet: ProxyRequest):
    try:
        packet.sendto(packet.send_data, (int_to_ip(packet.src_ip), 0))
    except OSError:
        pass


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

def inspect(packet: ProxyRequest):

    request_results = _inspect(packet)

    if (not request_results.redirect):
        packet.nfqueue.accept()

    else:
        packet.nfqueue.drop()

        packet.generate_proxy_response()

        send_to_client(packet)

    Log.log(packet, request_results)

# this is where the system decides whether to block dns query/sinkhole or to allow. notification will be done
# via the request tracker upon returning signature scan result
def _inspect(packet: ProxyRequest) -> DNS_REQUEST_RESULTS:
    # NOTE: request_ident[0] is a string representation of ip addresses. this is currently needed as the whitelists
    # are stored in this format and we have since moved away from this format on the back end.
    # TODO: in the near-ish future, consider storing ip whitelists as integers to conform to newer standards.
    whitelisted = _ip_whitelist_get(packet.request_identifier[0], False)
    enum_categories = []

    requests = packet.requests

    # NOTE: dns whitelist does not override tld blocks at the moment. this is most likely the desired setup
    # TLD (top level domain) block | after first index will pass nested to allow for continue
    if _tld_get(packet.tld):

        return DNS_REQUEST_RESULTS(True, 'tld filter', TLD_CAT[requests[0]])

    # signature/ blacklist check.
    # DNS_REQUEST_RESULTS(redirect, block type, category)
    for enum_request in requests[1:]:

        # NOTE: allowing malicious category overrides (for false positives)
        if (enum_request in _dns_whitelist):

            return DNS_REQUEST_RESULTS(False, None, None)

        # ip whitelist overrides configured blacklist
        if (not whitelisted and enum_request in _dns_blacklist):

            return DNS_REQUEST_RESULTS(True, 'blacklist', DNS_CAT.time_based)

        # pulling domain category if signature present. | NOTE: this is now using imported cython function factory
        category = DNS_CAT(_recursive_binary_search(enum_request))
        if (category is not DNS_CAT.NONE) and _block_query(category, whitelisted):

            return DNS_REQUEST_RESULTS(True, 'category', category)

        # adding returned cat to enum list. this will be used to identify categories
        # for allowed requests.
        enum_categories.append(category)

    # Keyword search within domain || block if match
    for keyword, category in _dns_keywords:
        if (keyword in packet.request):

            return DNS_REQUEST_RESULTS(True, 'keyword', category)

    # pulling most specific category that is not none otherwise returned value will be DNS_CAT.NONE.
    for category in enum_categories:
        if category is not DNS_CAT.NONE: break

    else: category = DNS_CAT.NONE

    # DEFAULT ACTION | ALLOW
    return DNS_REQUEST_RESULTS(False, None, category)

# grabbing the request category and determining whether the request should be blocked. if so, returns general
# information for further processing
def _block_query(category: DNS_CAT, whitelisted: bool) -> bool:
    # signature match, but blocking disabled for the category | ALLOW
    if (category not in _enabled_categories):
        return False

    # signature match, not whitelisted, or whitelisted and cat is bad | BLOCK
    if (not whitelisted or category in [DNS_CAT.malicious, DNS_CAT.cryptominer]):
        return True

    # default action | ALLOW
    return False


if (INIT_MODULE):
    dns_cat_signatures = generate_domain(Log)

    # using cython function factory to create binary search function with module specific signatures
    signature_bounds = (0, len(dns_cat_signatures)-1)

    # TODO: collisions were found in the geolocation filtering data structure. this has been fixed for geolocation and
    #  standard ip category filtering, but has not been investigated for dns signatures. due to the way the signatures
    #  are compressed, it is much less likely to happen to dns signatures. (main issue were values in multiples of 10
    #  because of the multiple 0s contained).
    #  to be safe, run through the signatures, generate bin and host id, then check for host id collisions within a bin.
    _recursive_binary_search = generate_recursive_binary_search(dns_cat_signatures, signature_bounds)

    Log.run(
        name=LOG_NAME
    )

    # starting server before proxy because proxy will block server will not
    DNSServer.run(Log, threaded=False, always_on=True)
    DNSProxy.run(Log, q_num=Queue.DNS_PROXY)
