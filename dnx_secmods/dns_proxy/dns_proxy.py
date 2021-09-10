#!/usr/bin/python3

import os
import socket
import sys

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import *  # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.def_namedtuples import DNS_BLACKLIST, DNS_REQUEST_RESULTS, DNS_SIGNATURES, DNS_WHITELIST

from dnx_secmods.dns_proxy.dns_proxy_automate import Configuration
from dnx_secmods.dns_proxy.dns_proxy_log import Log
from dnx_secmods.dns_proxy.dns_proxy_packets import ProxyRequest
from dnx_secmods.dns_proxy.dns_proxy_server import DNSServer

from dnx_iptools.dnx_trie_search import generate_recursive_binary_search  # pylint: disable=import-error, no-name-in-module
from dnx_iptools.packet_classes import Listener

LOG_NAME = 'dns_proxy'


class DNSProxy(Listener):
    # dns | ip
    whitelist = DNS_WHITELIST(
        {}, {}
    )
    blacklist = DNS_BLACKLIST(
        {}
    )
    # en_dns | dns | tld | keyword | NOTE: dns signatures are now contained within the binary search extension as a closure
    signatures = DNS_SIGNATURES(
        {DNS_CAT.doh}, {}, []
    )

    _dns_sig_ref = None

    # assigning locally so make the code alittle more maintainable if class or methods change outside of the
    # proxy which would otherwise require [potential] extreme internal modification.
    _packet_parser = ProxyRequest.interface # alternate constructor
    _dns_server    = DNSServer
    _request_tracker_insert = DNSServer.REQ_TRACKER.insert

    __slots__ = (
        '_dns_record_get',
    )

    @classmethod
    def _setup(cls):
        Configuration.proxy_setup(cls)
        cls.set_proxy_callback(func=Inspect.dns)

        Log.notice(f'{cls.__name__} initialization complete.')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._dns_record_get = self._dns_server.dns_records.get

    @classmethod
    def notify_server(cls, request_identifier, decision):
        '''add the client address and proxy decision to the reference request results dictionary. this reference
        is controlled through a local class variable assignment.'''

        cls._request_tracker_insert(request_identifier, decision, module_index=DNS.PROXY)

    @classmethod
    def send_to_client(cls, packet):
        try:
            packet.sendto(packet.send_data, (f'{packet.src_ip}', 0))
        except OSError:
            pass

    # pre check will filter out invalid packets or local dns records/ .local.
    def _pre_inspect(self, packet):
        if (packet.qr != DNS.QUERY): return False

        if (packet.qtype in [DNS.A, DNS.NS] and not self._dns_record_get(packet.request)):
            return True

        # refusing ipv6 dns record types as policy
        if (packet.qtype == DNS.AAAA):
            packet.generate_proxy_response()
            self.send_to_client(packet)

        return False

    @staticmethod
    def listener_sock(intf, intf_ip):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

        l_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        l_sock.setblocking(0)

        l_sock.bind((f'{intf_ip}', 0))

        return l_sock


class Inspect:
    _Proxy = DNSProxy

    _ip_whitelist_get = _Proxy.whitelist.ip.get
    _tld_get = _Proxy.signatures.tld.get

    # NOTE: recently added these refs. look into doing the same for the proxy signatures
    _proxy_notify_server = _Proxy.notify_server
    _proxy_send_to_client = _Proxy.send_to_client

    @classmethod
    def dns(cls, packet):
        self = cls()
        request_results = self._dns_inspect(self._Proxy, packet)
        # NOTE: accessing class var through instance is 7-10% faster
        if (not request_results.redirect):
            self._proxy_notify_server(packet.request_identifier, decision=DNS.ALLOWED)

        else:
            self._proxy_notify_server(packet.request_identifier, decision=DNS.FLAGGED)

            packet.generate_proxy_response()

            self._proxy_send_to_client(packet)

        Log.log(packet, request_results)

    # this is where the system decides whether to block dns query/sinkhole or to allow. notification will be done
    # via the request tracker upon returning signature scan result
    def _dns_inspect(self, Proxy, packet):
        whitelisted = self._ip_whitelist_get(packet.src_ip, False)
        enum_categories = []

        # signature/ blacklist check.
        # DNS_REQUEST_RESULTS(redirect, block type, category)
        # NOTE: dns whitelist does not override tld blocks at the moment | this is most likely the desired setup
        for i, enum_request in enumerate(packet.requests):
            # TLD (top level domain) block | after first index will pass nested to allow for continue
            if (not i):
                if self._tld_get(enum_request):
                    Log.dprint(f'TLD Block: {packet.request}')

                    return DNS_REQUEST_RESULTS(True, 'tld filter', TLD_CAT[enum_request])

                continue

            # NOTE: allowing malicious category overrides (for false positives)
            if (enum_request in Proxy.whitelist.dns):

                return DNS_REQUEST_RESULTS(False, None, None)

            # ip whitelist overrides configured blacklist
            if (not whitelisted and enum_request in Proxy.blacklist.dns):

                return DNS_REQUEST_RESULTS(True, 'blacklist', DNS_CAT.time_based)

            # pulling domain category if signature present. | NOTE: this is now using imported cython function factory
            category = DNS_CAT(_recursive_binary_search(enum_request))
            if (category is not DNS_CAT.NONE) and self._block_query(category, whitelisted):

                return DNS_REQUEST_RESULTS(True, 'category', category)

            # adding returned cat to enum list. this will be used to identify categories
            # for allowed requests.
            enum_categories.append(category)

        # Keyword search within domain || block if match
        for keyword, category in Proxy.signatures.keyword:
            if (keyword in packet.request):

                return DNS_REQUEST_RESULTS(True, 'keyword', category)

        # pulling most specific category that is not none otherwise returned value will be DNS_CAT.NONE.
        for category in enum_categories:
            if category is not DNS_CAT.NONE: break

        # DEFAULT ACTION | ALLOW
        return DNS_REQUEST_RESULTS(False, None, category)

    # # grabbing the request category and determining whether the request should be blocked. if so, returns general
    # # information for further processing
    def _block_query(self, category, whitelisted):
        # signature match, but blocking disabled for the category | ALLOW
        if (category not in self._Proxy.signatures.en_dns):
            return False

        # signature match, not whitelisted, or whitelisted and cat is bad | BLOCK
        if (not whitelisted or category in [DNS_CAT.malicious, DNS_CAT.cryptominer]):
            return True

        # default action | ALLOW
        return False

if __name__ == '__main__':
    dns_cat_signatures = Configuration.load_dns_signature_bitmap()

    # using cython function factory to create binary search function with module specific signatures
    signature_bounds = (0, len(dns_cat_signatures)-1)

    # TODO: collisions were found in the geolocation filtering data structure. this has been fixed
    # for geolocation and standard ip category filtering, but has not been investigated for dns signatures.
    # run through the signatures, generate bin and host id, then check for host id collisions within a bin.
    _recursive_binary_search = generate_recursive_binary_search(dns_cat_signatures, signature_bounds)

    Log.run(
        name=LOG_NAME
    )
    DNSProxy.run(Log, threaded=True, always_on=True)
    DNSServer.run(Log, threaded=False, always_on=True)
