#!/usr/bin/python3

import os, sys
import socket

from functools import lru_cache

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_parent_classes import Listener
from dnx_configure.dnx_namedtuples import DNS_REQUEST_RESULTS, PROXY_DECISION
from dnx_configure.dnx_namedtuples import WHITELIST, BLACKLIST, SIGNATURES

from dns_proxy.dns_proxy_log import Log
from dns_proxy.dns_proxy_packets import ProxyRequest
from dns_proxy.dns_proxy_server import DNSServer
from dns_proxy.dns_proxy_automate import Configuration

from dnx_configure.dnx_code_profiler import profiler

LOG_NAME = 'dns_proxy'


class DNSProxy(Listener):
    # dns | ip
    whitelist = WHITELIST(
        {}, {}
    )
    blacklist = BLACKLIST(
        {}
    )

    _dns_sig_ref = None

    _packet_parser = ProxyRequest.interface # alternate constructor
    _dns_server    = DNSServer

    @classmethod
    def _setup(cls):
        dns_sigs = Configuration.load_signatures()
        # en_dns | dns | tld | keyword
        cls.signatures = SIGNATURES(
            set(), dns_sigs, {}, []
        )

        Configuration.proxy_setup(cls)
        cls.set_proxy_callback(func=Inspect.dns)

        Log.notice(f'{cls.__name__} initialization complete.')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._dns_record_get = self._dns_server.dns_records.get

#    @profiler
    # pre check will filter out invalid packets or local dns records/ .local.
    def _pre_inspect(self, packet):
        if (packet.qr != DNS.QUERY): return False

        if (packet.qtype in [DNS.A, DNS.NS]
                and not self._dns_record_get(packet.request)):
            return True

        # refusing ipv6 dns record types as policy
        if (packet.qtype == DNS.AAAA):
            packet.generate_proxy_response() # NOTE: complete
            self.send_to_client(packet) # NOTE: complete

        return False

    @classmethod
    def notify_server(cls, packet, decision):
        cls._dns_server.REQ_RESULTS[packet.client_address] = decision

    @property
    def listener_sock(self):
        l_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        l_sock.bind((self._intf, 3))

        return l_sock


class Inspect:
    _Proxy = DNSProxy

    __slots__ = (
        # protected vars
        '_packet', '_whitelisted', '_match'
    )

    def __init__(self, packet):
        self._packet = packet

        self._whitelisted = False
        self._match = None

    @classmethod
    def dns(cls, packet):
        self = cls(packet)
        request_results = self._dns_inspect()
        # NOTE: accessing class var through instance is 7-10% faster
        if (not request_results.redirect):
            self._Proxy.notify_server(packet, decision=DNS.ALLOWED)
        else:
            self._Proxy.notify_server(packet, decision=DNS.FLAGGED)

            packet.generate_proxy_response()

            self._Proxy.send_to_client(packet)

        Log.log(packet, request_results)

    # this is where the system decides whether to block dns query/sinkhole or to allow. notification will be done via the
    # request tracker upon returning signature scan result
    def _dns_inspect(self):
        packet, Proxy, whitelisted = self._packet, self._Proxy, False

        # TODO: make this only apply to global whitelist as currently it will think tor whitelist entries
        # are part of it.
        # checking whitelist.
        if (packet.src_ip in Proxy.whitelist.ip):
            whitelisted = True

        # NOTE: dns whitelist does not override tld blocks at the moment
        # signature/ blacklist check. if either match will return results
        for i, enum_request in enumerate(packet.requests):
            # TLD (top level domain) block | after first index will pass
            # nested to allow for continue
            if (not i):
                if Proxy.signatures.tld.get(enum_request):
                    Log.dprint(f'TLD Block: {packet.request}')

                    return DNS_REQUEST_RESULTS(True, 'tld filter', enum_request)
                continue

            # NOTE: allowing malicious category overrides (for false positives)
            if (enum_request in Proxy.whitelist.dns):

                return DNS_REQUEST_RESULTS(False, None, None)

            # ip whitelist overrides configured blacklist
            if (not whitelisted and enum_request in Proxy.blacklist.dns):
                Log.dprint(f'Blacklist Block: {packet.request}')

                return DNS_REQUEST_RESULTS(True, 'blacklist', 'time based')

            # pulling domain category if signature present.
            category = self._bin_search(enum_request)
            if category and self._block_query(category, whitelisted):
                Log.dprint(f'Category Block: {packet.request}')

                return DNS_REQUEST_RESULTS(True, 'category', category)

        # Keyword search within domain || block if match
        for keyword, category in Proxy.signatures.keyword:
            if (keyword in packet.request):
                Log.dprint(f'Keyword Block: {packet.request}')

                return DNS_REQUEST_RESULTS(True, 'keyword', category)

        # DEFAULT ACTION | ALLOW
        return DNS_REQUEST_RESULTS(False, None, None)

    @lru_cache(maxsize=1024)
    def _bin_search(self, request, recursion=False):
        rb_id, rh_id = request
        if (not recursion):
            sigs = self._Proxy.signatures.dns
        else:
            sigs = self._match
        # initializing data set bounds
        left, right = 0, len(sigs)-1

        while left <= right:
            mid = left + (right - left) // 2
            b_id, match = sigs[mid]
            # host bin id matches a bin id in sigs
            if (b_id == rb_id):
                break
            # excluding left half
            elif (b_id < rb_id):
                left = mid + 1
            # excluding right half
            elif (b_id > rb_id):
                right = mid - 1
        else:
            return None

        self._match = match
        # on bin match, recursively call to check host ids
        if (not recursion):
            return self._bin_search((rh_id, 0), recursion=True)

        return DNS_CAT(match)

    # grabbing the request category and determining whether the request should be blocked. if so, returns general
    # information for further processing
    def _block_query(self, category, whitelisted):
        # signature match, but blocking disabled for the category | ALLOW
        if (category not in self._Proxy.signatures.en_dns):
            return False

        # signature match, not whitelisted, or whitelisted and cat is bad | BLOCK
        if (not whitelisted or category in ['malicious', 'cryptominer']):
            return True

        # default action | ALLOW
        return False

if __name__ == '__main__':
    Log.run(
        name=LOG_NAME,
        verbose=VERBOSE,
        root=ROOT
    )
    DNSProxy.run(Log, threaded=True)
    DNSServer.run(Log, threaded=True)
