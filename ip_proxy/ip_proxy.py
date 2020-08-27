#!/usr/bin/env python3

import os, sys
import time
import threading

from functools import lru_cache

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_binary_search import generate_linear_binary_search, generate_recursive_binary_search # pylint: disable=no-name-in-module
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_namedtuples import IPP_IP_INFO, IPP_INSPECTION_RESULTS, IPP_LOG, INFECTED_LOG
from dnx_configure.dnx_file_operations import load_signatures
from dnx_iptools.dnx_parent_classes import NFQueue

from ip_proxy.ip_proxy_log import Log
from ip_proxy.ip_proxy_packets import IPPPacket, ProxyResponse
from ip_proxy.ip_proxy_restrict import LanRestrict
from ip_proxy.ip_proxy_automate import Configuration

from dnx_configure.dnx_code_profiler import profiler

LOG_NAME = 'ip_proxy'

# TODO:
class IPProxy(NFQueue):
    inspect_on     = False
    ids_mode       = False
    cat_enabled    = False
    cat_settings   = {}

    geo_enabled    = False
    geo_settings   = {}

    ip_whitelist   = {}
    tor_whitelist  = {}
    open_ports     = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }
    _packet_parser = IPPPacket.netfilter # alternate constructor

    @classmethod
    def _setup(cls):
        Configuration.setup(cls)
        ProxyResponse.setup(cls, Log)
        LanRestrict.run(cls)

        cls.set_proxy_callback(func=Inspect.ip)

    # if nothing is enabled the packet will be forwarded based on mark of packet.
    def _pre_check(self, nfqueue):
        if (self.inspect_on or LanRestrict.is_active):
            return True # marked for parsing
        else:
            self.forward_packet(nfqueue, nfqueue.get_mark())

        return False # parse not needed

    def _pre_inspect(self, packet):
        # if local ip is not in the ip whitelist, the packet will be dropped while time restriction is active.
        if (LanRestrict.is_active and packet.zone == LAN_IN
                and packet.src_ip not in self.ip_whitelist):
            packet.nfqueue.drop()

        elif (self.inspect_on):
            return True # marked for further inspection

        # just in case proxy was disabled mid parse of packets
        else:
            self.forward_packet(packet.nfqueue, packet.zone)

    @classmethod
    def forward_packet(cls, nfqueue, zone, action=CONN.ACCEPT):
        if (zone == WAN_IN and action is CONN.DROP):
            nfqueue.set_mark(IP_PROXY_DROP)
        elif (zone == LAN_IN):
            nfqueue.set_mark(SEND_TO_FIREWALL)
        elif (zone == WAN_IN):
            nfqueue.set_mark(SEND_TO_IPS)
        # NOTE: this is to protect the repeat if no match. probably log??
        else:
            nfqueue.drop()
            return

        nfqueue.repeat()


class Inspect:
    _Proxy = IPProxy
    _ProxyResponse = ProxyResponse

    __slots__ = (
        '_packet', '_match'
    )

    # direct reference to the Proxy forward packet method
    _forward_packet = _Proxy.forward_packet

    # direct reference to the proxy response method
    _prepare_and_send = _ProxyResponse.prepare_and_send

    def __init__(self):
        self._match = None

    @classmethod
    def ip(cls, packet):
        self = cls()
        action, category = self._ip_inspect(packet)

        self._Proxy.forward_packet(packet.nfqueue, packet.zone, action)
#        self._forward_packet(packet.nfqueue, packet.zone, action)

        # sending reset
        if (action is CONN.DROP):
            self._prepare_and_send(packet)

        if (category):
            Log.log(packet, IPP_INSPECTION_RESULTS(category, action))

    def _ip_inspect(self, packet):
        action = CONN.ACCEPT # setting default action
        Proxy = self._Proxy
        # will cross reference category based ips if enabled
        if (Proxy.cat_enabled):
            category = IPP_CAT(_recursive_binary_search(packet.bin_data))

            Log.debug(f'CAT LOOKUP | {packet.conn.tracked_ip}: {category}')

            # if category match, and category is configured to block in direction of conn/packet
            if (category is not IPP_CAT.NONE) and self._blocked_ip(category, packet):
                action = CONN.DROP

        # will cross reference geolocation network if enabled at not already blocked
        # NOTE: this is now using imported cython function factory
        if (action is CONN.ACCEPT and Proxy.geo_enabled):
            category = GEO(_linear_binary_search(packet.bin_data))

            Log.debug(f'GEO LOOKUP | {packet.conn.tracked_ip}: {category}')

            # if category match and country is configurted to block in direction of conn/packet
            if (category is not GEO.NONE) and self._blocked_country(category, packet.direction):
                action = CONN.DROP

        # NOTE: debugs are for testing.
        if (action is CONN.ACCEPT):
            Log.debug(f'IP PROXY | ACCEPTED | {packet.conn.tracked_ip}: {packet.direction}')

        # if marked for drop, but id mode is enabled decision will get changed to ACCEPT.
        elif (action is CONN.DROP and Proxy.ids_mode): # NOTE: should only match if IDS mode enabled and sig match + cat enabled(direction match included)
            Log.debug(f'IP PROXY | DETECTED | {packet.conn.tracked_ip}: {packet.direction}.')
            action = CONN.ACCEPT

        elif (action is CONN.DROP):
            Log.debug(f'IP PROXY | DROPPED | {packet.conn.tracked_ip}: {packet.direction}')

        return action, category

    # category setting lookup. will match packet direction with configured dir for category/category group.
    def _blocked_ip(self, category, packet):
        # flooring cat to its cat group for easier matching of tor nodes
        cat_group = IPP_CAT((category // 10) * 10)
        if (cat_group is IPP_CAT.TOR):
            block_direction = self._Proxy.cat_settings[category]
            if (packet.conn.local_ip in self._Proxy.tor_whitelist):
                return False

        else:
            block_direction = self._Proxy.cat_settings[cat_group]

        # notify proxy the connection should be blocked
        if (block_direction in [packet.direction, DIR.BOTH]):
            return True

        # default action is allow due to category not being enabled
        return False

    def _blocked_country(self, category, direction):
        if (self._Proxy.geo_settings[category] in [direction, DIR.BOTH]):
            return True

        return False


    # NOTE: this has been moved to a cython extension and is imported and set up at runtime.
    # keeping for archival purposes for awhile.

    # @lru_cache(maxsize=1024)
    # def _cat_bin_match(self, host, recursion=False):
    #     hb_id, hh_id, f_octet = host
    #     if (not recursion):
    #         sigs = self._Proxy.cat_signatures
    #         left, right = self._calculate_bounds(left=0, right=len(sigs)-1, f_octet=f_octet)
    #     else:
    #         sigs = self._match
    #         left, right = 0, len(sigs)-1

    #     while left <= right:
    #         mid = left + (right - left) // 2
    #         b_id, match = sigs[mid]

    #         # host bin id matches a bin id in sigs
    #         if (b_id == hb_id):
    #             break

    #         # excluding left half
    #         elif (b_id < hb_id):
    #             left = mid + 1

    #         # excluding right half
    #         elif (b_id > hb_id):
    #             right = mid - 1
    #     else:
    #         return None

    #     # on bin match, assign var of dataset then recursively call to check host ids
    #     if (not recursion):
    #         self._match = match

    #         return self._cat_bin_match((hh_id, 0, 0), recursion=True)

    #     return IPP_CAT(match)

    # @lru_cache(maxsize=1024)
    # def _geo_bin_match(self, host):
    #     hb_id, h_id, f_octet = host
    #     sigs = self._Proxy.geo_signatures

    #     # initial adjustment. using an interpolative clamping of left/right bounds.
    #     left, right = self._calculate_bounds(left=0, right=len(sigs)-1, f_octet=f_octet)
    #     while left <= right:
    #         mid = left + (right - left) // 2
    #         b_id, h_ranges = sigs[mid]

    #         # excluding left half
    #         if (b_id < hb_id):
    #             left = mid + 1

    #         # excluding right half
    #         elif (b_id > hb_id):
    #             right = mid - 1

    #         # host bin id matches a bin id in sigs
    #         else:
    #             break
    #     else:
    #         return None

    #     for r_start, r_end, c_code in h_ranges:
    #         if r_start <= h_id <= r_end:
    #             return GEO(c_code)

if __name__ == "__main__":
    ip_cat_signatures, geoloc_signatures = Configuration.load_ip_signature_bitmaps()

    # using cython function factory to create binary search function with module specific signatures
    ip_cat_signature_bounds = (0, len(ip_cat_signatures)-1)
    geoloc_signature_bounds = (0, len(geoloc_signatures)-1)

    _recursive_binary_search = generate_recursive_binary_search(ip_cat_signatures, ip_cat_signature_bounds)
    _linear_binary_search = generate_linear_binary_search(geoloc_signatures, geoloc_signature_bounds)

    Log.run(
        name=LOG_NAME,
        verbose=VERBOSE,
        root=ROOT
    )
    IPProxy.run(Log, q_num=1)
