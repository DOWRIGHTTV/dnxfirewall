#!/usr/bin/env python3

import os, sys
import time
import threading

from functools import lru_cache

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_binary_search import generate_linear_binary_search, generate_recursive_binary_search # pylint: disable=import-error, no-name-in-module
from dnx_configure.dnx_namedtuples import IPP_IP_INFO, IPP_INSPECTION_RESULTS, IPP_LOG, INFECTED_LOG
from dnx_configure.dnx_file_operations import load_signatures
from dnx_iptools.dnx_parent_classes import NFQueue

from ip_proxy.ip_proxy_log import Log
from ip_proxy.ip_proxy_packets import IPPPacket, ProxyResponse
from ip_proxy.ip_proxy_restrict import LanRestrict
from ip_proxy.ip_proxy_automate import Configuration

from dnx_configure.dnx_code_profiler import profiler

LOG_NAME = 'ip_proxy'


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

    # NOTE: this may no be needed. we should be running the inspection engine at all times for
    # geolocation (and maybe aditional things down the road). if all reputation cats are disabled
    # then that signature set will be bypassed and set to None.
    # # if nothing is enabled the packet will be forwarded based on mark of packet.
    # def _pre_check(self, nfqueue):
    #     # marked for parsing
    #     if (self.inspect_on or LanRestrict.is_active):
    #         return True

    #     else:
    #         self.forward_packet(nfqueue, nfqueue.get_mark())

    #     # parse not needed
    #     return False

    def _pre_inspect(self, packet):
        # if local ip is not in the ip whitelist, the packet will be dropped while time restriction is active.
        if (LanRestrict.is_active and packet.zone == LAN_IN
                and packet.src_ip not in self.ip_whitelist):
            packet.nfqueue.drop()

        else:
            return True

        # # marked for further inspection
        # elif (self.inspect_on):
        #     return True

        # # just in case proxy was disabled mid parse of packets
        # else:
        #     self.forward_packet(packet.nfqueue, packet.zone)

    @classmethod
    def forward_packet(cls, nfqueue, zone, action=CONN.ACCEPT):
        if (zone == LAN_IN):
            nfqueue.set_mark(LAN_ZONE_FIREWALL)

        elif(zone == DMZ_IN):
            nfqueue.set_mark(DMZ_ZONE_FIREWALL)

        elif (zone == WAN_IN):
            if (action is CONN.DROP):
                nfqueue.set_mark(IP_PROXY_DROP)

            else:
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
        action, category = self._ip_inspect(self._Proxy, packet)

        # ip proxy will handle the drop of packet for icmp packets that do not need to be inspected by ips
        if ((action is CONN.DROP and packet.protocol is PROTO.ICMP)
                and (packet.icmp_type is not ICMP.ECHO or packet.direction is DIR.OUTBOUND)):
            packet.nfqueue.drop()

        else:
            self._Proxy.forward_packet(packet.nfqueue, packet.zone, action)

        Log.log(packet, IPP_INSPECTION_RESULTS(category, action))

    def _ip_inspect(self, Proxy, packet):
        action = CONN.ACCEPT
        reputation = IPP_CAT.DNL

        # running through geolocation signatures for a host match. NOTE: not all countries are included in the sig
        # set at this time. the additional compression algo needs to be re implemented before more countries can
        # be added due to memory cost.
        country = GEO(_linear_binary_search(packet.bin_data))

        # if category match and country is configurted to block in direction of conn/packet
        if (country is not GEO.NONE):
            action = self._country_action(country, packet.direction)

        # no need to check reputation of host if filtered by geolocation
        if (action is CONN.ACCEPT and Proxy.reputation_enabled):

            reputation = IPP_CAT(_recursive_binary_search(packet.bin_data))

            # if category match, and category is configured to block in direction of conn/packet
            if (reputation is not IPP_CAT.NONE):
                action = self._reputation_action(reputation, packet)

        return action, (f'{country.name}', f'{reputation.name}')

    # category setting lookup. will match packet direction with configured dir for category/category group.
    def _reputation_action(self, category, packet):
        # flooring cat to its cat group for easier matching of tor nodes
        rep_group = IPP_CAT((category // 10) * 10)
        if (rep_group is IPP_CAT.TOR):

            # only outbound traffic will match tor whitelist since this override is designed for a user to access
            # tor and not to open a local machine to tor traffic.
            # TODO: evaluate if we should have an inbound override, though i dont know who would ever want random
            # tor users accessing their servers.
            if (packet.direction is DIR.OUTBOUND and packet.conn.local_ip in self._Proxy.tor_whitelist):
                return CONN.ACCEPT

            block_direction = self._Proxy.cat_settings[category]

        else:
            block_direction = self._Proxy.cat_settings[rep_group]

        # notify proxy the connection should be blocked
        if (block_direction in [packet.direction, DIR.BOTH]):
            return CONN.DROP

        # default action is allow due to category not being enabled
        return CONN.ACCEPT

    def _country_action(self, category, direction):
        if (self._Proxy.geo_settings[category] in [direction, DIR.BOTH]):
            return CONN.DROP

        return CONN.ACCEPT

if __name__ == '__main__':
    ip_cat_signatures, geoloc_signatures = Configuration.load_ip_signature_bitmaps()

    # using cython function factory to create binary search function with module specific signatures
    ip_cat_signature_bounds = (0, len(ip_cat_signatures)-1)
    geoloc_signature_bounds = (0, len(geoloc_signatures)-1)

    _recursive_binary_search = generate_recursive_binary_search(ip_cat_signatures, ip_cat_signature_bounds)
    _linear_binary_search = generate_linear_binary_search(geoloc_signatures, geoloc_signature_bounds)

    Log.run(
        name=LOG_NAME
    )
    IPProxy.run(Log, q_num=1)
