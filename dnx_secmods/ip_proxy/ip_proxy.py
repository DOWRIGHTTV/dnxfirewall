#!/usr/bin/env python3

import __init__

import os, sys

from dnx_sysmods.configure.def_constants import *
from dnx_sysmods.configure.def_namedtuples import IPP_INSPECTION_RESULTS

from dnx_secmods.ip_proxy.ip_proxy_packets import IPPPacket, ProxyResponse
from dnx_secmods.ip_proxy.ip_proxy_restrict import LanRestrict
from dnx_secmods.ip_proxy.ip_proxy_automate import Configuration
from dnx_secmods.ip_proxy.ip_proxy_log import Log

from dnx_iptools.packet_classes import NFQueue
from dnx_iptools.dnx_trie_search import generate_linear_binary_search, generate_recursive_binary_search # pylint: disable=import-error, no-name-in-module

LOG_NAME = 'ip_proxy'


class IPProxy(NFQueue):
    ids_mode   = False

    reputation_enabled   = False
    reputation_settings  = {}
    geolocation_enabled  = True
    geolocation_settings = {}

    ip_whitelist  = {}
    tor_whitelist = {}
    open_ports    = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }
    _packet_parser = IPPPacket.netfilter_rcv # alternate constructor

    @classmethod
    def _setup(cls):
        Configuration.setup(cls)
        ProxyResponse.setup(cls, Log)
        LanRestrict.run(cls)

        cls.set_proxy_callback(func=Inspect.ip)

    def _pre_inspect(self, packet):
        # TODO: this can and should be moved to cfirewall
        # if local ip is not in the ip whitelist, the packet will be dropped while time restriction is active.
        if (LanRestrict.is_active and packet.in_zone == LAN_IN
                and packet.src_ip not in self.ip_whitelist):
            packet.nfqueue.drop()

            return False

        # standard ip proxy inspect. further action decided post inspection.
        if (packet.action is CONN.ACCEPT and packet.ip_proxy_profile):
            return True

        # forwarding packet to ips for portscan/ddos inspection
        if (packet.direction is DIR.INBOUND and packet.ips_profile):
            packet.nfqueue.forward(Queue.IPS_IDS)

        # dropped by cfirewall > inspect geo only
        else:
            packet.nfqueue.drop()

        # quick path to log geo data. doing this post action since its a log only path.
        Inspect.geo_only(packet)

        return False

    @classmethod
    def forward_packet(cls, packet, direction, action):

        # TODO: update mark seems to be broken causing IPS to fail. IPS is logging profile "10" or bit "1010". this
        #  may require ntoh
        if (direction is DIR.INBOUND and packet.ips_profile):

            # re-mark needed to notify ips to drop the packet and do ddos inspection only if enabled.
            # bitwise op resets first 4 bits (allocated for action) to 0 then set the bits for drop.
            if (action is CONN.DROP):
                packet.nfqueue.update_mark(packet.mark & 65520 | CONN.DROP)

            packet.nfqueue.forward(Queue.IPS_IDS)

        elif (action is CONN.ACCEPT):
            packet.nfqueue.accept()

        # explicit condition to reduce chance of confusion
        elif (action is CONN.DROP):
            packet.nfqueue.drop()


class Inspect:
    _Proxy = IPProxy

    __slots__ = (
        '_packet',
    )

    # direct reference to the Proxy forward packet method
    _forward_packet = _Proxy.forward_packet

    # direct reference to the proxy response method
    _prepare_and_send = ProxyResponse.prepare_and_send

    @classmethod
    def geo_only(cls, packet):
        country = GEO(_linear_binary_search(packet.bin_data))

        Log.log(packet, IPP_INSPECTION_RESULTS(country.name, ''), geo_only=True)

    @classmethod
    def ip(cls, packet):
        self = cls()
        action, category = self._ip_inspect(self._Proxy, packet)

        self._Proxy.forward_packet(packet, packet.direction, action)

        # RECENTLY MOVED: thought it more fitting here than in the forward method
        # if tcp or udp, we will send a kill conn packet.
        if (action is CONN.REJECT):
            cls._prepare_and_send(packet)

        Log.log(packet, IPP_INSPECTION_RESULTS(category, action))

    def _ip_inspect(self, Proxy, packet):
        action = CONN.ACCEPT
        reputation = REP.DNL

        # running through geolocation signatures for a host match. NOTE: not all countries are included in the sig
        # set at this time. the additional compression algo needs to be re implemented before more countries can
        # be added due to memory cost.
        country = GEO(_linear_binary_search(packet.bin_data))

        # if category match and country is configured to block in direction of conn/packet
        if (country is not GEO.NONE):
            action = self._country_action(country, packet)

        # no need to check reputation of host if filtered by geolocation
        if (action is CONN.ACCEPT and Proxy.reputation_enabled):

            reputation = REP(_recursive_binary_search(packet.bin_data))

            # if category match, and category is configured to block in direction of conn/packet
            if (reputation is not REP.NONE):
                action = self._reputation_action(reputation, packet)

        return action, (country.name, reputation.name)

    # TODO: expand for profiles. reputation_settings[profile][category]
    # category setting lookup. will match packet direction with configured dir for category/category group.
    def _reputation_action(self, category, packet):
        # flooring cat to its cat group for easier matching of tor nodes
        rep_group = REP((category // 10) * 10)
        if (rep_group is REP.TOR):

            # only outbound traffic will match tor whitelist since this override is designed for a user to access
            # tor and not to open a local machine to tor traffic.
            # TODO: evaluate if we should have an inbound override, though i dont know who would ever want random
            # tor users accessing their servers.
            if (packet.direction is DIR.OUTBOUND and packet.conn.local_ip in self._Proxy.tor_whitelist):
                return CONN.ACCEPT

            block_direction = self._Proxy.reputation_settings[category]

        else:
            block_direction = self._Proxy.reputation_settings[rep_group]

        # notify proxy the connection should be blocked
        if (block_direction in [packet.direction, DIR.BOTH]):
            # hardcorded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
            if (packet.protocol is ICMP):
                return CONN.DROP

            else:
                return CONN.REJECT

        # default action is allow due to category not being enabled
        return CONN.ACCEPT

    # TODO: expand for profiles. geolocation_settings[profile][category]
    def _country_action(self, category, packet):
        if (self._Proxy.geolocation_settings[category] in [packet.direction, DIR.BOTH]):
            # hardcorded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
            if (packet.protocol is ICMP):
                return CONN.DROP

            else:
                return CONN.REJECT

        return CONN.ACCEPT

if __name__ == '__main__':
    Log.run(
        name=LOG_NAME
    )

    ip_cat_signatures, geoloc_signatures = Configuration.load_ip_signature_bitmaps()

    # using cython function factory to create binary search function with module specific signatures
    ip_cat_signature_bounds = (0, len(ip_cat_signatures)-1)
    geoloc_signature_bounds = (0, len(geoloc_signatures)-1)

    _recursive_binary_search = generate_recursive_binary_search(ip_cat_signatures, ip_cat_signature_bounds)
    _linear_binary_search = generate_linear_binary_search(geoloc_signatures, geoloc_signature_bounds)

    IPProxy.run(Log, q_num=1)
