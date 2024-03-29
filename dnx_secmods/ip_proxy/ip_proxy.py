#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import UINT16_MAX
from dnx_gentools.def_enums import CONN, PROTO, Queue, DIR, GEO, REP
from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS

from dnx_iptools.packet_classes import NFQueue

from ip_proxy_packets import IPPPacket, ProxyResponse
from ip_proxy_restrict import LanRestrict
from ip_proxy_automate import ProxyConfiguration
from ip_proxy_log import Log

__all__ = (
    'IPProxy',
)

REP_LOOKUP: Callable[[int], int] = NotImplemented  # will be assigned by __init__ prior to running
PREPARE_AND_SEND = ProxyResponse.prepare_and_send


class IPProxy(ProxyConfiguration, NFQueue):

    _packet_parser: ClassVar[ProxyParser] = IPPPacket.netfilter_recv

    __slots__ = ()

    def _setup(self) -> None:
        self.__class__.set_proxy_callback(func=inspect)

        self.configure()

        ProxyResponse.setup(Log, self.__class__.open_ports)
        # LanRestrict.run(self.__class__)

    @staticmethod
    def forward_packet(packet: IPPPacket, direction: DIR, action: CONN) -> None:

        # PRE DROP FILTERS
        # --------------------
        # IPS/IDS FORWARD
        # --------------------
        # ips filter for only INBOUND traffic inspection.
        # dropped packets still need to be processed for ddos/portscan profiling
        # if ips profile is set on a rule for outbound traffic, it will be ignored.
        # TODO: look into what would be needed to expand ips inspection to lan to wan or lan to lan rules.
        if (packet.ips_profile and direction is DIR.INBOUND):
            packet.nfqueue.update_mark(packet.mark & UINT16_MAX)

            packet.nfqueue.forward(Queue.IPS_IDS)

        # ====================
        # IP PROXY DROP
        # ====================
        # no other security modules configured on rule and failed ip proxy inspection
        elif (action is CONN.DROP):
            packet.nfqueue.drop()

        # POST DROP FILTERS
        # --------------------
        # DNS PROXY FORWARD
        # --------------------
        elif (packet.dns_profile and packet.protocol is PROTO.UDP and packet.dst_port == PROTO.DNS):
            packet.nfqueue.forward(Queue.DNS_PROXY)

        # ====================
        # IP PROXY ACCEPT
        # ====================
        # no other security modules configured on rule and passed ip proxy inspection
        elif (action is CONN.ACCEPT):
            packet.nfqueue.accept()


# =================
# INSPECTION LOGIC
# =================
FORWARD_PACKET = IPProxy.forward_packet

# direct references to proxy class data structure methods
_reputation_settings = IPProxy.reputation_settings
_reputation_enabled  = IPProxy.reputation_enabled

_geolocation_settings = IPProxy.geolocation_settings

_tor_whitelist = IPProxy.tor_whitelist

def inspect(_, packet: IPPPacket) -> None:

    results = _inspect(packet)

    FORWARD_PACKET(packet, packet.direction, results.action)

    # RECENTLY MOVED: thought it more fitting here than in the forward method
    # if tcp or udp, we will send a kill conn packet.
    if (results.action is CONN.REJECT):
        PREPARE_AND_SEND(packet)

    Log.log(packet, results)

def _inspect(packet: IPPPacket) -> IPP_INSPECTION_RESULTS:
    action = CONN.ACCEPT
    reputation = REP.DNL

    # geolocation lookup is done by cfirewall, so we only need to define enum
    country = GEO(packet.tracked_geo)

    # if category match and country is configured to block in direction of conn/packet
    if (country is not GEO.NONE):
        action = _country_action(country, packet)

    # no need to check reputation of host if filtered by geolocation
    if (action is CONN.ACCEPT and _reputation_enabled):

        reputation = REP(REP_LOOKUP(packet.tracked_ip))

        # if category match, and category is configured to block in direction of conn/packet
        if (reputation is not REP.NONE):
            action = _reputation_action(reputation, packet)

    return IPP_INSPECTION_RESULTS((country.name, reputation.name), action)

# TODO: expand for profiles. reputation_settings[profile][category]
# category setting lookup. will match packet direction with configured dir for category/category group.
def _reputation_action(category: REP, packet: IPPPacket) -> CONN:
    # flooring cat to its cat group for easier matching of tor nodes
    rep_group = REP((category // 10) * 10)
    if (rep_group is REP.TOR):

        # only outbound traffic will match tor whitelist since this override is designed for a user to access tor
        # and not to open a local machine to tor traffic.
        # TODO: evaluate if we should have an inbound override, though i dont know who would ever want random tor
        #  users accessing their servers.
        if (packet.direction is DIR.OUTBOUND and packet.local_ip in _tor_whitelist):
            return CONN.ACCEPT

        block_direction = _reputation_settings[category]

    else:
        block_direction = _reputation_settings[rep_group]

    # notify proxy the connection should be blocked. dir enum is Flag with bitwise ops.
    if (packet.direction & block_direction):
        # hardcoded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
        if (packet.protocol is PROTO.ICMP):
            return CONN.DROP

        return CONN.REJECT

    # default action is allow
    return CONN.ACCEPT

# TODO: expand for profiles. geolocation_settings[profile][category]
def _country_action(category: GEO, packet: IPPPacket) -> CONN:

    # dir enum is _Flag with bitwise ops. this makes comparison much easier.
    if (packet.direction & _geolocation_settings[category]):
        # hardcoded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
        if (packet.protocol is PROTO.ICMP):
            return CONN.DROP

        return CONN.REJECT

    return CONN.ACCEPT
