#!/usr/bin/env python3

from __future__ import annotations

from threading import Thread

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import UINT16_MAX, RUN_FOREVER
from dnx_gentools.def_enums import PROTO, Queue
from dnx_gentools.def_enums import GEOLOCATION, GEO_ID_TO_STRING, REPUTATION, REP_ID_TO_STRING
from dnx_gentools.def_enums import DIRECTION, DIR_OFF, DIR_OUTBOUND, DIR_INBOUND, DIR_BOTH
from dnx_gentools.def_enums import DECISION, CONN_REJECT, CONN_INSPECT, CONN_DROP, CONN_ACCEPT
from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS

from dnx_iptools.packet_classes import NFQueue

from ip_proxy_packets import IPPPacket, ProxyResponse
# from ip_proxy_restrict import LanRestrict
from ip_proxy_automate import ProxyConfiguration
from ip_proxy_log import Log

__all__ = (
    'IPProxy',
)

PREPARE_AND_SEND = ProxyResponse.prepare_and_send

class IPProxy(ProxyConfiguration, NFQueue):

    _packet_parser: ClassVar[ProxyParser] = IPPPacket.netfilter_recv

    __slots__ = ()

    def _setup(self) -> None:
        self.configure()

        ProxyResponse.setup(Log, self.__class__.open_ports)
        # LanRestrict.run(self.__class__)

        for i in range(self.DEFAULT_THREAD_COUNT):
            Thread(target=self.inspection_worker, args=(i,)).start()

    def inspection_worker(self, i: int) -> NoReturn:
        Log.informational(f'[proxy/worker][{i}] inspection thread started')

        inspection_queue_get = self.inspection_queue.get

        for _ in RUN_FOREVER:
            packet: IPPPacket = inspection_queue_get()

            results = inspect(packet)

            forward_packet(packet, packet.direction, results.action)

            if (results.action is CONN_REJECT):
                PREPARE_AND_SEND(packet)

            Log.log(packet, results)

# =================
# FORWARDING LOGIC
# =================
def forward_packet(packet: IPPPacket, direction: DIRECTION, action: DECISION) -> None:
    # PRE DROP FILTERS
    # --------------------
    # IPS/IDS FORWARD
    # --------------------
    # ips filter for only INBOUND traffic inspection.
    # dropped packets still need to be processed for ddos/portscan profiling
    # if ips profile is set on a rule for outbound traffic, it will be ignored.
    # TODO: look into what would be needed to expand ips inspection to lan to wan or lan to lan rules.
    if (packet.ips_profile and direction == DIR_INBOUND):
        packet.nfqueue.update_mark(packet.mark & UINT16_MAX)

        packet.nfqueue.forward(Queue.IDS_IPS)

    # ====================
    # IP PROXY DROP
    # ====================
    # no other security modules configured on rule and failed ip proxy inspection
    elif (action == CONN_DROP):
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
    elif (action == CONN_ACCEPT):
        packet.nfqueue.accept()


# =================
# INSPECTION LOGIC
# =================
# assigned by __init__ prior to running
REP_LOOKUP: Callable[[int], int] = NotImplemented

# direct references to proxy class data structure methods
_reputation_settings = IPProxy.reputation_settings
_geolocation_settings = IPProxy.geolocation_settings

# _tor_whitelist = IPProxy.tor_whitelist

def inspect(packet: IPPPacket) -> IPP_INSPECTION_RESULTS:

    # if category match and country is configured to block in direction of conn/packet
    if country := packet.tracked_geo:
        action, country_name = _country_action(country, packet)

    else:
        action, country_name = CONN_ACCEPT, GEO_ID_TO_STRING[country]

    # no need to check reputation of host if filtered by geolocation
    if (action is CONN_ACCEPT):

        # if category match, and category is configured to block in direction of conn/packet
        if reputation := REP_LOOKUP(packet.tracked_ip):
            action, rep_name = _reputation_action(reputation, packet)

        else:
            rep_name = REP_ID_TO_STRING[reputation]

    else:
        rep_name = REP_ID_TO_STRING[-1]  # REP.DNL

    return IPP_INSPECTION_RESULTS((country_name, rep_name), action)

# TODO: expand for profiles. reputation_settings[profile][category]
# category setting lookup. will match packet direction with configured dir for category/category group.
def _reputation_action(category: int, packet: IPPPacket) -> tuple[DECISION, REPUTATION]:

    # flooring cat to its group id for easier matching
    rep_group = REP_ID_TO_STRING[(category // 10) * 10]

    # TOR categories need to be checked individually
    if (rep_group == 'TOR'):
        rep_group = REP_ID_TO_STRING[category]

        # only outbound traffic will match tor whitelist since this override is designed for a user to access tor
        # and not to open a local machine to tor traffic.
        # if (packet.direction is DIR.OUTBOUND and packet.local_ip in _tor_whitelist):
        #     return CONN_ACCEPT

    block_direction = _reputation_settings[rep_group]

    # notify proxy the connection should be blocked. dir enum is Flag with bitwise ops.
    if (packet.direction & block_direction):
        # hardcoded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
        if (packet.protocol is PROTO.ICMP):
            return CONN_DROP

        return CONN_REJECT

    # default action is allow
    return CONN_ACCEPT

# TODO: expand for profiles. geolocation_settings[profile][category]
def _country_action(country: int, packet: IPPPacket) -> tuple[DECISION, GEOLOCATION]:

    country_name = GEO_ID_TO_STRING[country]

    # dir enum is _Flag with bitwise ops. this makes comparison much easier.
    if (packet.direction & _geolocation_settings[country_name]):
        # hardcoded for icmp to drop and tcp/udp to reject. # TODO: consider making this configurable.
        if (packet.protocol is PROTO.ICMP):
            return CONN_DROP, country_name

        return CONN_REJECT, country_name

    return CONN_ACCEPT, country_name
