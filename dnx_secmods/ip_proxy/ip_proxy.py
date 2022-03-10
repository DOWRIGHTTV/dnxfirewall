#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import CONN, PROTO, Queue, DIR, GEO, REP
from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS
from dnx_gentools.signature_operations import generate_reputation

from dnx_iptools.packet_classes import NFQueue
from dnx_iptools.dnx_trie_search import RecurveTrie

from ip_proxy_packets import IPPPacket, ProxyResponse
from ip_proxy_restrict import LanRestrict
from ip_proxy_automate import Configuration
from ip_proxy_log import Log

__all__ = (
    'run', 'IPProxy'
)

LOG_NAME: str = 'ip_proxy'


class IPProxy(NFQueue):
    ids_mode: ClassVar[bool] = False

    reputation_enabled:   ClassVar[bool] = False
    reputation_settings:  ClassVar[dict] = {}
    geolocation_enabled:  ClassVar[bool] = True
    geolocation_settings: ClassVar[dict] = {}

    ip_whitelist:  ClassVar[dict] = {}
    tor_whitelist: ClassVar[dict] = {}

    open_ports: ClassVar[dict[PROTO, dict[int, int]]] = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }

    _packet_parser: ClassVar[ProxyParser] = IPPPacket.netfilter_recv

    def _setup(self) -> None:
        self.__class__.set_proxy_callback(func=inspect)

        Configuration.setup(self.__class__)
        ProxyResponse.setup(Log, self.__class__)
        LanRestrict.run(self.__class__)

    def _pre_inspect(self, packet: IPPPacket) -> bool:

        # --------------------
        # IP PROXY INSPECT
        # --------------------
        if (packet.ipp_profile and packet.action is CONN.ACCEPT):
            return True

        # --------------------
        # DIRECT TO DNS PROXY
        # --------------------
        elif (packet.dns_profile and packet.direction is DIR.OUTBOUND
                and packet.protocol is PROTO.UDP and packet.dst_port == PROTO.DNS):
            packet.nfqueue.forward(Queue.DNS_PROXY)

        # --------------------
        # DIRECT TO IPS/IDS
        # --------------------
        # forwarding packet to ips for portscan/ddos inspection with deferred action verdict
        # accept or deny actions are both capable of being inspected by ips/ids.
        if (packet.ips_profile and packet.direction is DIR.INBOUND):
            packet.nfqueue.forward(Queue.IPS_IDS)

        # --------------------
        # DIRECT TO GEO/ACCEPT
        # --------------------
        elif (packet.action is CONN.ACCEPT):
            packet.nfqueue.accept()

        # --------------------
        # DIRECT TO GEO/DROP
        # --------------------
        else:
            packet.nfqueue.drop()

        # quick path to log geo data. doing this post action, since it's a log-only path.
        log_geolocation(packet)

        return False

    @staticmethod
    def forward_packet(packet: IPPPacket, direction: DIR, action: CONN) -> None:

        # PACKET MARK UPDATE - needed for forward to ips/ids and dns proxy
        if (action is CONN.DROP):
            packet.nfqueue.update_mark(packet.mark & 65532)

        # --------------------
        # DNS PROXY FORWARD
        # --------------------
        # this needs to be first to give local dns records to be implicitly allowed
        if (packet.dns_profile and packet.protocol is PROTO.UDP and packet.dst_port == PROTO.DNS):
            packet.nfqueue.forward(Queue.DNS_PROXY)

        # --------------------
        # IPS/IDS FORWARD
        # --------------------
        # ips filter for only INBOUND traffic inspection.
        # if ips profile is set on a rule for outbound traffic, it will be ignored.
        # TODO: look into what would be needed to expand ips inspection to lan to wan or lan to lan rules.
        elif (packet.ips_profile and direction is DIR.INBOUND):
            packet.nfqueue.forward(Queue.IPS_IDS)

        # --------------------
        # IP PROXY ACCEPT
        # --------------------
        # no other security modules configured on rule and passed ip proxy inspection
        elif (action is CONN.ACCEPT):
            packet.nfqueue.accept()

        # --------------------
        # IP PROXY DROP
        # --------------------
        # no other security modules configured on rule and failed ip proxy inspection
        elif (action is CONN.DROP):
            packet.nfqueue.drop()


# GENERAL PROXY FUNCTIONS
def log_geolocation(packet: IPPPacket) -> None:

    # country of tracked (external) passed from cfirewall via packet mark
    country = GEO(packet.tracked_geo)

    Log.log(packet, IPP_INSPECTION_RESULTS(country.name, ''), geo_only=True)


# =================
# INSPECTION LOGIC
# =================
_forward_packet   = IPProxy.forward_packet
_prepare_and_send = ProxyResponse.prepare_and_send

# direct references to proxy class data structure methods
_reputation_settings = IPProxy.reputation_settings
_reputation_enabled  = IPProxy.reputation_enabled

_geolocation_settings = IPProxy.geolocation_settings

_tor_whitelist = IPProxy.tor_whitelist

def inspect(packet: IPPPacket) -> None:

    action, category = _inspect(packet)

    _forward_packet(packet, packet.direction, action)

    # RECENTLY MOVED: thought it more fitting here than in the forward method
    # if tcp or udp, we will send a kill conn packet.
    if (action is CONN.REJECT):
        _prepare_and_send(packet)

    Log.log(packet, IPP_INSPECTION_RESULTS(category, action))

def _inspect(packet: IPPPacket) -> tuple[CONN, tuple[str, str]]:
    action = CONN.ACCEPT
    reputation = REP.DNL

    # NOTE: geo search is now done by cfirewall. based on the direction, it will pass on country of tracked_ip
    country = GEO(packet.tracked_geo)

    # if category match and country is configured to block in direction of conn/packet
    # TODO: consider option to configure default action for unknown countries
    if (country is not GEO.NONE):
        action = _country_action(country, packet)

    # no need to check reputation of host if filtered by geolocation
    if (action is CONN.ACCEPT and _reputation_enabled):

        reputation = REP(_recurve_trie_search(packet.bin_data))

        # if category match, and category is configured to block in direction of conn/packet
        if (reputation is not REP.NONE):
            action = _reputation_action(reputation, packet)

    return action, (country.name, reputation.name)

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

    # default action is allow due to category not being enabled
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

def run():
    IPProxy.run(Log, q_num=Queue.IP_PROXY)


if (INIT_MODULE == LOG_NAME.replace('_', '-')):
    Log.run(
        name=LOG_NAME
    )

    reputation_signatures = generate_reputation(Log)

    # initializing C/Cython extension, converting python structures to native C array/struct,
    # and assigning direct reference to search method [which calls underlying C without GIL]
    recurve_trie: RecurveTrie = RecurveTrie()
    recurve_trie.generate_structure(reputation_signatures)

    _recurve_trie_search = recurve_trie.search

    # memory allocation was done manually within C extension for its structures. python structures
    # are no longer needed at this point so freeing memory.
    del reputation_signatures
