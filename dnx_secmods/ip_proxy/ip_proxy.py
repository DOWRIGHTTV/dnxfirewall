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
    # this is providing an alternate constructor
    _packet_parser: ClassVar[ProxyParser] = IPPPacket.netfilter_recv

    @classmethod
    def _setup(cls) -> None:
        cls.set_proxy_callback(func=inspect)

        Configuration.setup(cls)
        ProxyResponse.setup(Log, cls)
        LanRestrict.run(cls)

    def _pre_inspect(self, packet: IPPPacket) -> bool:
        # TODO: this can and should be moved to cfirewall
        # if local ip is not in the ip whitelist, the packet will be dropped while time restriction is active.
        if (LanRestrict.is_active and packet.in_zone == LAN_IN
                and packet.src_ip not in self.ip_whitelist):
            packet.nfqueue.drop()

            return False

        # standard ip proxy inspect. further action will be decided after inspection.
        if (packet.action is CONN.ACCEPT and packet.ipp_profile):
            return True

        # forwarding packet to ips for portscan/ddos inspection. accept or deny actions are both capable of being
        # inspected by ips/ids. if ips/ids inspection is needed, the ip proxy will defer verdict and forward.
        if (packet.direction is DIR.INBOUND and packet.ips_profile):
            packet.nfqueue.forward(Queue.IPS_IDS)

        # if the packet is not dropped at this point, neither the ips/ids nor proxy profiles are set. in this case,
        # the ip proxy will issue the accept verdict.
        elif (packet.action is CONN.ACCEPT and not packet.ipp_profile):
            packet.nfqueue.accept()

        # dropped by cfirewall > inspect geo only
        else:
            packet.nfqueue.drop()

        # quick path to log geo data. doing this post action, since it's a log-only path.
        log_geolocation(packet)

        return False

    @classmethod
    def forward_packet(cls, packet: IPPPacket, direction: DIR, action: CONN) -> None:

        # NOTE: this condition restricts ips inspection to INBOUND only to emulate prior functionality. if ips profile
        # is set on a rule for outbound traffic, it will be ignored.
        # TODO: look into what would be needed to expand ips inspection to lan to wan or lan to lan rules.
        if (direction is DIR.INBOUND and packet.ips_profile):

            # mark update needed to notify ips to drop the packet, but inspect under specified profile. the bitwise op
            # resets first 2 bits (allocated for action) to 0 (CONN.DROP = 0).
            if (action is CONN.DROP):
                packet.nfqueue.update_mark(packet.mark & 65532)

            packet.nfqueue.forward(Queue.IPS_IDS)

        elif (packet.protocol is PROTO.UDP and packet.dst_port == PROTO.DNS and packet.dns_profile):
            packet.nfqueue.forward(Queue.DNS_PROXY)

        elif (action is CONN.ACCEPT):
            packet.nfqueue.accept()

        # explicit condition match for readability
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

    # NOTE: geo search is now done by cfirewall. based on direction it will pass on country of tracked_ip
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
    reputation_signatures = generate_reputation(Log)

    # initializing C/Cython extension, converting python structures to native C array/struct,
    # and assigning direct reference to search method [which calls underlying C without GIL]
    recurve_trie: RecurveTrie = RecurveTrie()
    recurve_trie.generate_structure(reputation_signatures)

    _recurve_trie_search = recurve_trie.search

    # memory allocation was done manually within C extension for its structures. python structures
    # are no longer needed at this point so freeing memory.
    del reputation_signatures

    IPProxy.run(Log, q_num=Queue.IP_PROXY)


if (INIT_MODULE == LOG_NAME):
    Log.run(
        name=LOG_NAME
    )