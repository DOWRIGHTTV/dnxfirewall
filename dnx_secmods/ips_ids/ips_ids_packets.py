#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import CONN, PROTO

from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import itoip
from dnx_iptools.interface_ops import load_interfaces


class IPSPacket(NFPacket):

    __slots__ = (
        'tracked_ip', 'target_port', 'icmp_payload_override', 'mark',

        'action', 'direction', 'ipp_profile', 'dns_profile', 'ips_profile',
    )

    def __init__(self):
        super().__init__()

        self.target_port = None
        self.icmp_payload_override = b''

    def tcp_override(self, dst_port, seq_num):
        '''returns packet instance with the overridden values modified. this is to be used by the response system
        where a packet copy is used to send retroactive blocks.'''

        self.dst_port = dst_port
        self.seq_number = seq_num

        return self

    def udp_override(self, icmp_payload):
        '''returns packet instance with the overriden values modified. this is to be used by the response system
        where a packet copy is used to send retroactive blocks.'''

        self.icmp_payload_override = icmp_payload

        return self

    # building named tuple with tracked_ip, tracked_port, and local_port variables
    def _before_exit(self, mark):
        # X | X | ips (4b) | dns (4b) | ipp (4b) | geoloc (8b) | direction (2b) | action (2b)
        self.mark = mark

        self.action = CONN(mark & 3)
        # self.direction = DIR(mark >> 2 & 3)

        # self.tracked_geo = mark >> 4 & 255
        # self.ipp_profile = mark >> 12 & 15
        # self.dns_profile = mark >> 16 & 15
        self.ips_profile = mark >> 20 & 15

        # NOTE: subject to change. this assumes ip restricted to inbound traffic only.
        self.tracked_ip = itoip(self.src_ip)
        if (self.protocol is not PROTO.ICMP):
            self.target_port = self.dst_port

class IPSResponse(RawResponse):
    _intfs = load_interfaces(exclude=['lan', 'dmz'])
