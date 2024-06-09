#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import PROTO_ICMP

from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.interface_ops import load_interfaces

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Bytes
    from dnx_gentools.def_typing import IP_ADDRINT, NET_PORT


class IPSPacket(NFPacket):
    tracked_ip:  IP_ADDRINT
    target_port: NET_PORT

    icmp_payload_override: Bytes

    __slots__ = (
        'tracked_ip', 'target_port', 'icmp_payload_override'
    )

    def __init__(self):
        # super().__init__()  # parent no longer uses __init__ method
        self.target_port = 0  # note: type issue is ok here.
        self.icmp_payload_override = b''

    def tcp_override(self, dst_port: NET_PORT, seq_num: int) -> IPSPacket:
        '''override the tcp header values of the received packet with the passed in data.

        a reference to the packet instance will be returned.
        this is to be used by the response system where a packet copy is used to send retroactive blocks.
        '''
        self.dst_port = dst_port
        self.seq_number = seq_num

        return self

    def udp_override(self, icmp_payload: Bytes) -> IPSPacket:
        '''override the icmp payload from the received packet with the passed in data.

        a reference to the packet instance will be returned.
        this is to be used by the response system where a packet copy is used to send retroactive blocks.
        '''
        self.icmp_payload_override = icmp_payload

        return self

    def _before_exit(self, mark: int) -> None:

        self.tracked_ip = self.src_ip
        if (self.protocol is not PROTO_ICMP):
            self.target_port = self.dst_port

class IPSResponse(RawResponse):
    _intfs = load_interfaces(exclude=['lan', 'dmz'])
