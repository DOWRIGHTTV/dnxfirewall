#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_iptools.interface_ops as interface

from dnx_sysmods.configure.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.def_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import checksum_ipv4, checksum_tcp, checksum_icmp, int_to_ipaddr


# TODO: make sure iptable rule can allow for icmp echo/8 through forward. basically if host is doing a icmp flood
# attack on an open port it will not be detected with current rules.
class IPSPacket(NFPacket):

    __slots__ = (
        'tracked_ip', 'target_port', 'icmp_payload_override'
    )

    def __init__(self):
        super().__init__()

        self.target_port = None
        self.icmp_payload_override = b''

    def tcp_override(self, dst_port, seq_num):
        '''returns packet instance with the overriden values modified. this is to be used by the response system
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
    def _before_exit(self):
        if (self.zone == SEND_TO_IPS):
            self.zone = WAN_IN

        self.tracked_ip = int_to_ipaddr(self.src_ip)
        if (self.protocol is not PROTO.ICMP):
            self.target_port = self.dst_port


class IPSResponse(RawResponse):
    _intfs = (
        (WAN_IN, interface.get_intf('wan')),
    )

    def _prepare_packet(self, packet, dnx_src_ip):
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re assign in the packert object
        # NOTE: can we please optimize this. PLEASE!
        port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
        if port_override:
            self._packet_override(packet, dnx_src_ip, port_override)

        # 1a. generating tcp/pseudo header | iterating to calculate checksum
        if (packet.protocol is PROTO.TCP):
            protocol, checksum = PROTO.TCP, double_byte_pack(0,0)
            for i in range(2):

                # packing tcp header
                tcp_header = tcp_header_pack(
                    packet.dst_port, packet.src_port, 696969, packet.seq_number + 1,
                    80, 20, 0, checksum, 0
                )
                if i: break

                # packing pseudo header
                pseudo_header = [pseudo_header_pack(
                    dnx_src_ip, long_pack(packet.src_ip), 0, 6, 20
                ), tcp_header]

                checksum = checksum_tcp(byte_join(pseudo_header))

            send_data = [tcp_header]
            ip_len = len(tcp_header) + 20

        # 1b. generating icmp header and payload iterating to calculate checksum
        elif (packet.protocol is PROTO.UDP):
            protocol, checksum = PROTO.ICMP, double_byte_pack(0,0)
            for i in range(2):

                # packing icmp full
                if (packet.icmp_payload_override):
                    icmp_full = [icmp_header_pack(3, 3, checksum, 0, 0), packet.icmp_payload_override]

                else:
                    icmp_full = [
                        icmp_header_pack(3, 3, checksum, 0, 0), packet.ip_header, packet.udp_header, packet.udp_payload
                    ]

                icmp_full = byte_join(icmp_full)
                if i: break

                checksum = checksum_icmp(icmp_full)

            send_data = [icmp_full]
            ip_len = len(icmp_full) + 20

        # 2. generating ip header with loop to create header, calculate zerod checksum, then rebuild
        # with correct checksum | append to send data
        checksum = double_byte_pack(0,0)
        for i in range(2):

            # packing ip header
            ip_header = ip_header_pack(
                69, 0, ip_len, 0, 16384, 255, protocol,
                checksum, dnx_src_ip, long_pack(packet.src_ip)
            )
            if i: break

            checksum = checksum_ipv4(ip_header)

        send_data.append(ip_header)

        # NOTE: we shouldnt have to track ethernet headers anymore
        # # 3. generating ethernet header | append to send data
        # send_data.append(eth_header_pack(
        #     packet.src_mac, self._dnx_src_mac, L2_PROTO
        # ))

        # returning with joined data from above
        return byte_join(reversed(send_data))

    def _packet_override(self, packet, dnx_src_ip, port_override):
        if (packet.protocol is PROTO.TCP):
            packet.dst_port = port_override

        elif (packet.protocol is PROTO.UDP):
            packet.udp_header = udp_header_pack(
                packet.src_port, port_override, packet.udp_len, packet.udp_chk
            )
            checksum = double_byte_pack(0,0)
            for i in range(2):
                ip_header = ip_header_override_pack(
                    packet.ip_header[:10], checksum, long_pack(packet.src_ip), dnx_src_ip
                )
                if i: break
                checksum = checksum_ipv4(ip_header)

            # overriding packet ip header after process is complete. this will make the loops more efficient than
            # direct references to the instance object every time.
            packet.ip_header = ip_header

    #all packets need to be further examined in override method
    def _override_needed(self, packet):
        return True