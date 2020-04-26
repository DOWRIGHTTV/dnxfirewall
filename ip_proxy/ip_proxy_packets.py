#!/usr/bin/env python3

import os, sys
import time

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_parent_classes import RawPacket, RawResponse
from dnx_iptools.dnx_protocol_tools import checksum_ipv4, checksum_tcp, checksum_icmp
from dnx_configure.dnx_namedtuples import IPP_SRC_INFO, IPP_DST_INFO, IPP_IP_INFO


class IPPPacket(RawPacket):
    __slots__ = (
        'direction', 'conn', 'bin_data'
    )

    def _before_exit(self):
        if (self.zone == WAN_IN):
            self.direction = DIR.INBOUND
            # NOTE: wont be needed if we use bitmap cat bin search
            self.conn = IPP_IP_INFO(str(self.src_ip), str(self.dst_ip))

            bin_data = str(int(self.src_ip))
            self.bin_data = (int(bin_data[:-5]), int(bin_data[-5:]), self.sf_octet)

        elif (self.zone in [LAN_IN, DMZ_IN]):
            self.direction = DIR.OUTBOUND
            # NOTE: wont be needed if we use bitmap cat bin search
            self.conn = IPP_IP_INFO(str(self.dst_ip), str(self.src_ip))

            bin_data = str(int(self.dst_ip))
            self.bin_data = (int(bin_data[:-5]), int(bin_data[-5:]), self.df_octet)


# TODO: test UDP / icmp dst unreachable packet!
# TODO: test inbound connections/ reject having correct src port
class ProxyResponse(RawResponse):

    def _prepare_packet(self, packet):
        # 1a. generating tcp/pseudo header | iterating to calculate checksum
        if (packet.protocol == PROTO.TCP):
            protocol, checksum = PROTO.TCP, double_byte_pack(0,0)
            for i in range(2):
                tcp_header = tcp_header_pack(
                    packet.dst_port, packet.src_port, 696969, packet.seq_number + 1,
                    80, 20, 0, checksum, 0
                )
                if i: break
                pseudo_header = [pseudo_header_pack(
                    self._dnx_src_ip, packet.src_ip.packed, 0, 6, 20
                ), tcp_header]
                checksum = checksum_tcp(b''.join(pseudo_header))

            send_data = [tcp_header]

        # 1b. generating icmp header and payload iterating to calculate checksum
        elif (packet.protocol == PROTO.UDP):
            protocol, checksum = PROTO.ICMP, double_byte_pack(0,0)
            for i in range(2):
                icmp_full = [icmp_header_pack(3, 3, checksum, 0, 0)]
                if (packet.icmp_payload_override):
                    icmp_full.append(packet.icmp_payload_override)
                else:
                    icmp_full.extend([packet.ip_header, packet.udp_header, packet.udp_payload])
                if i: break
                checksum = checksum_icmp(b''.join(icmp_full))

            send_data = [icmp_full]

        # 2. generating ip header with loop to create header, calculate zerod checksum, then rebuild
        # with correct checksum | append to send data
        ip_len, checksum = 20 + len(b''.join(send_data)), double_byte_pack(0,0)
        for i in range(2):
            ip_header = ip_header_pack(
                69, 0, ip_len, 0, 16384, 255, protocol,
                checksum, self._dnx_src_ip, packet.src_ip.packed
            )
            if i: break
            checksum = checksum_ipv4(ip_header)

        send_data.append(ip_header)

        # 3. generating ethernet header | append to send data
        send_data.append(eth_header_pack(
            packet.src_mac, self._dnx_src_mac, L2_PROTO
        ))
        # assigning instance variable with joined data from above
        self.send_data = b''.join(reversed(send_data))

    def _packet_override(self, packet):
        port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
        if (not port_override): return

        if (packet.protocol == PROTO.TCP):
            packet.dst_port = port_override

        elif (packet.protocol == PROTO.UDP):
            packet.udp_header = udp_header_pack(
                packet.src_port, port_override, packet.udp_len, packet.udp_check
            )
            checksum = double_byte_pack(0,0)
            for i in range(2):
                ip_header = ip_header_pack(
                    packet.ip_header[:10], checksum, packet.src_ip.packed, self._dnx_src_ip
                )
                if i: break
                checksum = checksum_ipv4(ip_header)

    def _override_needed(self, packet):
        # override only required on WAN > local nets (lan, dmz)
        if (packet.direction == DIR.INBOUND):
            return True

        return False
