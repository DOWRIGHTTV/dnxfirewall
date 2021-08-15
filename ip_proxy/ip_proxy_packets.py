#!/usr/bin/env python3

import os, sys

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
            # NOTE: this should only be needed for logging perposes. if so, see if we can get rid of it
            # but replacing it with a more efficient mechanism
            self.conn = IPP_IP_INFO(f'{self.src_ip}', f'{self.dst_ip}')

            ip_addr = int(self.src_ip)

        elif (self.zone in [LAN_IN, DMZ_IN]):
            self.direction = DIR.OUTBOUND
            # NOTE: this should only be needed for logging perposes. if so, see if we can get rid of it
            # but replacing it with a more efficient mechanism
            self.conn = IPP_IP_INFO(f'{self.dst_ip}', f'{self.src_ip}')

            ip_addr = int(self.dst_ip)

        self.bin_data = (ip_addr & MSB, ip_addr & LSB)


# TODO: test UDP / icmp dst unreachable packet!
# TODO: test inbound connections/ reject having correct src port
class ProxyResponse(RawResponse):

    def _prepare_packet(self, packet, dnx_src_ip):
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re assign in the packet object
        # NOTE: can we please optimize this. PLEASE!
        port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
        if (port_override):
            self._packet_override(packet, dnx_src_ip, port_override)

        # 1a. generating tcp/pseudo header | iterating to calculate checksum
        if (packet.protocol is PROTO.TCP):
            protocol, checksum = PROTO.TCP, double_byte_pack(0,0)
            for i in range(2):

                # packing the tcp header, 1st iter 0 checksum, 2nd is actual
                tcp_header = tcp_header_pack(
                    packet.dst_port, packet.src_port, 696969, packet.seq_number + 1,
                    80, 20, 0, checksum, 0
                )
                if i: break

                # joining pseudo header with tcp header to calculate the tcp checksum
                pseudo_header = [pseudo_header_pack(
                    dnx_src_ip, packet.src_ip.packed, 0, 6, 20
                ), tcp_header]

                checksum = checksum_tcp(byte_join(pseudo_header))

            send_data = [tcp_header]

        # 1b. generating icmp header and payload iterating to calculate checksum
        elif (packet.protocol is PROTO.UDP):
            protocol, checksum = PROTO.ICMP, double_byte_pack(0,0)
            for i in range(2):

                # packing the icmp header and payload, 1st iter 0 checksum, 2nd i actual
                icmp_full = [
                    icmp_header_pack(3, 3, checksum, 0, 0), packet.ip_header, packet.udp_header, packet.udp_payload
                ]
                if i: break

                checksum = checksum_icmp(byte_join(icmp_full))

            send_data = [icmp_full]

        # 2. generating ip header with loop to create header, calculate zerod checksum, then rebuild
        # with correct checksum | append to send data
        ip_len, checksum = 20 + len(byte_join(send_data)), double_byte_pack(0,0)
        for i in range(2):

            # packing ip header
            ip_header = ip_header_pack(
                69, 0, ip_len, 0, 16384, 255, protocol,
                checksum, dnx_src_ip, packet.src_ip.packed
            )
            if i: break

            checksum = checksum_ipv4(ip_header)

        send_data.append(ip_header)

        # NOTE: should no longer need to self manage ethernet header.
        # # 3. generating ethernet header | append to send data
        # send_data.append(eth_header_pack(
        #     packet.src_mac, self._dnx_src_mac, L2_PROTO
        # ))

        # return joined data from above
        return byte_join(reversed(send_data))

    # TODO: go back over this. this seems kinda wonky. i might just be in sleepboi brain mode but
    # it seems weird that we override, but then do nothin with ip header. i think we en up sending
    # the old ip header in this case. EVEN MORE SURE NOW. pretty sure we havent tested udp scans
    # or blocks anytime recent.
    def _packet_override(self, packet, dnx_src_ip, port_override):
        if (packet.protocol is PROTO.TCP):
            packet.dst_port = port_override

        elif (packet.protocol is PROTO.UDP):
            packet.udp_header = udp_header_pack(
                packet.src_port, port_override, packet.udp_len, packet.udp_check
            )
            # TODO: this doesnt seem right for some reason. we are assigning ip_header, but
            # we are doing nothin with it????? this should be assigned within packet yes???
            # if so once its complete we can assign it instead of while iterating.
            # this would also apply to the IPS!
            checksum = double_byte_pack(0,0)
            for i in range(2):
                ip_header = ip_header_override_pack(
                    packet.ip_header[:10], checksum, packet.src_ip.packed, dnx_src_ip
                )
                if i: break
                checksum = checksum_ipv4(ip_header)

            # overriding packet ip header after process is complete. this will make the loops more efficient that
            # direct references to the instance object every time.
            packet.ip_header = ip_header

    def _override_needed(self, packet):
        # override only required on WAN -> local nets (lan, dmz)
        return packet.direction is DIR.INBOUND
