#!/usr/bin/env python3

from dnx_gentools.def_constants import *

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import *
from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import checksum_ipv4, checksum_tcp, checksum_icmp, int_to_ipaddr
from dnx_iptools.interface_ops import load_interfaces


class IPSPacket(NFPacket):

    __slots__ = (
        'tracked_ip', 'target_port', 'icmp_payload_override', 'mark',

        'action', 'direction', 'ipp_profile', 'ips_profile',
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
        # X | X | X | X | ips | ipp | direction | action
        self.mark = mark

        self.action      = CONN(mark & 15)
        self.direction   = DIR( mark >> 4 & 15)

        self.ipp_profile = mark >>  8 & 15
        self.ips_profile = mark >> 12 & 15

        self.tracked_ip = int_to_ipaddr(self.src_ip)
        if (self.protocol is not PROTO.ICMP):
            self.target_port = self.dst_port


# pre defined fields which are functionally constants for the purpose of connection resets
ip_header_template = PR_IP_HDR(**{'ver_ihl': 69, 'tos': 0, 'ident': 0, 'flags_fro': 16384, 'ttl': 255})
tcp_header_template = PR_TCP_HDR(**{'seq_num': 696969, 'offset_control': 20500, 'window': 0, 'urg_ptr': 0})
pseudo_header_template = PR_TCP_PSEUDO_HDR(**{'reserved': 0, 'protocol': 6, 'tcp_len': 20})
icmp_header_template = PR_ICMP_HDR(**{'type': 3, 'code': 3, 'unused': 0})


class IPSResponse(RawResponse):
    _intfs = load_interfaces(exclude=['lan', 'dmz'])

    # TODO: ensure dnx_src_ip is in integer form. consider sending in dst also since it is referenced alot.
    def _prepare_packet(self, packet, dnx_src_ip):
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re assign in the packet object
        # NOTE: can we please optimize this. PLEASE!
        port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
        if (port_override):
            self._packet_override(packet, dnx_src_ip, port_override)

        # TCP HEADER
        if (packet.protocol is PROTO.TCP):
            response_protocol = PROTO.TCP

            # new instance of header byte container template
            proto_header = tcp_header_template()

            # assigning missing fields
            proto_header.dst_port = packet.dst_port
            proto_header.src_port = packet.src_port
            proto_header.ack_num = packet.seq_number + 1

            pseudo_header = pseudo_header_template()
            pseudo_header.src_ip = dnx_src_ip
            pseudo_header.dst_ip = packet.src_ip

            # calculating checksum of container
            proto_header.checksum = checksum_tcp(
                byte_join([pseudo_header.assemble(), proto_header.assemble()])
            )

            proto_len = len(proto_header)

        # ICMP HEADER
        elif (packet.protocol is PROTO.UDP):
            response_protocol = PROTO.ICMP

            proto_header = icmp_header_template()

            # per icmp, ip header and first 8 bytes of rcvd payload are including in icmp response payload
            icmp_payload = byte_join([packet.ip_header, packet.udp_header])
            proto_header.checksum = checksum_icmp(
                byte_join([proto_header.assemble(), icmp_payload])
            )

            proto_len = len(proto_header) + len(icmp_payload)

        # IP HEADER
        ip_header = ip_header_template()

        ip_header.tl = 20 + proto_len
        ip_header.protocol = response_protocol
        ip_header.src_ip = dnx_src_ip
        ip_header.dst_ip = packet.src_ip

        ip_header.checksum = checksum_ipv4(ip_header.assemble())

        packet_data = [ip_header.assemble(), proto_header.assemble()]
        if (packet.protocol is PROTO.UDP):
            packet_data.append(icmp_payload)

        # final assembly with calculated checksums and combining data.
        return byte_join(packet_data)

    # def _prepare_packet(self, packet, dnx_src_ip):
    #     # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
    #     # and re assign in the packert object
    #     # NOTE: can we please optimize this. PLEASE!
    #     port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
    #     if port_override:
    #         self._packet_override(packet, dnx_src_ip, port_override)

    #     # 1a. generating tcp/pseudo header | iterating to calculate checksum
    #     if (packet.protocol is PROTO.TCP):
    #         protocol, checksum = PROTO.TCP, double_byte_pack(0,0)
    #         for i in range(2):

    #             # packing tcp header
    #             tcp_header = tcp_header_pack(
    #                 packet.dst_port, packet.src_port, 696969, packet.seq_number + 1,
    #                 80, 20, 0, checksum, 0
    #             )
    #             if i: break

    #             # packing pseudo header
    #             pseudo_header = [pseudo_header_pack(
    #                 dnx_src_ip, long_pack(packet.src_ip), 0, 6, 20
    #             ), tcp_header]

    #             checksum = checksum_tcp(byte_join(pseudo_header))

    #         send_data = [tcp_header]
    #         ip_len = len(tcp_header) + 20

    #     # 1b. generating icmp header and payload iterating to calculate checksum
    #     elif (packet.protocol is PROTO.UDP):
    #         protocol, checksum = PROTO.ICMP, double_byte_pack(0,0)
    #         for i in range(2):

    #             # packing icmp full
    #             if (packet.icmp_payload_override):
    #                 icmp_full = [icmp_header_pack(3, 3, checksum, 0, 0), packet.icmp_payload_override]

    #             else:
    #                 icmp_full = [
    #                     icmp_header_pack(3, 3, checksum, 0, 0), packet.ip_header, packet.udp_header, packet.udp_payload
    #                 ]

    #             icmp_full = byte_join(icmp_full)
    #             if i: break

    #             checksum = checksum_icmp(icmp_full)

    #         send_data = [icmp_full]
    #         ip_len = len(icmp_full) + 20

    #     # 2. generating ip header with loop to create header, calculate zerod checksum, then rebuild
    #     # with correct checksum | append to send data
    #     checksum = double_byte_pack(0,0)
    #     for i in range(2):

    #         # packing ip header
    #         ip_header = ip_header_pack(
    #             69, 0, ip_len, 0, 16384, 255, protocol,
    #             checksum, dnx_src_ip, long_pack(packet.src_ip)
    #         )
    #         if i: break

    #         checksum = checksum_ipv4(ip_header)

    #     send_data.append(ip_header)

    #     # NOTE: we shouldnt have to track ethernet headers anymore
    #     # # 3. generating ethernet header | append to send data
    #     # send_data.append(eth_header_pack(
    #     #     packet.src_mac, self._dnx_src_mac, L2_PROTO
    #     # ))

    #     # returning with joined data from above
    #     return byte_join(reversed(send_data))

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
