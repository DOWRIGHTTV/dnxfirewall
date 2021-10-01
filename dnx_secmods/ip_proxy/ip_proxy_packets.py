#!/usr/bin/env python3

from dnx_gentools.def_constants import *

from dnx_iptools.def_structs import *
from dnx_iptools.def_bytecontainers import *
from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import checksum_ipv4, checksum_tcp, checksum_icmp, int_to_ipaddr


class IPPPacket(NFPacket):

    __slots__ = (
        'direction', 'action',
        'ipp_profile', 'ips_profile',

        'local_ip', 'tracked_ip',
        'bin_data',
    )

    def _before_exit(self, mark):

        # X | X | X | X | ips | ipp | direction | action

        self.action    = CONN(mark & 15)
        self.direction = DIR( mark >> 4 & 15)

        self.ipp_profile = mark >>  8 & 15
        self.ips_profile = mark >> 12 & 15

        if (self.direction == DIR.INBOUND):
            tracked_ip = self.src_ip

            self.tracked_ip = int_to_ipaddr(tracked_ip)
            self.local_ip = int_to_ipaddr(self.dst_ip)

        # elif self.direction = DIR.OUTBOUND:
        else:
            tracked_ip = self.dst_ip

            self.local_ip = int_to_ipaddr(self.src_ip)
            self.tracked_ip = int_to_ipaddr(tracked_ip)

        self.bin_data = (tracked_ip & MSB, tracked_ip & LSB)


# pre defined fields which are functionally constants for the purpose of connection resets
ip_header_template = PR_IP_HDR(**{'ver_ihl': 69, 'tos': 0, 'ident': 0, 'flags_fro': 16384, 'ttl': 255})
tcp_header_template = PR_TCP_HDR(**{'seq_num': 696969, 'offset_control': 20500, 'window': 0, 'urg_ptr': 0})
pseudo_header_template = PR_TCP_PSEUDO_HDR(**{'reserved': 0, 'protocol': 6, 'tcp_len': 20})
icmp_header_template = PR_ICMP_HDR(**{'type': 3, 'code': 3, 'unused': 0})


# TODO: test UDP / icmp dst unreachable packet!
# TODO: test inbound connections/ reject having correct src port
class ProxyResponse(RawResponse):

    # NOTE: consider sending in dst also since it is referenced a 2+ times.
    def _prepare_packet2(self, packet, dnx_src_ip):
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re assign in the packet object
        # NOTE: can we please optimize this. PLEASE!
        port_override = self._Module.open_ports[packet.protocol].get(packet.dst_port)
        if (port_override):
            self._packet_override(packet, dnx_src_ip, port_override)

        # TCP HEADER
        if (packet.protocol is PROTO.TCP):

            # new instance of header byte container template
            proto_header = tcp_header_template()

            # assigning missing fields
            proto_header.dst_port = packet.dst_port
            proto_header.src_port = packet.src_port
            proto_header.ack_num  = packet.seq_number+1

            pseudo_header = PR_TCP_PSEUDO_HDR()
            pseudo_header.src_ip = dnx_src_ip
            pseudo_header.dst_ip = packet.src_ip

            # calculating checksum of container
            proto_header.checksum = checksum_tcp(pseudo_header.assemble() + proto_header.assemble())

            proto_len = len(proto_header)

        # ICMP HEADER
        elif (packet.protocol is PROTO.UDP):
            proto_header = icmp_header_template()

            # per icmp, ip header and first 8 bytes of rcvd payload are including in icmp response payload
            icmp_payload = packet.ip_header + packet.udp_header
            proto_header.checksum = checksum_icmp(
                 byte_join(proto_header.assemble() + icmp_payload)
            )

            proto_len = len(proto_header) + len(icmp_payload)

        # IP HEADER
        ip_header = ip_header_template()

        ip_header.tl = 20 + proto_len
        ip_header.protocol = packet.protocol
        ip_header.src_ip = dnx_src_ip
        ip_header.dst_ip = packet.src_ip

        ip_header.checksum = checksum_ipv4(ip_header.assemble())

        packet_data = [ip_header.assemble(), proto_header.assemble()]
        if (packet.protocol is PROTO.UDP):
            packet_data.append(icmp_payload)

        # final assembly with calculated checksums and combining data.
        return byte_join(packet_data)

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
                    dnx_src_ip, long_pack(packet.src_ip), 0, 6, 20
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
                checksum, dnx_src_ip, long_pack(packet.src_ip)
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
    #  it seems weird that we override, but then do nothin with ip header. i think we en up sending
    #  the old ip header in this case. EVEN MORE SURE NOW. pretty sure we havent tested udp scans
    #  or blocks anytime recent.
    def _packet_override(self, packet, dnx_src_ip, port_override):
        if (packet.protocol is PROTO.TCP):
            packet.dst_port = port_override

        elif (packet.protocol is PROTO.UDP):
            packet.udp_header = udp_header_pack(
                packet.src_port, port_override, packet.udp_len, packet.udp_check
            )
            # TODO: this doesnt seem right for some reason. we are assigning ip_header, but
            #  we are doing nothin with it????? this should be assigned within packet yes???
            #  if so once its complete we can assign it instead of while iterating.
            #  this would also apply to the IPS!
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
