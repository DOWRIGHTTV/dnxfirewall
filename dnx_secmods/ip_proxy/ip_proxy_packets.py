#!/usr/bin/env python3

from dnx_gentools.def_constants import *

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import *
from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import calc_checksum, int_to_ip


class IPPPacket(NFPacket):

    __slots__ = (
        'direction', 'action',
        'ipp_profile', 'dns_profile', 'ips_profile',

        'local_ip', 'tracked_ip',
        'tracked_geo', 'bin_data',
    )

    def _before_exit(self, mark):

        # X | X | ips (4b) | dns (4b) | ipp (4b) | geoloc (8b) | direction (2b) | action (2b)

        self.action    = CONN(mark & 3)
        self.direction =  DIR(mark >> 2 & 3)

        self.tracked_geo = mark >>  4 & 255
        self.ipp_profile = mark >> 12 & 15
        # self.dns_profile = mark >> 16 & 15
        self.ips_profile = mark >> 20 & 15

        if (self.direction == DIR.INBOUND):
            tracked_ip = self.src_ip

            self.tracked_ip = int_to_ip(tracked_ip)
            self.local_ip = int_to_ip(self.dst_ip)

        # elif self.direction = DIR.OUTBOUND:
        else:
            tracked_ip = self.dst_ip

            self.local_ip = int_to_ip(self.src_ip)
            self.tracked_ip = int_to_ip(tracked_ip)

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
    def _prepare_packet(self, packet, dnx_src_ip):
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re-assign in the packet object
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
            proto_header.ack_num  = packet.seq_number+1

            pseudo_header = pseudo_header_template()
            pseudo_header.src_ip = dnx_src_ip
            pseudo_header.dst_ip = packet.src_ip

            # calculating checksum of container
            proto_header.checksum = calc_checksum(
                byte_join([pseudo_header.assemble(), proto_header.assemble()])
            )

            proto_len = len(proto_header)

        # ICMP HEADER
        elif (packet.protocol is PROTO.UDP):
            response_protocol = PROTO.ICMP

            proto_header = icmp_header_template()

            # per icmp, ip header and first 8 bytes of rcvd payload are included in icmp response payload
            icmp_payload = byte_join([packet.ip_header, packet.udp_header])
            proto_header.checksum = calc_checksum(
                byte_join([proto_header.assemble(), icmp_payload])
            )

            proto_len = len(proto_header) + len(icmp_payload)

        # IP HEADER
        ip_header = ip_header_template()

        ip_header.tl = 20 + proto_len
        ip_header.protocol = response_protocol
        ip_header.src_ip = dnx_src_ip
        ip_header.dst_ip = packet.src_ip

        ip_header.checksum = calc_checksum(ip_header.assemble())

        packet_data = [ip_header.assemble(), proto_header.assemble()]
        if (packet.protocol is PROTO.UDP):
            packet_data.append(icmp_payload)

        # final assembly with calculated checksums and combining data.
        return byte_join(packet_data)

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

            csum = double_byte_pack(0,0)
            for i in range(2):
                ip_header = ip_header_override_pack(
                    packet.ip_header[:10], csum, long_pack(packet.src_ip), dnx_src_ip
                )
                if i: break
                csum = calc_checksum(ip_header)

            # overriding packet ip header after process is complete. this will make the loops more efficient than
            # direct references to the instance object every time.
            packet.ip_header = ip_header
