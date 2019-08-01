#!/usr/bin/python3

import os, sys
import struct
import time
import binascii
import subprocess
import array

from contextlib import closing
from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, IPPROTO_UDP

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_packet_checks import Checksums

class DNSResponse:
    def __init__(self, lan_int, response_ip, packet):
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((lan_int, 0))

        self.Packet = Packet(response_ip, packet)
        self.Packet.Start()

    def Response(self):
        self.Packet.AssembleQueryResponse()
        self.Packet.AssembleDNS()
        self.Packet.AssembleUDP()
        self.Packet.AssembleIPv4()
        self.Packet.AssembleEthernet()

        packet = self.Packet.ethernet_header + self.Packet.ipv4_header + self.Packet.udp_header
        packet += self.Packet.dns_header + self.Packet.dns_payload
        self.s.send(packet)

class Packet:
    def __init__(self, response_ip, packet):
        self.response_ip = response_ip
        self.packet = packet

        self.Checksum = Checksums()

        self.dns_payload = b''

    def Start(self):
        self.SplitPacket()
        self.CreateQueryResponse()
        self.CreateDNS()
        self.CreateUDP()
        self.CreateIPv4()
        self.AssembleIPv4()
        self.ip_chk = self.Checksum.IPv4(self.ipv4_header)

    def SplitPacket(self):
        self.dst_mac = self.packet.src_mac
        self.src_mac = self.packet.dst_mac
        self.src_ip = self.packet.dst_ip
        self.dst_ip = self.packet.src_ip
        self.src_port = 53
        self.dst_port = self.packet.src_port
        self.dnsID = self.packet.dnsID
        self.url = self.packet.qname.lower()

        self.l2pro = 0x0800

    def AssembleEthernet(self):
        self.ethernet_header = struct.pack('!6s6sH' ,
        binascii.unhexlify(self.dst_mac.replace(":","")),
        binascii.unhexlify(self.src_mac.replace(":","")),
        self.l2pro)

    def CreateIPv4(self):
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4 ) + ip_vhl
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn
        self.ip_tol = 20 + self.udp_len
        self.ip_idf = 0
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)
        self.ip_ttl = 255
        self.ip_proto = IPPROTO_UDP
        self.ip_chk = 0
        self.ip_saddr = inet_aton(self.src_ip)
        self.ip_daddr = inet_aton(self.dst_ip)

    def AssembleIPv4(self):
        self.ipv4_header = struct.pack('!2B3H2B' ,
        self.ip_ver,
        self.ip_dfc,
        self.ip_tol,
        self.ip_idf,
        self.ip_flg,
        self.ip_ttl,
        self.ip_proto
        )
        self.ipv4_header += struct.pack('<H' ,
        self.ip_chk
        )
        self.ipv4_header += struct.pack('!4s4s' ,
        self.ip_saddr,
        self.ip_daddr
        )

    def CreateUDP(self):
        self.udp_len = self.dnsL + 8 + 6
        self.udp_chk = 0

    def AssembleUDP(self):
        self.udp_header = struct.pack('!4H' ,
        self.src_port,
        self.dst_port,
        self.udp_len,
        self.udp_chk
        )

    def CreateDNS(self):
        self.id        = self.dnsID
        self.qr        = 1
        self.opcode    = 0
        self.aa        = 0
        self.tc        = 0
        self.rd        = 1
        self.ra        = 1
        self.z         = 0
        self.ad        = 0
        self.cd        = 0
        self.rcode     = 0
        self.qdcount   = 1
        self.ancount   = 1
        self.nscount   = 0
        self.arcount   = 0
        self.dnsL = self.dnsRL + 12

    def AssembleDNS(self):
        self.p1 = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | (self.rd << 0)
        self.p2 = (self.ra << 7) | (self.z << 6) | (self.ad << 5) | (self.cd << 4) | (self.rcode << 0)

        self.dns_header = struct.pack('!H2B4H' ,
        self.id,
        self.p1,
        self.p2,
        self.qdcount,
        self.ancount,
        self.nscount,
        self.arcount
        )

    def CreateQueryResponse(self):
        self.qname     = self.url
        self.qtype     = 1
        self.qclass    = 1

        self.rrname    = b'\xc0\x0c'
        self.type      = 1
        self.rclass    = 1
        self.ttl       = 300
        self.rdlen     = 4
        self.rdata     = inet_aton(self.response_ip)
        self.urlTTL    = len(self.url) * 2
        self.dnsRL     = self.urlTTL + 14 + 2

    def AssembleQueryResponse(self):
        split_url = self.url.split('.')
        for part in split_url:
            self.dns_payload += struct.pack('B', len(part))
            for char in part:
                self.dns_payload += struct.pack('B', ord(char))

        self.dns_payload += b'\x00'
        self.dns_payload += struct.pack('!2H' ,
        self.qtype,
        self.qclass
        )
        self.dns_payload += self.dns_payload
        self.dns_payload += struct.pack('!LH4s' ,
        self.ttl,
        self.rdlen,
        self.rdata
        )
