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

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_packet_checks import Checksums


class DNSResponse:
    def __init__(self, packet, lan_int, response_ip, query_type=A_RECORD):
        self.lan_int = lan_int

        self.CreateSocket()
        self.Packet = Packet(response_ip, query_type)
        self.Packet.SplitPacket(packet)

    def Response(self):
        self.Packet.BuildPayload()
        self.Packet.CreateHeaders()
        dns_response = self.Packet.Assemble()

        self.sock.send(dns_response)

    def CreateSocket(self):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.lan_int, 3))

class Packet:
    def __init__(self, response_ip, query_type):
        self.response_ip = response_ip
        self.query_type = query_type

        self.response_code = 0
        self.answer_count = 0
        self.dns_payload = b''

        self.Checksum = Checksums()

    def CreateHeaders(self):
        self.CreateDNS()
        self.CreateUDP()
        self.CreateIPv4()
        self.AssembleIPv4()
        self.ip_chk = self.Checksum.IPv4(self.ipv4_header)

    def Assemble(self):
        self.AssembleEthernet()
        self.AssembleIPv4()
        self.AssembleUDP()
        self.AssembleDNS()

        dns_response = self.ethernet_header + self.ipv4_header + self.udp_header
        dns_response += self.dns_header + self.dns_payload

        return dns_response

    def BuildPayload(self):
        self.BuildQuery()
        # if AAAA record will set response code to refuse and not give an answer
        if (self.query_type == AAAA_RECORD):
            self.response_code = 5
        # if local dns record returns none due to error, will inform client of error
        elif (not self.response_ip):
            self.response_code = 2
            print('SERVER FAILURE')
        # standard query response from remote server or for local dns record
        else:
            self.answer_count = 1
            self.BuildQueryResponse()

    def SplitPacket(self, packet):
        self.dst_mac = packet.src_mac
        self.src_mac = packet.dst_mac
        self.src_ip = packet.dst_ip
        self.dst_ip = packet.src_ip
        self.src_port = DNS_PORT
        self.dst_port = packet.src_port
        self.dns_id = packet.dns_id
        self.qname = packet.request

        self.l2pro = 0x0800

    def AssembleEthernet(self):
        self.ethernet_header = struct.pack('!6s6sH' ,
        binascii.unhexlify(self.dst_mac.replace(':','')),
        binascii.unhexlify(self.src_mac.replace(':','')),
        self.l2pro)

    def CreateIPv4(self):
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4 ) + ip_vhl
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn
        self.ip_tol = 20 + self.udp_length
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
        self.udp_length = self.dns_length + 8
        self.udp_chk = 0

    def AssembleUDP(self):
        self.udp_header = struct.pack('!4H' ,
        self.src_port,
        self.dst_port,
        self.udp_length,
        self.udp_chk
        )

    def CreateDNS(self):
        self.id        = self.dns_id
        self.qr        = 1
        self.opcode    = 0
        self.aa        = 0
        self.tc        = 0
        self.rd        = 1
        self.ra        = 1
        self.z         = 0
        self.rcode     = self.response_code
        self.qdcount   = 1
        self.ancount   = self.answer_count
        self.nscount   = 0
        self.arcount   = 0

        self.dns_length = 12 + len(self.dns_payload)

    def AssembleDNS(self):
        self.p1 = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | (self.rd << 0)
        self.p2 = (self.ra << 7) | (self.z << 4) | (self.rcode << 0)

        self.dns_header = struct.pack('!H2B4H' ,
        self.id,
        self.p1,
        self.p2,
        self.qdcount,
        self.ancount,
        self.nscount,
        self.arcount
        )

    def BuildQuery(self):
        self.qclass = 1

        split_url = self.qname.split('.')
        for part in split_url:
            self.dns_payload += struct.pack('B', len(part))
            for char in part:
                self.dns_payload += struct.pack('B', ord(char))

        self.dns_payload += b'\x00'
        self.dns_payload += struct.pack('!2H' ,
        self.query_type,
        self.qclass
        )

    def BuildQueryResponse(self):
        # assigning vars
        self.rrname    = b'\xc0\x0c'
        self.type      = self.query_type
        self.rclass    = 1
        self.ttl       = 300
        self.rdlen     = 4
        self.rdata     = inet_aton(self.response_ip)

        #packing vars
        self.dns_payload += struct.pack('!2s2HLH4s' ,
        self.rrname,
        self.type,
        self.rclass,
        self.ttl,
        self.rdlen,
        self.rdata
        )
