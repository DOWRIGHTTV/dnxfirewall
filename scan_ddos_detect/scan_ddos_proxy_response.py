#!/usr/bin/python3

import os, sys
import struct
import time
import binascii
import subprocess
import array

from contextlib import closing
from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, IPPROTO_ICMP

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_packet_checks import Checksums
from dnx_configure.dnx_system_info import Interface

class ICMPResponse:
    def __init__(self, wan_int, packet):
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((wan_int, 0))
        
        self.Packet = Packet(wan_int, packet)
        self.Packet.Start()

    def Response(self):

        self.Packet.AssembleEthernet()
        self.Packet.AssembleIPv4()
        self.Packet.AssembleICMP()

        packet = self.Packet.ethernet_header + self.Packet.ipv4_header + self.Packet.icmp_header
        packet += self.Packet.icmp_payload
        self.s.send(packet)
        print('PACKET SENT')

class Packet:
    def __init__(self, wan_int, packet):
        self.packet = packet
        self.wan_int = wan_int

        self.Checksum = Checksums()

    def Start(self):
        self.AssignValues()
        self.CreateICMP()
        self.AssembleICMP()
        self.CreateIPv4()
        self.AssembleIPv4()

        self.ip_chk = self.Checksum.IPv4(self.ipv4_header)        
        self.icmp_chk = self.Checksum.ICMP(self.icmp_header + self.icmp_payload)

    def AssignValues(self):
        self.icmp_payload = self.packet.ipv4_header + self.packet.udp_header
        Int = Interface()
        self.smac = Int.MAC(self.wan_int)
        self.dmac = self.packet.src_mac
        self.src_ip = Int.IP(self.wan_int)
        self.dst_ip = self.packet.src_ip
        self.l2pro = 0x0800
        
    def AssembleEthernet(self):
        self.ethernet_header = struct.pack('!6s6sH' ,
        binascii.unhexlify(self.dmac.replace(":","")),
        binascii.unhexlify(self.smac.replace(":","")),
        self.l2pro)
      
    def CreateIPv4(self):
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4 ) + ip_vhl
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn
        self.ip_tol = 20 + len(self.icmp_payload + self.icmp_header) # +8 for original udp header
        self.ip_idf = 0
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)
        self.ip_ttl = 255   
        self.ip_proto = IPPROTO_ICMP
        self.ip_chk = 0
        self.ip_saddr = inet_aton(self.src_ip)
        self.ip_daddr = inet_aton(self.dst_ip)
    
    def AssembleIPv4(self):
        self.ipv4_header = struct.pack('!BBHHHBB' ,
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
          
    def CreateICMP(self):            
        self.icmp_type = 3
        self.icmp_code = 3
        self.icmp_chk  = 0
        self.icmp_id   = 1
        self.icmp_seq  = 0
        self.padding   = 0

    def AssembleICMP(self):
        self.icmp_header = struct.pack('!2B',
        self.icmp_type,
        self.icmp_code)
        self.icmp_header += struct.pack('<H',
        self.icmp_chk
        )
        self.icmp_header += struct.pack('!2H',
        self.icmp_id,
        self.icmp_seq,
        )