#!/usr/bin/python3

import os, sys
import struct
import time
import binascii
import subprocess
import array

from contextlib import closing
from socket import socket, inet_aton, htons, AF_PACKET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_TCP

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_packet_checks import Checksums
from dnx_configure.dnx_system_info import Interface

ICMP = 1
TCP = 6
UDP = 17

class ScanResponse:
    def __init__(self, wan_int, packet, protocol):
        self.protocol = protocol

        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((wan_int, 0))

        if (protocol == TCP):
            self.Packet = TCPPacket(wan_int, packet)
        elif (protocol == UDP):
            self.Packet = ICMPPacket(wan_int, packet)

        self.Packet.Create()

    def Response(self):
        if (self.protocol == TCP):
            self.Packet.AssembleEthernet()
            self.Packet.AssembleIPv4()
            self.Packet.AssembleTCP()

            packet = self.Packet.ethernet_header + self.Packet.ipv4_header + self.Packet.tcp_header
            self.s.send(packet)
            print('TCP RESET SENT')

        elif (self.protocol == UDP):
            self.Packet.AssembleEthernet()
            self.Packet.AssembleIPv4()
            self.Packet.AssembleICMP()

            packet = self.Packet.ethernet_header + self.Packet.ipv4_header + self.Packet.icmp_header
            packet += self.Packet.icmp_payload
            self.s.send(packet)
            print('PACKET SENT')

class ICMPPacket:
    def __init__(self, wan_int, packet):
        self.packet = packet
        self.wan_int = wan_int

        self.Checksum = Checksums()

    def Create(self):
        self.AssignValues()
        self.CreateICMP()
        self.AssembleICMP()
        self.CreateIPv4()
        self.AssembleIPv4()

        self.ip_chk = self.Checksum.IPv4(self.ipv4_header)        
        self.icmp_chk = self.Checksum.ICMP(self.icmp_header + self.icmp_payload)

    def AssignValues(self):
        self.l2pro = 0x0800
        Int = Interface()
        self.smac = Int.MAC(self.wan_int)
        self.dmac = self.packet.src_mac
        self.src_ip = Int.IP(self.wan_int)
        self.dst_ip = self.packet.src_ip
        self.icmp_payload = self.packet.ipv4_header + self.packet.udp_header

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

class TCPPacket:
    def __init__(self, wan_int, packet):
        self.packet = packet
        self.wan_int = wan_int

        self.Checksum = Checksums()

    def Create(self):
        self.AssignValues()
        self.CreateIPv4()
        self.CreateTCP()

        self.AssembleIPv4()
        self.AssembleTCP()

        self.ipv4_checksum = self.Checksum.IPv4(self.ipv4_header)
        self.tcp_checksum = self.PseudoHeader()

    def AssignValues(self):
        self.l2pro = 0x0800
        Int = Interface()
        self.smac = Int.MAC(self.wan_int)
        self.dmac = self.packet.src_mac
        self.src_ip = Int.IP(self.wan_int)
        self.dst_ip = self.packet.src_ip
        self.src_port = self.packet.dst_port
        self.dst_port = self.packet.src_port

        self.sport = struct.pack('!H', self.src_port)
#        print(self.packet.seq_number)
        self.ack_number = self.packet.seq_number + 1
## -- L2 - Ethernet Section ---- ##
    def AssembleEthernet(self):
        self.ethernet_header = struct.pack('!6s6sH' ,
        binascii.unhexlify(self.dmac.replace(":","")),
        binascii.unhexlify(self.smac.replace(":","")),
        self.l2pro)

## -- L3 - IP Section ---- ##        
    def CreateIPv4(self):
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4 ) + ip_vhl
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn
        self.ip_tol = 20 + 20                   # ---- [ Total Length]        
        self.ip_idf = 1                     # ---- [ Identification ]        
        ip_rsv = 0                          # ---- [ Flags ]
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)        
        self.ip_ttl = 255                           # ---- [ Total Length ]        
        self.ip_proto = IPPROTO_TCP                 # ---- [ Protocol ]        
        self.ipv4_checksum = 0           # ---- [ Check Sum ]        
        self.ip_saddr = inet_aton(self.src_ip)      # ---- [ Source Address ]        
        self.ip_daddr = inet_aton(self.dst_ip)      # ---- [ Destination Address ]
    
    def AssembleIPv4(self):
        self.ipv4_header = struct.pack('!2B3H2B' ,
        self.ip_ver,        # IP Version 
        self.ip_dfc,        # Differentiate Service Field
        self.ip_tol,        # Total Length
        self.ip_idf,        # Identification
        self.ip_flg,        # Flags
        self.ip_ttl,        # Time to leave
        self.ip_proto        # protocol
        )    
        self.ipv4_header += struct.pack('<H' ,
        self.ipv4_checksum         # Checksum
        )
        self.ipv4_header += struct.pack('!4s4s' ,
        self.ip_saddr,        # Source IP 
        self.ip_daddr        # Destination IP
        )

## -- L4 - UDP Section ---- ##            
    def CreateTCP(self):          
        self.tcp_seq = 0
        self.tcp_ack_seq = self.ack_number
        self.tcp_hdr_len = 80

        tcp_urg = 0
        tcp_ack = 1
        tcp_psh = 0
        tcp_rst = 1
        tcp_syn = 0
        tcp_fin = 0

        tcp_doff = 5
        self.tcp_offset_res = (tcp_doff << 4) + 0
        self.tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        self.tcp_wdw = htons(0)
        self.tcp_checksum = 0
        self.tcp_urg_ptr = 0
        self.padding = b'\x00'*12

    def AssembleTCP(self):
        self.tcp_header = struct.pack('!2H2L2B3H',
        self.src_port,
        self.dst_port,
        self.tcp_seq,
        self.tcp_ack_seq,
        self.tcp_offset_res,
        self.tcp_flags,
        self.tcp_wdw,
        self.tcp_checksum,
        self.tcp_urg_ptr
        )

    def PseudoHeader(self):
        pseudo_header = b''
        pseudo_header += inet_aton(self.src_ip)
        pseudo_header += inet_aton(self.dst_ip)
        pseudo_header += struct.pack('!2BH', 0, 6, 54)
        pseudo_header += self.sport + self.tcp_header[2:16] + b'\x00\x00' + self.tcp_header[18:]
        
        tcp_checksum = self.Checksum.TCP(pseudo_header)

        return tcp_checksum