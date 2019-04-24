#!/usr/bin/python3

import sys
import struct
import time
import binascii
import subprocess
import array
from contextlib import closing
from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, IPPROTO_UDP


class DNSResponse:
    def __init__(self, iface, insideip, packet):
        self.iniface = iface
        
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.iniface, 0))
        
        self.ip = Packet(insideip, packet)
        self.ip.Start()

    def Response(self):
        self.ip.assemble_QueryR_fields()
        self.ip.assemble_dns_fields()
        self.ip.assemble_udp()
        self.ip.assemble_ipv4_fields()
        self.ip.assemble_eth_fields()
        complete =  self.ip.raw1 + self.ip.raw2 + self.ip.raw3  + self.ip.raw4 + self.ip.raw5
        self.s.send(complete)
#        print('Response Sent')

class Packet:
    def __init__(self, insideip, packet):
        self.insideip = insideip
        self.packet = packet
    
    def Start(self):
        self.split_packet()
        self.create_QueryR_fields()
        self.create_dns_fields()
        self.create_udp_fields()
        self.create_ipv4_fields_list()
        self.ipv4H = self.assemble_ipv4_fields()
        self.ip_chk = self.cksum(self.ipv4H)

    
    def split_packet(self):
        self.smac = self.packet.dmac
        self.dmac = self.packet.smac
        self.dstip = self.packet.src
        self.src = self.packet.dst
        self.sport = 53
        self.dport = self.packet.sport
        self.dst = (self.dstip, int(self.dport))
        self.dnsID = self.packet.dnsID
        self.url = self.packet.qname.lower()

        # Ethernet II (DIX) Protocol Types
        self.l2pro = 0x0800        # Internet Protocol packet        
        
    def cksum(self, s):
        if len(s) & 1:
            s = s + '\0'
        words = array.array('h', s)
        sum = 0
        for word in words:
            sum = sum + (word & 0xffff)
        hi = sum >> 16
        lo = sum & 0xffff
        sum = hi + lo
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff
        
## -- L2 - Ethernet Section ---- ##
    def assemble_eth_fields(self):
# ---- [Assemble All Fields Of Ether Packet] ---- #
        self.raw1 = struct.pack('!6s6sH' ,
        binascii.unhexlify(self.smac.replace(":","")),
        binascii.unhexlify(self.dmac.replace(":","")),
        self.l2pro)

## -- L3 - IP Section ---- ##        
    def create_ipv4_fields_list(self):
# ---- [Internet Protocol Version] ---- #
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4 ) + ip_vhl
# ---- [Differentiate Servic Field] ---- #
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn        
        self.ip_tol = 20 + self.udp_len     # ---- [ Total Length]        
        self.ip_idf = 0     # ---- [ Identification ]        
        ip_rsv = 0             # ---- [ Flags ]
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)        
        self.ip_ttl = 255                     # ---- [ Total Length ]        
        self.ip_proto = IPPROTO_UDP             # ---- [ Protocol ]        
        self.ip_chk = 0                         # ---- [ Check Sum ]        
        self.ip_saddr = inet_aton(self.src)     # ---- [ Source Address ]        
        self.ip_daddr = inet_aton(self.dstip)     # ---- [ Destination Address ]
    
    def assemble_ipv4_fields(self):
        self.raw2 = struct.pack('!BBHHHBB' ,
        self.ip_ver,        # IP Version 
        self.ip_dfc,        # Differentiate Service Field
        self.ip_tol,        # Total Length
        self.ip_idf,        # Identification
        self.ip_flg,        # Flags
        self.ip_ttl,        # Time to leave
        self.ip_proto        # protocol
        )    
        self.raw2 += struct.pack('<H' ,
        self.ip_chk         # Checksum
        )
        self.raw2 += struct.pack('!4s4s' ,
        self.ip_saddr,        # Source IP 
        self.ip_daddr        # Destination IP
        )
        return(self.raw2)

## -- L4 - UDP Section ---- ##            
    def create_udp_fields(self):            
        self.udp_sport = 53  # ---- [ Source Port]        
        self.udp_dport = self.dport    # ---- [ Destination Port ]        
        self.udp_len = self.dnsL + 8 + 6        # ---- [ Total Length ]        
        self.udp_chk = 0        # ---- [ Check Sum ]

    def assemble_udp(self):
        self.raw3 = struct.pack('!HHHH' ,
        self.udp_sport,         # IP Version 
        self.udp_dport,         # Differentiate Service Field
        self.udp_len,         # Total Length
        self.udp_chk         # Identification
        )
        
    def create_dns_fields(self):    
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
        
    def assemble_dns_fields(self):
        self.p1 = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | (self.rd << 0)
        self.p2 = (self.ra << 7) | (self.z << 6) | (self.ad << 5) | (self.cd << 4) | (self.rcode << 0)          
        self.raw4 = struct.pack('!H2B4H' ,
        self.id,
        self.p1,
        self.p2,
        self.qdcount,
        self.ancount,
        self.nscount,
        self.arcount
        )
        
    def create_QueryR_fields(self):
     ###[ DNS Question Record ]###
        self.qname     = self.url
        self.qtype     = 1
        self.qclass    = 1
        
     ###[ DNS Resource Record ]###
        self.rrname    = b'\xc0\x0c' #self.url
        self.type      = 1
        self.rclass    = 1
        self.ttl       = 300
        self.rdlen     = 4
        self.rdata     = inet_aton(self.insideip)
        self.urlTTL = len(self.url) + len(self.url)
        self.dnsRL = self.urlTTL  + 14 + 2
        
    def assemble_QueryR_fields(self):
     ###[ DNS Question Record ]###
        split_url = self.url.split(".")
        self.urlpack = b''
        for part in split_url: # iterate (2) for madd and org
            self.urlpack += struct.pack("B", len(part))
            for char in part:
                self.urlpack += struct.pack("B", ord(char))
        self.urlpack = self.urlpack + b'\x00'
        self.urlpack = self.urlpack + struct.pack('!2H' ,
        self.qtype,
        self.qclass
        )
        self.urlpack += self.urlpack
#        print(self.urlpack)
     ###[ DNS Resource Record ]###        
        self.raw5 = self.urlpack + struct.pack('!LH4s' , 
        self.ttl,
        self.rdlen,
        self.rdata
        )        
        
