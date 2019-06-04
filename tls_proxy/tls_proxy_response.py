#!/usr/bin/env python3

import os, sys
import json
import array
import binascii
import struct

from socket import socket, htons, inet_aton, AF_PACKET, SOCK_RAW, IPPROTO_TCP

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_packet_checks import Checksums

class TLSResponse:
    def __init__(self, connection, to_server=False):
        self.path = os.environ['HOME_DIR']

        with open(f'{self.path}/data/config.json', 'r') as settings:
            setting = json.load(settings)                      
        wan_int = setting['Settings']['Interface']['Outside']          
        lan_int = setting['Settings']['Interface']['Inside']

#        wan_int = 'eth0'
        self.s = socket(AF_PACKET, SOCK_RAW)
        if (to_server):
            self.s.bind((wan_int, 0))
        else:
            self.s.bind((lan_int, 0))
        
        self.Packet = CreatePacket(connection, to_server)
        self.Packet.Create()

    def Send(self):
        self.Packet.AssembleEthernet()
        self.Packet.AssembleIPv4()
        self.Packet.AssembleTCP()
        packet = self.Packet.ethernet_header + self.Packet.ipv4_header + self.Packet.tcp_header
        print(packet)
        self.s.send(packet)
        print('TCP RESET SENT')

class CreatePacket:
    def __init__(self, connection, to_server=False):
        self.connection = connection
        self.to_server = to_server

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
        self.nat_port = struct.pack('!H', self.connection['NAT']['Port'])
        self.client_port = struct.pack('!H', self.connection['Client']['Port'])

        if (self.to_server):
            self.smac = self.connection['NAT']['MAC']
            self.src_ip = self.connection['NAT']['IP']
            self.sport = self.connection['NAT']['Port']
            self.dmac = self.connection['DFG']['MAC']
            self.dst_ip = self.connection['Server']['IP']
            self.dport = self.connection['Server']['Port']
        else:
            self.smac = self.connection['LAN']['MAC']
            self.src_ip = self.connection['Server']['IP']
            self.sport = self.connection['Server']['Port']
            self.dmac = self.connection['Client']['MAC']
            self.dst_ip = self.connection['Client']['IP']
            self.dport = self.connection['Client']['Port']
        
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
        self.tcp_seq = 696969
        self.tcp_ack_seq = 0
        self.tcp_hdr_len = 80

        tcp_urg = 0
        tcp_ack = 0
        tcp_psh = 0
        tcp_rst = 1
        tcp_syn = 0
        tcp_fin = 0

        tcp_doff = 5
        self.tcp_offset_res = (tcp_doff << 4) + 0
        self.tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        self.tcp_wdw = htons(5840)
        self.tcp_checksum = 0
        self.tcp_urg_ptr = 0
        self.padding = b'\x00'*12

    def AssembleTCP(self):
        self.tcp_header = struct.pack('!2H2L2B3H',
        self.sport,
        self.dport,
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
        if (self.to_server):
            pseudo_header += self.nat_port + self.tcp_header[2:16] + b'\x00\x00' + self.tcp_header[18:]
        else:                   
            pseudo_header += self.tcp_header[0:2] + self.client_port + self.tcp_header[4:16] + b'\x00\x00' + self.tcp_header[18:]     
        pseudo_packet = pseudo_header
        
        tcp_checksum = self.Checksum.TCP(pseudo_packet)

        return tcp_checksum

if __name__ == '__main__':
    connection = {'Client': {'IP': '192.168.5.135', 'Port': 4400, 'MAC': 'bb:bb:bb:bb:bb:bb'},
                        'NAT': {'IP': '192.168.5.135', 'Port': 4400, 'MAC': '08:00:27:02:10:b6'},
                        'LAN': {'IP': '10.10.10.10', 'MAC': 'aa:aa:aa:aa:aa:aa'},
                        'Server': {'IP': '192.168.2.1', 'Port': 4444},
                        'DFG': {'MAC': 'fc:aa:14:fe:1d:c8'},
                        'Socket': 'sock'}

    TLSR = TLSResponse(connection, to_server=True)
    TLSR.Send()