#!/usr/bin/python3

import struct
import binascii
import codecs

from socket import socket, inet_aton, AF_PACKET, SOCK_RAW

from dnx_configure.dnx_exceptions import *

class Sniffer:
    def __init__(self, iface, action):
        self.action = action
        self.iface = iface
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.iface, 3))
        
    def Start(self):
        print(f'[+] Sniffing on: {self.iface}')
        while True:
            data, addr = self.s.recvfrom(1600)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.protocol in {6, 17}):
                    self.action(Packet)
            except DNXError:
                pass
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        
    def Parse(self):
        self.Ethernet()
        self.Protocol()
        self.IP()
        if (self.protocol in {17}):
            self.UDP()
        elif (self.protocol in {6}):
            self.TCP()
        else:
            raise IPProtocolError('Packet protocol is not 6/TCP or 17/UDP')

    def Ethernet(self):  
        s = []
        d = []
        smac = struct.unpack('!6c', self.data[6:12])
        dmac = struct.unpack('!6c', self.data[0:6])

        for byte in smac:
            s.append(byte.hex())
        for byte in dmac:
            d.append(byte.hex())
    
        self.src_mac = f'{s[0]}:{s[1]}:{s[2]}:{s[3]}:{s[4]}:{s[5]}'
        self.dst_mac = f'{d[0]}:{d[1]}:{d[2]}:{d[3]}:{d[4]}:{d[5]}'
    
    def IP(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src_ip = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst_ip = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'

        self.ipv4_header = self.data[14:34]

    def Protocol(self):
        self.protocol = self.data[23]

    def UDP(self):
        udp_header = struct.unpack('!4H', self.data[34:42])
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.udp_length = udp_header[2]
        self.udp_checksum = udp_header[3]

        self.udp_header = self.data[34:42]

    def TCP(self):
        tcp_header = struct.unpack('!2H', self.data[34:38])
        self.src_port = tcp_header[0]
        self.dst_port = tcp_header[1]
#        tcp_header = struct.unpack('!4H', self.data[34:])
        