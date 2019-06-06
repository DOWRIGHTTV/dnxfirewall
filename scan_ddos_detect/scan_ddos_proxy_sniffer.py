#!/usr/bin/python3

import os, sys
import struct
import binascii
import codecs
#ADD TRACEBAACK TO THIS SHIT


from socket import socket, inet_aton, AF_PACKET, SOCK_RAW

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_exceptions import *

class Sniffer:
    def __init__(self, wan_int, wan_ip, action):
        self.action = action
        self.wan_int = wan_int
        self.wan_ip = wan_ip
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.wan_int, 3))
        
    def Start(self):
        print(f'[+] Sniffing on: {self.wan_int}')
        while True:
            send_to_proxy = False
            data, addr = self.s.recvfrom(1600)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.protocol in {6}):#, 17}):
#                    if (Packet.dst_port <= 1024 or Packet.src_port <= 1024):
                    if (Packet.dst_ip == self.wan_ip and Packet.tcp_syn and not Packet.tcp_ack):
                        send_to_proxy = True
                    elif (Packet.dst_ip == self.wan_ip and Packet.tcp_ack and not Packet.tcp_syn):
                        send_to_proxy = True
                    elif (Packet.src_ip == self.wan_ip and Packet.tcp_syn and Packet.tcp_ack):
                        send_to_proxy = True
                elif (Packet.protocol in {17}):
                    if (Packet.dst_ip == self.wan_ip):
                        send_to_proxy = True

                if (send_to_proxy):
                    self.action(Packet)
            except DNXError:
                pass
            except Exception as E:
                print(E)
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr

        self.tcp_syn = False
        self.tcp_ack = False
        
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
#        tcp_header = self.data[34:66]
#        tcp_flags = tcp_header[14]
        tcp_ports = struct.unpack('!2H', self.data[34:38]) #2LH
        self.src_port = tcp_ports[0]
        self.dst_port = tcp_ports[1]

#        print(self.data[46:50])
#        tcp_flags_all = {8: '', 7: '', 6: 'URG', 5: 'ACK', 4: 'PSH', 3: 'RST', 2: 'SYN', 1: 'FIN'}
        if (self.data[47] & 1 << 1):
            self.tcp_syn = True
        if (self.data[47] & 1 << 4):
            self.tcp_ack = True
        # if (tcp_flags[0] & 1 << 1):
        #     self.tcp_syn = True
        # if (tcp_flags[0] & 1 << 4):
        #     self.tcp_ack = True

        
                
        