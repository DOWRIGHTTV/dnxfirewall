#!/usr/bin/python3

import os, sys
import struct
import binascii
import codecs

from socket import socket, AF_PACKET, SOCK_RAW

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_exceptions import *

ICMP = 1
TCP = 6
UDP = 17

class Sniffer:
    def __init__(self, lan_int, action):
        self.lan_int = lan_int
        self.action = action
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.lan_int, 3))
        
    def Start(self):
        print('[+] Sniffing on All Interfaces')
        while True:
            data, addr = self.s.recvfrom(1600)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.protocol in {TCP, UDP}):
                    self.action(Packet)
            except DNXError:
                pass
            except Exception as E:
                print(E)
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        
    def Parse(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol in {TCP, UDP}):
            self.Ports()
        else:
            raise IPProtocolError('Packet protocol is not 6/TCP or 17/UDP')
                
    def Ethernet(self):   
        s = []
        d = []
        smac = struct.unpack('!6c', self.data[0:6])
        dmac = struct.unpack('!6c', self.data[6:12])

        for byte in smac:
            s.append(byte.hex())
        for byte in dmac:
            d.append(byte.hex())
    
        self.smac = f'{s[0]}:{s[1]}:{s[2]}:{s[3]}:{s[4]}:{s[5]}'
        self.dmac = f'{d[0]}:{d[1]}:{d[2]}:{d[3]}:{d[4]}:{d[5]}'
    
    def IP(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'
        
    def Protocol(self):
        self.protocol = self.data[23]
        
    def Ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]
        
