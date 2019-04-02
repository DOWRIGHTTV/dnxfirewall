#!/usr/bin/python3

from socket import socket, AF_PACKET, SOCK_RAW
import struct
import binascii
import codecs

class Sniffer:
    def __init__(self, iface, action):
        self.iface = iface
        self.action = action
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.iface, 3))
        
    def Start(self):
        print('[+] Sniffing on All Interfaces')
        while True:
            data, addr = self.s.recvfrom(1600)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.protocol == 6 or Packet.protocol == 17):
                    self.action(Packet)
            except AttributeError:
                pass
            except Exception as E:
                print(E)
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        
    def Parse(self):
        self.ethernet()
        self.ip()
        self.protocol()
        if (self.protocol != 1):
            self.ports()

                
    def ethernet(self):   
        s = []
        d = []
        smac = struct.unpack('!6c', self.data[0:6])
        dmac = struct.unpack('!6c', self.data[6:12])

        for byte in smac:
            s.append(byte.hex())
        for byte in dmac:
            d.append(byte.hex())
    
        self.smac = '{}:{}:{}:{}:{}:{}'.format(s[0], s[1], s[2], s[3], s[4], s[5])
        self.dmac = '{}:{}:{}:{}:{}:{}'.format(d[0], d[1], d[2], d[3], d[4], d[5])  
    
    def ip(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src = '{}.{}.{}.{}'.format(s[0], s[1], s[2], s[3])
        self.dst = '{}.{}.{}.{}'.format(d[0], d[1], d[2], d[3])
        
    def protocol(self):
        self.protocol = self.data[23]
        
    def ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]
        
