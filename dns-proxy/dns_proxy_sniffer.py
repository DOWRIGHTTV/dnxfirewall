#!/usr/bin/python3

from socket import *
import struct
import binascii
import codecs

class Sniffer:
    def __init__(self, iface, action):
        self.action = action
        self.iface = iface
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.iface, 3))
        
    def Start(self):
        print('[+] Sniffing on: {}'.format(self.iface))
        while True:
            data, addr = self.s.recvfrom(1024)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.qname) and (Packet.qtype == 1):
                    self.action(Packet)
            except AttributeError as AE:
                pass
            except Exception as E:
                print(E)
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        
    def Parse(self):
        try:
            self.udp()
            if (self.dport == 53):
                self.dnsQuery()
                self.dns()
                if (self.qtype == 1):
                    self.ip()
                    self.ethernet()
            else:
                pass
        except Exception:
            pass
                
    def ethernet(self):   
        s = []
        d = []
        smac = struct.unpack('!6c', self.data[0:6])
        dmac = struct.unpack('!6c', self.data[6:12])
        PROTO = struct.unpack('!2c', self.data[12:14])

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

    def udp(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]
    
    def dns(self):
        dnsID = struct.unpack('!H', self.data[42:44])
        self.dnsID = dnsID[0]        

    def dnsQuery(self):
        qn = self.data[54:].split(b'\x00',1)
        qt = qn[1]
        qn = qn[0]
        b = 1
        for byte in qn[1:]:
            b += 1

        qname = struct.unpack('!{}B'.format(b), qn[0:b+1])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        len = -1
        self.qname = ''
        for byte in qname:
            if(len == -1):
                len = byte
            elif(len == 0):
                len = byte
                self.qname += "."
            else:
                self.qname += chr(byte)
                len -= 1
      
        
