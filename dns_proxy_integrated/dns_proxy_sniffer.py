#!/usr/bin/python3

import os, sys
import struct
import binascii
import codecs
import traceback

from socket import socket, AF_PACKET, SOCK_RAW

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_exceptions import DNXError, DNSProtocolError, UDPProtocolError, IPProtocolError

UDP = 17
DNS = 53
A_RECORD = 1

class Sniffer:
    def __init__(self, interface, action):
        self.action = action
        self.interface = interface
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.interface, 3))
        
    def Start(self):
        print(f'[+] Sniffing on: {self.interface}')
        while True:
            data, addr = self.s.recvfrom(1024)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                self.action(Packet)
            except DNXError:
                pass
            except Exception:
                traceback.print_exc()
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr
        
    def Parse(self):
        self.Protocol()
        if (self.protocol == UDP):
            self.IPv4()
            self.Ethernet()
            self.UDPHeader()
            if (self.dport == DNS):
                self.DNSHeader()
                self.DNSQuery()
                if (self.qtype != A_RECORD):
                    raise DNSProtocolError('DNS Protocol is not message type 1(IPv4 Query)')
            else:
                raise UDPProtocolError('UDP protocol is not DNS')
        else:
            raise IPProtocolError('Packet protocol is not 17/UDP')
                
    def Ethernet(self):
        smac = struct.unpack('!6c', self.data[6:12])
        dmac = struct.unpack('!6c', self.data[0:6])

        self.smac = ''
        self.dmac = ''
        for i, (b1, b2) in enumerate(zip(smac, dmac), 1):
            if (i != 1):
                self.smac += ':'
                self.dmac += ':'
            self.smac += f'{b1.hex()}'
            self.dmac += f'{b2.hex()}'
    
    def IPv4(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'

        self.ip_header_length = 0
        bit_values = [32,16,8,4]

        tcp = self.data[14:]
        tmp_length = bin(tcp[0])[5:10]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                self.ip_header_length += bit_values[i]

    def Protocol(self):
        self.protocol = self.data[23]

    def UDPHeader(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]
    
    def DNSHeader(self):
        dnsID = struct.unpack('!H', self.data[42:44])
        self.dnsID = dnsID[0]        

    def DNSQuery(self):
        offset = 14 + self.ip_header_length
        qn = self.data[offset + 20:].split(b'\x00',1)
        qt = qn[1]
        qn = qn[0]
        b = len(qn)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', qn[0:eoqname])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        # coverting query name from bytes to string
        length = qname[0] + 1
        self.qname = ''
        for byte in qname:
            if (length != 0):
                self.qname += chr(byte)
                length -= 1
                continue
                
            length = byte
            self.qname += '.'
