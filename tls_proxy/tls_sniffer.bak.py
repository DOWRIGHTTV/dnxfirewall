#!/usr/bin/env python3

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
        print('[+] Sniffing on interface {}'.format(self.iface))
        while True:
            data, addr = self.s.recvfrom(8000)
            try:
                Packet = PacketParse(data, addr)
                Packet.Parse()
                if (Packet.protocol == 6):
                    if (Packet.sport == 443 and Packet.handshake_type == 11):
                        self.action(Packet)
            except AttributeError:
                pass
            except Exception as E:
                print(E)
                                        
class PacketParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr

        self.certificate_present = False

        self.certificate_chain = []

    def Parse(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol != 1):
            self.Ports()
#        if (self.dport == 443):
#            self.RecordLayer()
        self.offset = 0
        if (self.sport == 443):
            while True:
                self.HandshakeProtocol()
                if (self.content_type == 22):
                    if (self.handshake_type == 2):
                        self.offset = self.content_length
                    elif (self.handshake_type == 11):
                        print(self.handshake_type)
                        self.Certificate()
                        self.certificate_offset = 0
                        self.cert_count = 0
                        while True:
                            print('happy easter')
                            self.Certificate_Chain()
                            self.cert_count += 1
                            if (self.certificate_end >= self.certificate_total_length):
                                print('{} {}'.format(self.certificate_total_length, self.certificate_end))
                                break
                        print(self.cert_count)
                        break
                    else:
                        break
                else:
                    break

                
    def Ethernet(self):
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
    
    def IP(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src = '{}.{}.{}.{}'.format(s[0], s[1], s[2], s[3])
        self.dst = '{}.{}.{}.{}'.format(d[0], d[1], d[2], d[3])
        
    def Protocol(self):
        self.protocol = self.data[23]
        
    def Ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]

    def TCP(self):
        tcp = self.data[34:66]

    def HandshakeProtocol(self):
        handshake_protocol = struct.unpack('!B2HB', self.data[self.offset + 66:self.offset + 72])
        self.content_type = handshake_protocol[0]
        self.version = handshake_protocol[1]
        self.handshake_length = handshake_protocol[2]
        self.handshake_type = handshake_protocol[3]

        self.hs_protocol_size = self.handshake_length + 4
        self.content_length = self.handshake_length + 5

    def Certificate(self):
        print('in certificate overall')
        self.certificate_length_start = self.offset + 66 + 12
        self.certificate_total_length = struct.unpack('!H', self.data[self.offset+66+7:self.offset+66+7+2])[0]

        print('CERT TOTAL LENGTH: {}'.format(self.certificate_total_length))

        self.certificates = self.data[self.certificate_length_start:]

    def Certificate_Chain(self):
        self.certificate_present = True
        print('CERT OFFSET: {}'.format(self.certificate_offset))
        print('='*23)
        print('CERT OFFSET + CERT START: {}'.format(self.certificate_offset+self.certificate_length_start))
        print(self.data[self.certificate_offset+self.certificate_length_start:])
        print('+'*23)

        self.certificate_start = self.certificate_length_start + 3
#        self.cc_first_byte = struct.unpack('!B', self.data[self.certificate_start])
        certificate_length = struct.unpack('!H', self.data[self.certificate_offset+self.certificate_length_start+1:self.certificate_offset+self.certificate_length_start+3])[0]
        print(certificate_length)
        self.certificate_end = self.certificate_offset + self.certificate_start + certificate_length

        self.certificate = self.data[self.certificate_offset + self.certificate_start:self.certificate_end]
        print(self.certificate)
        print('OFFSET: {} || LENGTH: {}'.format(self.certificate_offset, certificate_length))
        self.certificate_offset += certificate_length + 3

        # certificate_info = struct.unpack('!2BHBH', self.data[self.cert_info:self.cert_info + 7])
        # self.handshake_type = certificate_info[0]
        # self.clength = certificate_info[4]
        # self.cert_start = self.cert_info + 7
        # self.certificates = self.data[self.cert_start+3:self.cert_start+3+self.clength-6]

    # def Print(self):
        # print('='*23)
        # for i, _ in enumerate(self.data[66:72], 1):
        #     pass
        # print('Record Layer: {}: {}'.format(i, self.data[66:72]))
        # print('CTYPE1: {}'.format(self.ctype1))
        # print('LENGTH: {}'.format(self.length))

        # print('-'*23)

        # print('CTYPE2: {}'.format(self.ctype2))
        # print('HSTYPE: {}'.format(self.handshake_type))
        # print('CLENGTH: {}'.format(self.clength-6))

        # print('='*23)

        # self.length = handshake_protocol[5]

        # self.hp_cert_start = 66 + self.rlength
        # self.cert_info = self.hp_cert_start + 5
        # hp_cert = struct.unpack('B', self.data[self.hp_cert_start:self.hp_cert_start+1])
        # self.ctype2 = hp_cert[0]
        # print(self.ctype2)
