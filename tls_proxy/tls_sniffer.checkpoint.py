#!/usr/bin/env python3

from socket import socket, inet_aton, inet_ntoa, AF_PACKET, SOCK_RAW
import struct
import binascii
import codecs

class Sniffer:
    def __init__(self, iface, action):
        self.iface = iface
        self.action = action
        self.s = socket(AF_PACKET, SOCK_RAW)
        self.s.bind((self.iface, 3))

        self.ssl_packet = []
        self.ssl_lengths = []

        self.ack_check = 0
        self.sequence_number = 0
        
    def Start(self):
        print('[+] Sniffing on interface {}'.format(self.iface))
        while True:
            data, addr = self.s.recvfrom(1650)
            try:
                Header = HeaderParse(data, addr)
                hs_type, seq_number, ack_number, tcp_segment_length = Header.Parse()
                packet_length = len(self.ssl_packet) - 1
                if (hs_type == 1):
                    print('='*30)
                    print('CLIENT HELLO')
                    self.ack_check = seq_number + tcp_segment_length
                    self.ssl_packet.append(data)
                elif (hs_type == 2):
                    print('SERVER HELLO')
#                    print('ACK: {} || CHECK: {}'.format(ack_number, self.ack_check))
                    if (ack_number == self.ack_check):
                        print('SEQ: {} || CHECK: {}'.format(seq_number, self.sequence_number))
                        if (self.sequence_number == 0):                           
                            self.ssl_packet.append(data)
                            self.sequence_number += tcp_segment_length + seq_number
                            print('-'*30)
                elif (seq_number == self.sequence_number):
                    self.ssl_packet.append(data)
                    self.sequence_number += tcp_segment_length
                if (self.ssl_packet[packet_length][-4:] == b'\x0e\x00\x00\x00'):
                    print(self.ssl_packet)
                    self.ssl_packet = []
                print('SEQ: {} || CHECK: {}'.format(seq_number, self.sequence_number))
                print('ACK: {} || CHECK: {}'.format(ack_number, self.ack_check))
#                if (Packet.protocol == 6):
                    # if (Packet.sport == 443 and Packet.handshake_type == 11):
                    #     self.action(Packet)
#                    pass
            except AttributeError:
                pass
            except Exception as E:
                pass
                                        
class HeaderParse:
    def __init__(self, data, addr):
        self.data = data
        self.addr = addr

    def Parse(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol == 6):
            self.Ports()
        if (self.dport == 443):
            self.HandshakeProtocol()
            if (self.content_type == 22 and self.handshake_type == 1):
                print('CLIENT HELLO || SRC PORT: {}'.format(self.sport))
                seq_number, ack_number, tcp_segment_length = self.TCP() 
                return 1, seq_number, ack_number, tcp_segment_length

        ## SERVER HELLO ACK_NUMBER NEEDS TO MATCH SEQUENCE NUMBER + TCP SEGMENT LENGTH
        ## OF CLIENT HELLO
        elif (self.sport == 443):
            self.HandshakeProtocol()
            if (self.content_type == 22 and self.handshake_type == 2):
                print('SERVER HELLO || DST PORT: {}'.format(self.dport))
                seq_number, ack_number, tcp_segment_length = self.TCP()
                return 2, seq_number, ack_number, tcp_segment_length
        else:
            return 'Nein', 'Nein', 'Nein', 'Nein'
                
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
        tcp_header_length = 0
        bit_values = [32,16,8,4]

        tcp = self.data[34:66]
        seq_number = tcp[4:8]
        ack_number = tcp [8:12]
        seq_number = struct.unpack('!L', seq_number)[0]
        ack_number = struct.unpack('!L', ack_number)[0]
        tmp_length = bin(tcp[12])[2:6]
#        tmp_length = bin(struct.unpack('!B', tcp[12])[0])[2:6]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                tcp_header_length += bit_values[i]

        tcp_segment_length = len(self.data) - 34
        tcp_segment_length -= tcp_header_length

        # print('SEQUENCE: {}'.format(seq_number))
        # print('ACK: {}'.format(ack_number))

        # print('SEG LEN: {}'.format(tcp_segment_length))
        return seq_number, ack_number, tcp_segment_length

    def HandshakeProtocol(self):
        handshake_protocol = struct.unpack('!B2HB', self.data[66:72])
        self.content_type = handshake_protocol[0]
        self.version = handshake_protocol[1]
        self.handshake_length = handshake_protocol[2]
        self.handshake_type = handshake_protocol[3]

class SSLParse:
    def __init__(self):

        self.certificate_present = False
        self.certificate_chain = []

        self.packet_stuffs = []

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
#        print(certificate_length)
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
