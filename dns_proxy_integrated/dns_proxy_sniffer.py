#!/usr/bin/python3

import os, sys
import struct
import binascii
import codecs
import traceback
import threading

from socket import socket, AF_PACKET, SOCK_RAW

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

UDP = 17
DNS = 53
A_RECORD = 1

class DNSSniffer:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy
        self.lan_int = DNSProxy.lan_int

    def Start(self):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.lan_int, 3))
        print(f'[+] Sniffing on: {self.lan_int}')
        while True:
            try:
                data = self.sock.recv(4096)

            except Exception:
                break

            try:
                packet = PacketParse(data)
                packet.Parse()
                if (packet.qtype == A_RECORD):
                    threading.Thread(target=self.DNSProxy.SignatureCheck, args=(packet,)).start()

            except Exception:
                traceback.print_exc()

        self.Start()

class PacketParse:
    def __init__(self, data):
        self.data = data

        self.qtype = 0

    def Parse(self):
        self.Protocol()
        if (self.protocol == UDP):
            self.IPv4()
            self.Ethernet()
            self.UDPHeader()
            if (self.dst_port == DNS):
                self.DNSHeader()
                self.DNSQuery()
            else:
                return
        else:
                return

    def Ethernet(self):
        src_mac = struct.unpack('!6c', self.data[6:12])
        dst_mac = struct.unpack('!6c', self.data[0:6])

        self.src_mac = ''
        self.dst_mac = ''
        for i, (b1, b2) in enumerate(zip(src_mac, dst_mac), 1):
            if (i != 1):
                self.src_mac += ':'
                self.dst_mac += ':'
            self.src_mac += f'{b1.hex()}'
            self.dst_mac += f'{b2.hex()}'

    def IPv4(self):
        s = struct.unpack('!4B', self.data[26:30])
        d = struct.unpack('!4B', self.data[30:34])
        self.src_ip = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst_ip = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'

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
        self.src_port = ports[0]
        self.dst_port = ports[1]

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

        qname = struct.unpack(f'!{b}B', qn[:eoqname])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        # coverting query name from bytes to string
        length = qname[0]
        self.qname = ''
        for byte in qname[1:]:
            if (length != 0):
                self.qname += chr(byte)
                length -= 1
                continue

            length = byte
            self.qname += '.'
