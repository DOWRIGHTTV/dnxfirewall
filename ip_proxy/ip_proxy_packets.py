#!/usr/bin/env python3

import os, sys
import struct

from ipaddress import IPv4Address

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *


class PacketParse:
    def __init__(self, data):
        self.data = data

        self.ip_header_length = 0
        self.protocol = 0
        self.tcp_syn = False
        self.tcp_ack = False

    def Parse(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol == TCP):
            self.TCP()
        elif (self.protocol == UDP):
            self.UDP()

    def Ethernet(self):
        self.src_mac = ':'.join(b.hex() for b in struct.unpack('!6c', self.data[6:12]))
        self.dst_mac = ':'.join(b.hex() for b in struct.unpack('!6c', self.data[0:6]))

    def IP(self):
        self.src_ip = str(IPv4Address(self.data[26:30]))
        self.dst_ip = str(IPv4Address(self.data[30:34]))

        ip_header = self.data[14:]

        header_length = bin(ip_header[0])[5:10]
        bit_values = [32,16,8,4]
        for bit, value in zip(header_length, bit_values):
            if (int(bit)):
                self.ip_header_length += value

    def Protocol(self):
        self.protocol = self.data[23]

    def UDP(self):
        header_start = self.ip_header_length + 14
        header_end = header_start + 8
        udp_header = struct.unpack('!4H', self.data[header_start:header_end])

        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]

    def TCP(self):
        header_start = self.ip_header_length + 14
        header_end = header_start + 32

        tcp_header = self.data[header_start:header_end]

        tcp_ports = struct.unpack('!2H', tcp_header[:4]) #2LH
        self.src_port = tcp_ports[0]
        self.dst_port = tcp_ports[1]

        numbers = struct.unpack('!2L', tcp_header[4:12])
        self.seq_number = numbers[0]
        self.ack_number = numbers[1]

        if (tcp_header[13] & 1 << 1): # SYN
            self.tcp_syn = True
        if (tcp_header[13] & 1 << 4): # ACK
            self.tcp_ack = True
