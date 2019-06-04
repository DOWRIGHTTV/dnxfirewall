#!/usr/bin/env python3

import struct
import binascii

from socket import inet_aton
from subprocess import run

from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_packet_checks import Checksums
from dnx_configure.dnx_exceptions import *

class PacketHeaders:
    def __init__(self, data, nat_port=None):
        self.data = data
        self.nat_port = nat_port

        self.tcp_header_length = 0
        self.dport = None
        self.sport = None

        self.payload = b''

    def Parse(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol in {6}):
            self.TCP()
            self.Ports()
            if (self.dport in {443}):
                return
            elif (self.sport in {443} and self.dport == self.nat_port):
                return
            else:
                raise TCPProtocolError('TCP Protocol is not related to HTTPS or to the specific session.')
        else:
            raise IPProtocolError('Packet protocol is not 6/TCP')

    def Ethernet(self):
        self.eth_proto = self.data[12:14]
        
        s = []
        smac = self.data[6:12]
        smac = struct.unpack('!6c', smac)
        for byte in smac:
            s.append(byte.hex())
            
        self.smac = f'{s[0]}:{s[1]}:{s[2]}:{s[3]}:{s[4]}:{s[5]}'
    
    ''' Parsing IP headers || SRC and DST IP Address '''
    def IP(self):
        self.ipv4H = self.data[14:34]
        self.checksum = self.ipv4H[10:12]

        src = self.ipv4H[12:16]
        dst = self.ipv4H[16:20]
        s = struct.unpack('!4B', src)
        d = struct.unpack('!4B', dst)        
        self.src = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'
        
#        print(f'ORIGINAL SOURCE: {self.src}')
#        print(f'ORIGINAL DESTINATION: {self.dst}')

    def TCP(self):
        bit_values = [32,16,8,4]

        tcp = self.data[34:94]
        tmp_length = bin(tcp[12])[2:6]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                self.tcp_header_length += bit_values[i]

        self.tcp_header = self.data[34:34+self.tcp_header_length]
        self.tcp_length = len(self.data) - 34
        if (len(self.data) > 34+self.tcp_header_length):
            self.payload = self.data[34+self.tcp_header_length:]

    ''' Parsing protocol || TCP 6, UDP 17, etc '''        
    def Protocol(self):
        self.protocol = self.data[23]
        
    ''' Parsing SRC and DST protocol ports '''
    def Ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]

        self.src_port = self.data[34:36]

class PacketManipulation:
    def __init__(self, packet_headers, net_info, data, connection, from_server):
        self.Checksum = Checksums()
        self.packet_headers = packet_headers
        self.dst_mac, self.wan_subnet = net_info
        self.data = data
        self.connection = connection
        self.from_server = from_server

        self.tcp_header_length = 0 
        self.dst_ip = None
        self.nat_port = None
        self.payload = b''

        if (from_server):
            self.src_mac = connection['LAN']['MAC']
            self.src_ip = connection['Server']['IP']
            self.dst_ip = connection['Client']['IP']
            self.client_port = connection['Client']['Port']
            self.client_port = struct.pack('!H', connection['Client']['Port'])            
        else:
            self.src_mac = connection['NAT']['MAC']
            self.src_ip = connection['NAT']['IP']
            self.nat_port = connection['NAT']['Port']
            self.nat_port = struct.pack('!H', self.nat_port)
            self.dst_ip = self.packet_headers.dst
            self.dst_port = self.data[36:38]

    def Start(self):
        self.CheckDestination()
        self.TCP()
        self.PsuedoHeader()
        self.RebuildHeaders()

    def CheckDestination(self):
        if (self.dst_ip in self.wan_subnet):
            Int = Interface()
            dst_mac = Int.IPtoMAC(self.dst_ip)
            if (not dst_mac):
                run(f'ping {self.dst_ip} -c 1', shell=True)
                self.dst_mac = Int.IPtoMAC(self.dst_ip)
            else:
                self.dst_mac = dst_mac

    ''' Parsing TCP information like sequence and acknowledgement number amd calculated tcp header
    length to be used by other classes for offset/proper indexing of packet contents.
    Returning all relevant information back to HeaderParse Start method to be redistributed to other classes
    based on need '''
    def TCP(self):
        bit_values = [32,16,8,4]

        tcp = self.data[34:94]
        tmp_length = bin(tcp[12])[2:6]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                self.tcp_header_length += bit_values[i]

        self.tcp_header = self.data[34:34+self.tcp_header_length]
        self.tcp_length = len(self.data) - 34
        if (len(self.data) > 34+self.tcp_header_length):
            self.payload = self.data[34+self.tcp_header_length:]

    def PsuedoHeader(self):
        psuedo_header = b''
        psuedo_header += inet_aton(self.src_ip)
        psuedo_header += inet_aton(self.dst_ip)
        psuedo_header += struct.pack('!2BH', 0, 6, self.tcp_length)
        if (self.from_server):            
            psuedo_header += self.tcp_header[0:2] + self.client_port + self.tcp_header[4:16] + b'\x00\x00' + self.tcp_header[18:]     
        else:
            psuedo_header += self.nat_port + self.tcp_header[2:16] + b'\x00\x00' + self.tcp_header[18:]
        psuedo_packet = psuedo_header + self.payload
        
        tcp_checksum = self.Checksum.TCP(psuedo_packet)
        self.tcp_checksum = struct.pack('<H', tcp_checksum)

    def RebuildHeaders(self):
        ethernet_header = self.RebuildEthernet()
        ip_header = self.RebuildIP()
        tcp_header = self.RebuildTCP()

        self.send_data = ethernet_header + ip_header + tcp_header + self.payload

    def RebuildEthernet(self):
        eth_header = struct.pack('!6s6s',
        binascii.unhexlify(self.dst_mac.replace(':', '')),
        binascii.unhexlify(self.src_mac.replace(':', '')))
        eth_header += self.packet_headers.eth_proto

        return eth_header

    def RebuildIP(self):
        ipv4_header = b''
        ipv4_header += self.packet_headers.ipv4H[:10]
        ipv4_header += b'\x00\x00'
        ipv4_header += inet_aton(self.src_ip)           
        ipv4_header += inet_aton(self.dst_ip) 

        if (len(self.packet_headers.ipv4H) > 20):
            ipv4_header += self.packet_headers.ipv4H[20:]

        ipv4_checksum = self.Checksum.IPv4(ipv4_header)
        ipv4_checksum = struct.pack('<H', ipv4_checksum)
        ipv4_header = ipv4_header[:10] + ipv4_checksum + ipv4_header[12:]

        return ipv4_header

    def RebuildTCP(self):
        if (self.from_server):
            tcp_header = self.tcp_header[:2] + self.client_port + self.tcp_header[4:16] + self.tcp_checksum + b'\x00\x00'
        else:            
            tcp_header = self.nat_port + self.tcp_header[2:16] + self.tcp_checksum + b'\x00\x00'

        if (self.tcp_header_length > 20):
            tcp_header += self.tcp_header[20:self.tcp_header_length]

        return tcp_header
