#!/usr/bin/env python3

import os, sys, time
import struct
import threading
import json
import array
import binascii
import traceback

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, AF_INET, SOCK_STREAM
from dnx_configure.dnx_system_info import Interface


class TLSRelay:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        
        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)

        self.iniface = self.setting['Settings']['Interface']['Inside']
        self.waniface = self.setting['Settings']['Interface']['Outside']
        self.dnsserver = self.setting['Settings']['DNSServers']

        Int = Interface()
        self.lan_ip = Int.IP(self.iniface)
        self.wan_ip = Int.IP(self.waniface)
        dfg = Int.DefaultGateway()
        dfg_mac = Int.DFGMAC(dfg)
        wan_mac = Int.MAC(self.waniface)
        self.lan_mac = Int.MAC(self.iniface)
        self.header_info = [wan_mac, dfg_mac, self.wan_ip]

        try:        
            self.lan_sock = socket(AF_PACKET, SOCK_RAW)
            self.lan_sock.bind((self.iniface, 3))

            self.wan_sock = socket(AF_PACKET, SOCK_RAW)
            self.wan_sock.bind((self.waniface, 0))
        except Exception as E:
            print(f'MAIN SOCKET EXCEPTION: {E}')
               
    def Start(self):
        self.Main()

    def Main(self):
        print(f'[+] Listening -> {self.iniface}')
        while True:
            data_from_host, _ = self.lan_sock.recvfrom(65565)
#                start = time.time()
            try:
                packet_from_host = PacketManipulation(self.header_info, data_from_host)
                packet_from_host.Start()
                if (packet_from_host.dport in {443}):
                    print('RECIEVED HTTPS CONNECTION FROM HOST')
                    Relay = threading.Thread(target=self.RelayThread, args=(packet_from_host,))
                    Relay.daemon = True
                    Relay.start()
            except Exception as E:
                print(f'MAIN PARSE EXCEPTION: {E}')
            
    def RelayThread(self, packet_from_host):
        self.wan_sock.send(packet_from_host.send_data)
        print(f'HTTPS Request Relayed to Server')

        ## packing required information into a list for the response to build headers and assigning variables
        ## in the local scope for ip info from packet from host instanced class of PacketManipulation. 
        header_info = [self.lan_mac, packet_from_host.smac, self.lan_ip]
        host_ip = packet_from_host.src
        host_port = packet_from_host.sport

        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
#        time.sleep(.01)
        ## -------------- ##

        ''' Sending rebuilt packet to original destination from local client, currently forwarding all packets,
        in the future will attempt to validated from tls proxy whether packet is ok for forwarding. '''
        while True:
            data_from_server, _ = self.wan_sock.recvfrom(65565)
            try:
                ## Parsing packets to wan interface to look for https response.
                packet_from_server = PacketManipulation(header_info, data_from_server, host_ip, host_port)
                packet_from_server.Start()
                if packet_from_server.protocol in {6}:
                    print('RESPONSE FROM SOMETHING')
                ## Checking desination port to match against original source port. if a match, will relay the packet
                ## information back to the original host/client.
                if (packet_from_server.dport == packet_from_host.sport):
                    print('HTTPS Response Received from Server')
                    print(packet_from_server.send_data)
                    self.lan_sock.send(packet_from_server.send_data)
                    print('Request Relayed to Host')
                    break
            except Exception as E:
                print(f'RELAY PARSE EXCEPTION: {E}')
                traceback.print_exc()

class PacketManipulation:
    def __init__(self, header_info, data, dst_ip=None, host_port=None):
        self.src_mac, self.dst_mac, self.src_ip = header_info
        self.data = data
        self.dst_ip = dst_ip
        self.host_port = host_port
        
        self.tcp_header_length = 0
        
        self.dport = None
        self.sport = None

    def Start(self):
        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol in {6}):
            self.Ports()
            if (self.dport in {443}):
                self.TCP()
                self.RebuildHeaders()

            elif (self.sport in {443} and self.dst_port == self.host_port):
                self.TCP()
                self.PsuedoHeader()
                self.RebuildHeaders()

    ''' Parsing ethernet headers || SRC and DST MAC Address'''            
    def Ethernet(self):
        self.eth_proto = self.data[12:14]
        
        s = []
        smac = self.data[0:6]
        smac = struct.unpack('!6c', smac)
        for byte in smac:
            s.append(byte.hex())
            
        self.smac = f'{s[0]}:{s[1]}:{s[2]}:{s[3]}:{s[4]}:{s[5]}'       
    
    ''' Parsing IP headers || SRC and DST IP Address '''
    def IP(self):
        self.ipv4H = self.data[14:34]
        self.checksum = self.ipv4H[10:12]
        self.src = self.ipv4H[12:16]
        self.dst = self.ipv4H[16:20]
        
        s = struct.unpack('!4B', self.src)        
        d = struct.unpack('!4B', self.dst)
        
        self.src = f'{s[0]}.{s[1]}.{s[2]}.{s[3]}'
        self.dst = f'{d[0]}.{d[1]}.{d[2]}.{d[3]}'
        
#        print(f'ORIGINAL SOURCE: {self.src}')
#        print(f'ORIGINAL DESTINATION: {self.dst}')

    ''' Parsing protocol || TCP 6, UDP 17, etc '''        
    def Protocol(self):
        self.protocol = self.data[23]
        
    ''' Parsing SRC and DST protocol ports '''
    def Ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]

        self.src_port = self.data[34:36]
        self.dst_port = self.data[36:38]

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
        self.payload = self.data[34+self.tcp_header_length:]

    def IPV4Checksum(self, header):
        if len(header) & 1:
            header = header + '\0'
        words = array.array('h', header)
        sum = 0
        for word in words:
            sum = sum + (word & 0xffff)
        hi = sum >> 16
        lo = sum & 0xffff
        sum = hi + lo
        sum = sum + (sum >> 16)

        return (~sum) & 0xffff

    def TCPChecksum(self, msg):
        s = 0       # Binary Sum
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if (i+1) < len(msg):
                a = ord(msg[i]) 
                b = ord(msg[i+1])
                s = s + (a+(b << 8))
            elif (i+1)==len(msg):
                s += ord(msg[i])

        s = s + (s >> 16)
        s = ~s & 0xffff

        return s

    def PsuedoHeader(self):
        psuedo_header = b''
        psuedo_header += struct.unpack('!4B', self.src_ip)
        psuedo_header += self.dst
        psuedo_header += struct.unpack('!2BH', 1, 1, self.tcp_header_length)
        psuedo_packet = psuedo_header + self.data[34+self.tcp_header_length:]
        
        tcp_checksum = self.TCPChecksum(psuedo_packet)
        self.tcp_checksum = struct.pack('!L', tcp_checksum)

    def RebuildHeaders(self):
        ethernet_header = self.RebuildEthernet()
        ip_header = self.RebuildIP()
        tcp_header = self.RebuildTCP

        self.send_data = ethernet_header + ip_header + tcp_header + self.payload

    def RebuildEthernet(self):
        eth_header = struct.pack('!6s6s',
        binascii.unhexlify(self.src_mac.replace(':', '')),
        binascii.unhexlify(self.dst_mac.replace(':', '')))
        eth_header += self.eth_proto

        return eth_header

    def RebuildIP(self):
        ipv4_header = b''
        ipv4_header += self.ipv4H[:10]
        ipv4_header += b'\x00\x00'
        ipv4_header += inet_aton(self.src_ip)

        if (not self.dst_ip):
            ipv4_header += inet_aton(self.dst)
        else:
            ipv4_header = inet_aton(self.dst_ip)

        if (len(self.ipv4H) > 20):
            ipv4_header += self.ipv4H[20:]

        ipv4_checksum = self.IPV4Checksum(ipv4_header)
        ipv4_checksum = struct.pack('<H', ipv4_checksum)
        ipv4_header = ipv4_header[:10] + ipv4_checksum + ipv4_header[12:]

        return ipv4_header

    def RebuildTCP(self):
        tcp_header = self.tcp_header[:16] + self.tcp_checksum
        if (self.tcp_header_length > 20):
            self.tcp_header += self.tcp_header[20:self.tcp_header_length]

        return tcp_header

if __name__ == "__main__":
    try:        
        TLS = TLSRelay()
        TLS.Start()
    except KeyboardInterrupt:
        exit(3)

