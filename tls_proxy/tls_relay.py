#!/usr/bin/python3

import os, sys, time
import struct
import threading
import json
import array
import binascii

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
        
        self.lport = 443
               
    def Start(self):
        self.Main()

    def Main(self):
        try:        
            self.sock = socket(AF_PACKET, SOCK_RAW)
            self.sock.bind((self.lan_ip, 3))

            # listen for UDP datagrams
            print(f'[+] Listening -> {self.lan_ip}:{self.lport}')
            while True:
                data_from_host, _ = self.sock.recvfrom(65565)
                print('RECIEVED DATA FROM HOST')
#                start = time.time()
                try:
                    packet_from_host = PacketManipulation(self.header_info, data_from_host)
                    packet_from_host.Start()
                    Relay = threading.Thread(target=self.RelayThread, args=(packet_from_host))
                    Relay.daemon = True
                    Relay.start()
                except Exception as E:
                    pass                    
        except Exception as E:
            print(E)
            
    def RelayThread(self, packet_from_host):
        sock = socket(AF_PACKET, SOCK_RAW)
        sock.bind((self.wan_ip, 3))
        header_info = [self.lan_mac, packet_from_host.smac, self.lan_ip]
        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
        time.sleep(.01)
        ## -------------- ##
        sock.send(packet_from_host.send_data)
        print(f'Request Relayed to Server on {443}')
        data_from_server, _ = sock.recv(65565)
        print('Request Received from Server')
        packet_from_server = PacketManipulation(header_info, data_from_server, packer_from_host.sport)
        packet_from_server.Start()
        self.sock.send(packet_from_server.send_data)
        print('Request Relayed to Host')
               
#        print('--------------------------')
#        end = time.time()
#        print(end - start)
#        print('--------------------------')

class PacketManipulation:
    def __init__(self, header_info, data, host_port=None):
        self.src_mac, self.dst_mac, self.src_ip = header_info
        self.data = data
        self.host_port = host_port

    def Start(self):
#        self.Ethernet()
        self.IP()
        self.Protocol()
        if (self.protocol in {6}):
            self.Ports()
            if (self.dport in {443}):
                self.TCP()
                self.RebuildHeaders()

            elif (self.sport in {443} and self.dport == self.host_port):
                self.TCP()
                self.RebuildHeaders()

    ''' Parsing ethernet headers || SRC and DST MAC Address'''            
    def Ethernet(self):
        self.smac = self.data[0:6]
        self.eth_proto = self.data[12:14]
    
    ''' Parsing IP headers || SRC and DST IP Address '''
    def IP(self):
        self.ipv4H = self.data[14:34]
        self.checksum = self.data[10:12]
        self.src = self.data[12:16]
        self.dst = self.data[16:20]

    ''' Parsing protocol || TCP 6, UDP 17, etc '''        
    def Protocol(self):
        self.protocol = self.data[23]
        
    ''' Parsing SRC and DST protocol ports '''
    def Ports(self):
        self.sport = self.data[34:36]
        self.dport = self.data[34:38]

    ''' Parsing TCP information like sequence and acknowledgement number amd calculated tcp header
    length to be used by other classes for offset/proper indexing of packet contents.
    Returning all relevant information back to HeaderParse Start method to be redistributed to other classes
    based on need '''
    def TCP(self):
        self.tcp_header_length = 0
        bit_values = [32,16,8,4]

        tcp = self.data[34:94]
        tmp_length = bin(tcp[12])[2:6]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                self.tcp_header_length += bit_values[i]

        self.tcp_header = self.data[34:34+self.tcp_header_length]

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

    def RebuildHeaders(self):
        eth_header = b''
        ipv4_header = b''

        src_mac = binascii.unhexlify(self.src_mac.replace(b':', b''))
        dst_mac = binascii.unhexlify(self.dst_mac.replace(b':', b''))
        eth_header += src_mac
        eth_header += dst_mac

        ipv4_header += self.ipv4H[:10]
        ipv4_header += b'\x00\x00'
        ipv4_header += inet_aton(self.src_ip)
        ipv4_header += self.dst
        if (len(self.ipv4H) > 20):
            ipv4_header += self.ipv4H[20:]

        ipv4_checksum = self.IPV4Checksum(ipv4_header)
        ipv4_checksum = struct.pack('<H', ipv4_checksum)
        ipv4_header.split('b\x00\x00')
        ipv4_header = ipv4_header[0] + ipv4_checksum + ipv4_header[1]

        rebuilt_header = eth_header + ipv4_header + self.tcp_header

        self.send_data = rebuilt_header + self.data[34+self.tcp_header_length:]

if __name__ == "__main__":
    try:        
        TLS = TLSRelay()
        TLS.Start()
    except KeyboardInterrupt:
        exit(3)

