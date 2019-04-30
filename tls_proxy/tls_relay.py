#!/usr/bin/env python3

import os, sys, time
import struct
import threading
import json
import array
import binascii
import traceback

from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, AF_INET, SOCK_STREAM
from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_exceptions import *


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
        dfg_mac = Int.IPtoMAC(dfg)
        wan_mac = Int.MAC(self.waniface)
        self.lan_mac = Int.MAC(self.iniface)
        wan_subnet = Int.WANSubnet(self.waniface, dfg)
        self.header_info = [wan_mac, dfg_mac, self.wan_ip, wan_subnet]     

        self.active_connections = {'Clients': {}}
        self.nat_ports = {}

        self.lan_sock = socket(AF_PACKET, SOCK_RAW)
        self.lan_sock.bind((self.iniface, 3))

        self.wan_sock = socket(AF_PACKET, SOCK_RAW)
        self.wan_sock.bind((self.waniface, 3))

        self.tls_ports = {443}
               
    def Start(self):
        self.Main()

    def Main(self):
        print(f'[+] Listening -> {self.iniface}')
        while True:
            active_connections = self.active_connections['Clients']
            conn_handle = False
            data_from_host, _ = self.lan_sock.recvfrom(65565)
#                start = time.time()
            try:
                packet_from_host = PacketManipulation(self.header_info, data_from_host)
                packet_from_host.Start()

                if (packet_from_host.dport in self.tls_ports):
                    print(f'HTTPS CONNECTION FROM HOST: {packet_from_host.sport}')
                    self.wan_sock.send(packet_from_host.send_data)

                    src_ip = packet_from_host.src
                    src_port = packet_from_host.sport
                    dst_ip = packet_from_host.dst
                    dst_port = packet_from_host.dport

                    if src_ip not in active_connections:
                        active_connections[src_ip] = {src_port: ''}
                        conn_handle = True
                    elif (src_ip in active_connections and src_port not in active_connections[src_ip]):
                        active_connections[src_ip].update({src_port: ''})    
                        conn_handle = True
                    if (conn_handle):
                        nat_port = self.AssignPublicPort()
                        print('Sending Connection to Thread')
                        connection = {'Client': {'IP': src_ip, 'Port': src_port},
                                        'NAT': {'IP': self.wan_ip, 'Port': nat_port},
                                        'Server': {'IP': dst_ip, 'Port': dst_port}}
                        Relay = threading.Thread(target=self.RelayThread, args=(packet_from_host, connection))
                        Relay.daemon = True
                        Relay.start()
            except DNXError as DE:
                print(DE)
            except Exception as E:
                print(f'MAIN PARSE EXCEPTION: {E}')
            
    def RelayThread(self, packet_from_host, connection):
        active_connections = self.active_connections['Clients']
        wan_sock = socket(AF_PACKET, SOCK_RAW)
        wan_sock.bind((self.waniface, 3))
#        print(f'HTTPS Request Relayed to Server')
        ## packing required information into a list for the response to build headers and assigning variables
        ## in the local scope for ip info from packet from host instanced class of PacketManipulation.
        header_info = [self.lan_mac, packet_from_host.smac, packet_from_host.dst, {}]
        nat_port = connection['NAT']['Port']
        host_port = packet_from_host.sport
        src_ip = packet_from_host.src
        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
#        time.sleep(.01)
        ## -------------- ##
        threading.Thread(target=self.Timer).start()
        ''' Sending rebuilt packet to original destination from local client, currently forwarding all packets,
        in the future will attempt to validated from tls proxy whether packet is ok for forwarding. '''
        while True:
            data_from_server, _ = wan_sock.recvfrom(65565)
            try:
                ## Parsing packets to wan interface to look for https response.
                packet_from_server = PacketManipulation(header_info, data_from_server, connection)
                packet_from_server.Start()
                src_ip = packet_from_server.src
                src_port = packet_from_server.sport
                dst_port = packet_from_server.dport
                if src_ip == connection['Server']['IP'] and src_port == connection['Server']['Port']:
                ## Checking desination port to match against original source port. if a match, will relay the packet
                ## information back to the original host/client.
                    if (dst_port == nat_port):
#                        print('HTTPS Response Received from Server')
                        self.lan_sock.send(packet_from_server.send_data)
                        print(f'Response sent to Host: {packet_from_server.dport}')
                        self.time_out = 0
                        break
                ## Time out connection after not recieving anything from remote server for |7 seconds|
                ## This number should be tuned further as it may unnecessarily long.
                if (self.time_out >= 7):
                    src_ip = connection['Client']['IP']
                    active_connections[src_ip].pop(host_port, None)
                    self.nat_ports.pop(nat_port, None)
                    break
            except DNXError:
                pass
            except Exception as E:
                print(f'RELAY PARSE EXCEPTION: {E}')
                traceback.print_exc()

    def AssignPublicPort(self):
        while True:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind(('', 0))
            nat_port = sock.getsockname()[1]
            if (nat_port not in self.nat_ports):
                self.nat_ports[nat_port] = ''
                
                return nat_port

    def Timer(self):
        self.time_out = 0
        while True:
            time.sleep(1)
            self.time_out += 1

class PacketManipulation:
    def __init__(self, header_info, data, connection=None):
        self.Checksum = Checksums()
        self.src_mac, self.dst_mac, self.src_ip, self.wan_subnet = header_info
        self.data = data
        self.connection = connection

        self.tcp_header_length = 0 
        self.dst_ip = None      
        self.dport = None
        self.sport = None
        self.nat_port = None
        self.payload = b''

        if (connection):
            self.dst_ip = connection['Client']['IP']
            self.dst_port = connection['Client']['Port']
            self.nat_port = connection['NAT']['Port']

    def Start(self):
        self.Ethernet()
        self.IP()
        self.CheckDestination()
        self.Protocol()
        if (self.protocol in {6}):
            self.Ports()           
            if (self.dport in {443}):
                self.TCP()
                self.PsuedoHeader()
                self.RebuildHeaders()
            elif (self.sport in {443} and self.dport == self.nat_port):
                self.TCP()
                self.PsuedoHeader()
                self.RebuildHeaders()
            else:
                raise TCPProtocolError('Packet is not related to HTTPS or to the specific session.')
        else:
            raise IPProtocolError('Packet protocol is not 6/TCP')

    def CheckDestination(self):
        if (self.dst_ip in self.wan_subnet):
            Int = Interface()
            dst_mac = Int.IPtoMAC(self.dst_ip)
            if (not dst_mac):
                run(f'ping {self.dst_ip} -c 1', shell=True)
                self.dst_mac = Int.IPtoMAC(self.dst_ip)
            else:
                self.dst_mac = dst_mac

    ''' Parsing ethernet headers || SRC and DST MAC Address'''            
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

    ''' Parsing protocol || TCP 6, UDP 17, etc '''        
    def Protocol(self):
        self.protocol = self.data[23]
        
    ''' Parsing SRC and DST protocol ports '''
    def Ports(self):
        ports = struct.unpack('!2H', self.data[34:38])
        self.sport = ports[0]
        self.dport = ports[1]

        self.src_port = self.data[34:36]
        if (self.connection):
            self.dst_port = struct.pack('!H', self.connection['Client']['Port'])
        else:
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
        self.tcp_segment_length = len(self.data) - 34
        if (len(self.data) > 34+self.tcp_header_length):
            self.payload = self.data[34+self.tcp_header_length:]

    def PsuedoHeader(self):
        psuedo_header = b''
        psuedo_header += inet_aton(self.src_ip)
        if (self.dst_ip):
            psuedo_header += inet_aton(self.dst_ip)
        else:
            psuedo_header += inet_aton(self.dst)            
        psuedo_header += struct.pack('!2BH', 0, 6, self.tcp_segment_length)
        psuedo_packet = psuedo_header + self.data[34:34+16] + b'\x00\x00' + self.data[34+18:]
        
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
        eth_header += self.eth_proto

        return eth_header

    def RebuildIP(self):
        ipv4_header = b''
        ipv4_header += self.ipv4H[:10]
        ipv4_header += b'\x00\x00'
        ipv4_header += inet_aton(self.src_ip)

        if (self.dst_ip):
            ipv4_header += inet_aton(self.dst_ip)
        else:            
            ipv4_header += inet_aton(self.dst)         

        if (len(self.ipv4H) > 20):
            ipv4_header += self.ipv4H[20:]

        ipv4_checksum = self.Checksum.IPV4(ipv4_header)
        ipv4_checksum = struct.pack('<H', ipv4_checksum)
        ipv4_header = ipv4_header[:10] + ipv4_checksum + ipv4_header[12:]

        return ipv4_header

    def RebuildTCP(self):
        if (self.connection):
            tcp_header = self.tcp_header[:2] + self.dst_port + self.tcp_header[4:16 ]+ self.tcp_checksum + b'\x00\x00'
        else:
            tcp_header = self.tcp_header[:16] + self.tcp_checksum + b'\x00\x00'
        if (self.tcp_header_length > 20):
            tcp_header += self.tcp_header[20:self.tcp_header_length]          

        return tcp_header

class Checksums:
    def IPV4(self, header):
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

    def TCP(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if ((i+1) < len(msg)):
                a = msg[i]
                b = msg[i+1]
                s = s + (a+(b << 8))            
            elif ((i+1) == len(msg)):
                s += msg[i]

        s = s + (s >> 16)
        s = ~s & 0xffff

        return s

if __name__ == "__main__":
    try:        
        TLS = TLSRelay()
        TLS.Start()
    except KeyboardInterrupt:
        exit()

