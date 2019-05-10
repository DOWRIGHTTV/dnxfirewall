#!/usr/bin/env python3

import os, sys, time
import threading
import traceback

from socket import socket, inet_aton, AF_PACKET, SOCK_RAW, AF_INET

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_exceptions import *
from tls_proxy.tls_proxy_sniffer import SSLHandlerThread, SSL, SSLType
from tls_proxy.tls_proxy_packets import PacketHeaders, PacketManipulation

class ConnectionHandler:
    def __init__(self, tls_relay):
        self.tls_relay = tls_relay
        self.wan_int = tls_relay.wan_int
        self.sock = tls_relay.sock
        self.lan_sock = tls_relay.lan_sock
        self.connection = tls_relay.connection
        self.action = tls_relay.action
        self.tcp_info = tls_relay.tcp_info

        self.client_mac = self.connection['Client']['MAC']
        self.client_ip = self.connection['Client']['IP']
        self.client_port = self.connection['Client']['Port']
        self.nat_port = self.connection['NAT']['Port']
        self.server_ip = self.connection['Server']['IP']
        self.server_port = self.connection['Server']['Port']

        self.lan_info = [self.client_mac, {}]

    def Start(self, timeout, protocol='TCP'):
        self.wan_sock = socket(AF_PACKET, SOCK_RAW)
        self.wan_sock.bind((self.wan_int, 3))

        threading.Thread(target=self.Timer).start()
        while True:
            self.data_from_server = self.wan_sock.recv(65565)
            print('RECEIVED DATA FROM SERVER')
            try:
                self.server_packet_headers = PacketHeaders(self.data_from_server, self.nat_port)
                self.server_packet_headers.Parse()
                self.src_ip = self.server_packet_headers.src
                self.src_port = self.server_packet_headers.sport
                self.dst_port = self.server_packet_headers.dport

                if (protocol == 'TCP'):
                    self.TCP()
                elif (protocol == 'SSL'):
                    self.SSL()

                timeout = self.Timeout()
                if (timeout):
                    break

            except DNXError:
                pass
            except Exception as E:
                print(f'RELAY PARSE EXCEPTION: {E}')
                traceback.print_exc()

    def TCP(self):
        if (len(self.server_packet_headers.payload) == 0 and self.src_ip == self.server_ip and self.src_port == self.server_port):
            if (self.dst_port == self.nat_port):
                packet_from_server = PacketManipulation(self.server_packet_headers, self.lan_info, self.data_from_server, self.connection, from_server=True)
                packet_from_server.Start()
                if (self.src_ip not in self.tls_relay.active_connections):
                    self.lan_sock.send(packet_from_server.send_data)
                    
                elif (self.src_ip in self.tls_relay.active_connections and self.src_port not in self.tls_relay.active_connections[self.src_ip]):
                    self.lan_sock.send(packet_from_server.send_data)
            
    def SSL(self):
        SSLHandler = SSLHandlerThread(self.connection, self.tcp_info, self.action)
        ''' Sending rebuilt packet to original destination from local client, currently forwarding all packets,
        in the future will attempt to validated from tls proxy whether packet is ok for forwarding. '''
        if self.src_ip == self.server_ip and self.src_port == self.server_port:
        ## Checking desination port to match against original source port. if a match, will relay the packet
        ## information back to the original host/client.
            if (self.dst_port == self.nat_port):
                self.time_out = 0
                ## Parsing packets to wan interface to look for https response.
                forward = self.CheckSSLType(SSLHandler, self.data_from_server)
                if (forward):
                    packet_from_server = PacketManipulation(self.server_packet_headers, self.lan_info, self.data_from_server, self.connection, from_server=True)
                    packet_from_server.Start()
#                        print('HTTPS Response Received from Server')
                    self.lan_sock.send(packet_from_server.send_data)
#                            print(f'Response sent to Host: {connection["Client"]["Port"]}')

    def CheckSSLType(self, SSLHandler, data_from_server):
        if (len(data_from_server) >= 75):
            forward = SSLHandler.Start(data_from_server)

            return forward

    def Timer(self):
        self.time_out = 0
        while True:
            time.sleep(1)
            self.time_out += 1

    def Timeout(self, protocol='TCP'):
        timeout = False
        if (protocol == 'TCP'):
            if (self.time_out > 2):
                timeout = True
        elif (protocol == 'SSL'):
            if (self.time_out > 120):
                self.tls_relay.active_connections[self.client_ip].pop(self.client_port, None)
                self.tls_relay.connections[self.client_ip].pop(self.client_port, None)
                self.tls_relay.tcp_handshakes[self.client_ip].pop(self.src_port, None)
                self.sock.close()
                self.wan_sock.close()

                timeout = True
        
        return timeout

