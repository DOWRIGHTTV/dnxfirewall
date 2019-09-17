#!/usr/bin/python3

import os, sys
import struct
import binascii
import codecs
import traceback
import time
import threading

from ipaddress import IPv4Address
from socket import socket, error, AF_PACKET, SOCK_RAW

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_ips.dnx_ips_packets import PacketParse


class IPSSniffer:
    def __init__(self, IPS):
        self.IPS = IPS
        self.wan_int = IPS.wan_int
        self.wan_ip = IPS.wan_ip
        self.broadcast = IPS.broadcast

    def Start(self, from_proxy=False):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.wan_int, 3))
        print(f'[+] Sniffing: {self.wan_int}')
        while True:
            # will only inspec traffic is open ports/ nats are configured and the ddos or portscan
            # is enabled or log level is informational
            if ((self.IPS.logging_level == INFORMATIONAL or self.IPS.portscan_prevention
                    or self.IPS.ddos_prevention) and (self.IPS.open_tcp_ports or self.IPS.open_udp_ports)):
                try:
                    data = self.sock.recv(4096)

                    self.PacketHandler(data)
                except error:
                    break

            elif (from_proxy):
                from_proxy = False
                time.sleep(5)
            else:
                time.sleep(SETTINGS_TIMER)

        self.Start()

    def PacketHandler(self, data):
        send_to_proxy = False
        try:
            packet = PacketParse(data)
            packet.Parse()
        except Exception:
            traceback.print_exc()

        connection_type = None
        if (packet.protocol == TCP):
            if (packet.dst_ip == self.wan_ip and packet.tcp_syn and not packet.tcp_ack):
                connection_type = INITIAL
                send_to_proxy = True
            elif (packet.dst_ip == self.wan_ip and packet.tcp_ack and not packet.tcp_syn):
                connection_type = RESPONSE
                send_to_proxy = True
            elif (packet.src_ip == self.wan_ip and packet.tcp_syn and packet.tcp_ack):
                connection_type = RESPONSE
                send_to_proxy = True
        elif (packet.protocol == UDP):
            if (packet.dst_ip == self.wan_ip):
                connection_type = INITIAL
                send_to_proxy = True
            elif (packet.src_ip == self.wan_ip):
                connection_type = RESPONSE
                send_to_proxy = True

        elif (packet.protocol == ICMP):
            if (packet.dst_ip == self.wan_ip):
                connection_type = None
                send_to_proxy = True

        if (send_to_proxy and packet.dst_ip != self.broadcast):
            threading.Thread(target=self.IPS.SignatureCheck, args=(packet, connection_type)).start()
