#!/usr/bin/python3

import os, sys
import time
import traceback
import threading

from ipaddress import IPv4Address
from socket import socket, error, AF_PACKET, SOCK_RAW

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dns_proxy.dns_proxy_packets import PacketParse
from dns_proxy.dns_proxy_response import DNSResponse


class DNSSniffer:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy
        self.lan_int = DNSProxy.lan_int

    def Start(self, from_proxy=False):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.lan_int, 3))
        print(f'[+] Sniffing: {self.lan_int}')
        while True:
            if (from_proxy):
                time.sleep(5)
                from_proxy = False

            try:
                data = self.sock.recv(4096)

                self.PacketHandler(data)
            except error:
                break

        self.Start()

    def PacketHandler(self, data):
        try:
            packet = PacketParse(data)
            packet.Parse()

        except Exception:
            traceback.print_exc()

        if (packet.qtype == A_RECORD):
#            print(f'SOURCE: {packet.src_ip}:{packet.src_port} DEST: {packet.dst_ip}:{packet.dst_port} | {packet.request}')
            threading.Thread(target=self.DNSProxy.SignatureCheck, args=(packet,)).start()

        # sending a response/ refuse message for ipv6 queries (firewall will have ipv6 disabled anyways)
        elif (packet.qtype == AAAA_RECORD):
            Proxy = DNSResponse(packet, self.lan_int, response_ip=None, query_type=packet.qtype)
            threading.Thread(target=Proxy.Response).start()
