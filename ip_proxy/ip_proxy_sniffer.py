#!/usr/bin/python3

import os, sys
import time
import struct
import binascii
import codecs
import threading
import traceback

from ipaddress import IPv4Address
from socket import socket, error, AF_PACKET, SOCK_RAW

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from ip_proxy.ip_proxy_packets import PacketParse


class IPSniffer:
    def __init__(self, IPProxy):
        self.IPProxy = IPProxy
        self.lan_int = IPProxy.lan_int

    def Start(self, from_proxy=False):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.lan_int, 3))
        print(f'[+] Sniffing: {self.lan_int}')
        while True:
            if (self.IPProxy.logging_level == INFORMATIONAL or self.IPProxy.tor_entry_block
                    or self.IPProxy.tor_exit_block or self.IPProxy.malware_block or self.IPProxy.compromised_block):
                try:
                    data = self.sock.recv(4096)

                    self.PacketHandler(data)
                except error:
                    break

            elif (from_proxy):
                from_proxy = False
                time.sleep(SHORT_POLL)
            else:
                print('ip proxy on standby')
                time.sleep(SETTINGS_TIMER)

        self.Start()

    def PacketHandler(self, data):
        try:
            packet = PacketParse(data)

            packet.Parse()
        except Exception:
            traceback.print_exc()

        if (packet.protocol in {TCP, UDP}):
            threading.Thread(target=self.IPProxy.SignatureCheck, args=(packet,)).start()
