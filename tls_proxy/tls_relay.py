#!/usr/bin/python3

import os, sys, time
import struct
import threading
import json

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from socket import socket, AF_INET, SOCK_STREAM
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
        self.laddr = Int.IP(self.iniface)
        self.qaddr = Int.IP(self.waniface)
        self.lport = 443
               
    def Start(self):
        self.Main()

    def Main(self):
        try:        
            self.sock = socket(AF_INET, SOCK_STREAM)
            self.sock.bind((self.laddr, self.lport))
            self.sock.listen(1)
            # listen for UDP datagrams
            print(f'[+] Listening -> {self.laddr}:{self.lport}')
            while True:
                data_to_server, addr = self.sock.accept()
                print('RECIEVED DATA FROM HOST')
                print(addr)
#                start = time.time()
                try:
#                    dst_ip = self.ParseHeader(self.data)
                    self.RelayThread(data_to_server)
                except Exception as E:
                    pass                    
        except Exception as E:
            print(E)
            
    def RelayThread(self, data_to_server):
        sock = socket(AF_INET, SOCK_STREAM)
        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
        time.sleep(.075)
        ## -------------- ##
        sock.send(data_to_server)
        sock.listen(1)
        print(f'Request Relayed to Server on {443}')
        data_from_server, _ = sock.accept()
        print('Request Received from Server')
        self.sock.send(data_from_server)
        print('Request Relayed to Host')
               
#        print('--------------------------')
#        end = time.time()
#        print(end - start)
#        print('--------------------------')
    ''' Parsing IP headers || SRC and DST IP Address '''
    def ParseHeader(self, data):
        s = struct.unpack('!4B', data[26:30])
        d = struct.unpack('!4B', data[30:34])
        self.src = '{}.{}.{}.{}'.format(s[0], s[1], s[2], s[3])
        self.dst = '{}.{}.{}.{}'.format(d[0], d[1], d[2], d[3])


if __name__ == "__main__":
    try:        
        TLS = TLSRelay()
        TLS.Start()
    except KeyboardInterrupt:
        exit(3)

