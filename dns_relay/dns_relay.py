#!/usr/bin/python3

import os, sys, subprocess
import struct
import traceback
import time
import threading
import json

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from socket import socket, AF_INET, SOCK_DGRAM
from dnx_configure.dnx_system_info import Interface


class DNSRelay:
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
        self.dns1 = [self.dnsserver['Server1']['IP Address'], True]
        self.dns2 = [self.dnsserver['Server2']['IP Address'], True]
        self.dnsList = [self.dns1, self.dns2]
        self.lport = 53
               
    def Start(self):
        Reach = threading.Thread(target=self.Reachability)
        Reach.daemon = True
        threading.Thread(target=self.Main).start()
        Reach.start()     
    
    def Reachability(self):
        DEVNULL = open(os.devnull, 'wb')
        while True:
            for i, server in enumerate(self.dnsList, 1):
                reach = subprocess.call(['sudo', 'ping', '-c', '1', server[0]], stdout = DEVNULL)
                dnsserver = self.dnsserver['Server{}'.format(i)]
                if (reach == 0):
                    server[1] = True
                    status = 'UP'
#                    print('{}:{}'.format(server[0], server[1]))
                else:
                    server[1] = False
                    status = 'Down'
#                    print('{}:{}'.format(server[0], server[1]))

                self.dnsserver.update({'Server{}'.format(i): {
                                            "Name": dnsserver['Name'],
                                            "IP Address": dnsserver['IP Address'],
                                            "Status": status}})

            with open('{}/data/dnsstatus.json'.format(self.path), 'w') as dnsstat:
                json.dump(self.dnsserver, dnsstat, indent=4)
        
            time.sleep(10)

    def Main(self):
        try:        
            self.sock = socket(AF_INET, SOCK_DGRAM)
            self.sock.bind((self.laddr, self.lport))
            # listen for UDP datagrams
            print('[+] Listening -> {}:{}'.format(self.laddr, self.lport))
            while True:
                self.data, self.addr = self.sock.recvfrom(1024)
#                start = time.time()
                try:
                    self.parse_init_query(self.data)
                    
                    if (self.qtype == b'\x01'):
                        Relay = threading.Thread(target=self.RelayThread)
                        Relay.daemon = True
                        Relay.start()
                    else:
                        pass
                except Exception as E:
                    pass                    
        except Exception as E:
            pass
            
    def RelayThread(self):
        sock = socket(AF_INET, SOCK_DGRAM)
        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
        time.sleep(.075)
        ## -------------- ##
        for server in self.dnsList:
            if (server[1] == True):
                sock.sendto(self.data, (server[0], 53))
                print('Request Relayed to {}: {}'.format(server, 53))
                data, _ = sock.recvfrom(1024)
                data = self.parse_and_rewrite_query_response(data)
                print('Request Received')
                break
            else:
                pass
        self.sock.sendto(data, self.addr)
               
#        print('--------------------------')
#        end = time.time()
#        print(end - start)
#        print('--------------------------')       

    def parse_init_query(self, data):
#        header = data[:12]
        self.payload = data[12:]
#        tmp = struct.unpack(">6H", header)
        j = self.payload.index(0) + 1 + 4
        self.qtype = self.payload[j-3:j-2]
    
    def parse_and_rewrite_query_response(self, data):
        
        qname = data[12:].split(b'\x00',1)[0]
#        qname = qname[0]
        b = 1
        for byte in qname[0:]:
            b += 1
            
        eoqname = 12+b
        eoquery = eoqname + 4        
        rrecord = data[eoquery:]
        
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x01+'
        
        if (rrecord[0:2] == pointer):                
            splitdata = data.split(pointer)
            rrname = pointer
        else:
            splitdata = data.split(qname)
            rrname = qname
            
        rr = b''
        for i, rrpart in enumerate(splitdata, 1):
            if i == 1:
                pass
            else:
                ttl_bytes = rrpart[4:8]
                ttl_check = struct.unpack(">L", ttl_bytes)[0]
                if (ttl_check > 299):
                    rr += rrname + rrpart[:4] + ttl_bytes_override + rrpart[8:]
                else:
                    rr += rrname + rrpart

        data = splitdata[0] + rr                    
                
        return data

if __name__ == "__main__":
    try:        
        DNS = DNSRelay()
        DNS.Start()
    except KeyboardInterrupt:
        exit(3)

