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
        
        with open(f'{self.path}/data/config.json', 'r') as settings:
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
                dnsserver = self.dnsserver[f'Server{i}']
                if (reach == 0):
                    server[1] = True
                    status = 'UP'
                else:
                    server[1] = False
                    status = 'Down'
#               print(f'{server[0]}:{server[1]}')
                self.dnsserver.update({f'Server{i}': {
                                            'Name': dnsserver['Name'],
                                            'IP Address': dnsserver['IP Address'],
                                            'Status': status}})

            with open(f'{self.path}/data/dnsstatus.json', 'w') as dnsstat:
                json.dump(self.dnsserver, dnsstat, indent=4)
        
            time.sleep(10)

    def Main(self):
        try:        
            self.sock = socket(AF_INET, SOCK_DGRAM)
            self.sock.bind((self.laddr, self.lport))
        except Exception as E:
            print(f'Main Socket Error: {E}')

        print(f'[+] Listening -> {self.laddr}:{self.lport}')
        while True:
            data_from_client, self.addr = self.sock.recvfrom(1024)
            try:
                packet = PacketManipulation(data_from_client)
                packet.Parse()  
                ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                ## to handle the rest of the process and sending client data in for relay to dns server        
                if (packet.qtype == b'\x01'):
                    Relay = threading.Thread(target=self.RelayThread, args=(data_from_client,))
                    Relay.daemon = True
                    Relay.start()
            except Exception as E:
                pass                    
            
    def RelayThread(self, data_from_client):
        sock = socket(AF_INET, SOCK_DGRAM)
        ## -- 75 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
        time.sleep(.075)
        ## -------------- ##
        ## Iterating over DNS Server List and Sending to first server that is available.
        for server in self.dnsList:
            if (server[1] == True):
                sock.sendto(data_from_client, (server[0], 53))
                print(f'Request Relayed to {server}: 53')

                ## Waiting for response from from then parsing packet and rewriting
                ## TTL to 5 minutes.
                data_from_server, _ = sock.recvfrom(1024)
                packet = PacketManipulation(data_from_server)
                packet.Parse()

                ## Relaying packet from server back to host
                packet_from_server = packet.send_data
                print('Request Received')
                break
        self.sock.sendto(packet_from_server, self.addr)     

class PacketManipulation:
    def __init__(self, data):
        self.data = data

    def Parse(self):
        self.ParseQuery()
        self.ParseRewrite()

    def ParseQuery(self):
#        header = data[:12]
        self.payload = self.data[12:]
#        tmp = struct.unpack(">6H", header)
        j = self.payload.index(0) + 1 + 4
        self.qtype = self.payload[j-3:j-2]
    
    def ParseRewrite(self):       
        qname = self.data[12:].split(b'\x00',1)[0]

        b = 1
        for byte in qname[0:]:
            b += 1
            
        eoqname = 12+b
        eoquery = eoqname + 4        
        rrecord = self.data[eoquery:]
        
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x01+'
        
        if (rrecord[0:2] == pointer):                
            splitdata = self.data.split(pointer)
            rrname = pointer
        else:
            splitdata = self.data.split(qname)
            rrname = qname
            
        rr = b''
        for i, rrpart in enumerate(splitdata, 1):
            if i == 1:
                pass
            else:
                ttl_bytes = rrpart[4:8]
                ttl_check = struct.unpack('>L', ttl_bytes)[0]
                if (ttl_check > 299):
                    rr += rrname + rrpart[:4] + ttl_bytes_override + rrpart[8:]
                else:
                    rr += rrname + rrpart

        self.send_data = splitdata[0] + rr

if __name__ == '__main__':
    try:        
        DNS = DNSRelay()
        DNS.Start()
    except KeyboardInterrupt:
        exit(3)

