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
from dnx_configure.dnx_system_info import System

DNS = 53

class DNSRelay:
    def __init__(self, dnsproxy):
        self.dnsproxy = dnsproxy
        self.path = os.environ['HOME_DIR']
        
        with open(f'{self.path}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)

        self.lan_int = self.setting['Settings']['Interface']['Inside']
        self.wan_int = self.setting['Settings']['Interface']['Outside']

        with open(f'{self.path}/data/dns_server.json', 'r') as dns_records:
            dns_record = json.load(dns_records)
        self.dns_servers = dns_record['DNSServer']['Resolvers']

        Int = Interface()
        self.laddr = Int.IP(self.lan_int)
        self.qaddr = Int.IP(self.wan_int)
        self.dns1 = [self.dns_servers['Server1']['IP Address'], True]
        self.dns2 = [self.dns_servers['Server2']['IP Address'], True]
        self.dnsList = [self.dns1, self.dns2]
        self.listen_port = DNS
               
    def Start(self):
        Reach = threading.Thread(target=self.Reachability)
        Reach.daemon = True
        Reach.start()

        threading.Thread(target=self.Main).start()
    
    def Reachability(self):
        DEVNULL = open(os.devnull, 'wb')
        while True:
            for i, server in enumerate(self.dnsList, 1):
                reach = subprocess.call(['sudo', 'ping', '-c', '1', server[0]], stdout=DEVNULL)
                dns_server = self.dns_servers[f'Server{i}']
                if (reach == 0):
                    server[1] = True
                    status = 'UP'
                else:
                    server[1] = False
                    status = 'Down'

                self.dns_servers.update({f'Server{i}': {
                                            'Name': dns_server['Name'],
                                            'IP Address': dns_server['IP Address'],
                                            'Status': status}})

            with open(f'{self.path}/data/dns_server_status.json', 'w') as dns_server:
                json.dump(self.dns_servers, dns_server, indent=4)
        
            time.sleep(10)

    def Main(self):       
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.laddr, self.listen_port))

        print(f'[+] Listening -> {self.laddr}:{self.listen_port}')
        while True:
            data_from_client, client_address = self.sock.recvfrom(1024)
            try:
                packet = PacketManipulation(data_from_client)
                packet.Parse()
                ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                ## to handle the rest of the process and sending client data in for relay to dns server        
                if (packet.qtype == 1):
                    Relay = threading.Thread(target=self.SignatureCheck, args=(packet, data_from_client, client_address))
                    Relay.daemon = True
                    Relay.start()
            except Exception as E:
                print(E)

    def SignatureCheck(self, packet, data_from_client, client_address):
        ## -- 50 ms delay on all requests to give proxy more time to react -- ## Should be more tightly tuned
        time.sleep(.05)
        ## ## ## ## ## ##
        req1 = packet.qname.lower() # www.micro.com or micro.com || sd.micro.com
        req = req1.split('.')
        req2 = f'{req[-2]}.{req[-1]}' # micro.com or co.uk

        flagged_traffic = self.dnsproxy.flagged_traffic
        request = req1
        src_ip = client_address[0]
        src_port = client_address[1]
        print(f'{src_ip} : {src_port}')
        #send to check the signature
        try:
            if (req1 == flagged_traffic[src_ip][src_port]):
                relay = False
                request = req1
            elif (req2 == flagged_traffic[src_ip][src_port]):
                relay = False
                request = req2
        except KeyError:
            relay = True

        if (relay):
            print(f'Relay Allowed: {src_ip}:{src_port} | {request}')
            self.Relay(data_from_client, client_address)
        else:
            print(f'Relay Denied: {src_ip}:{src_port} | {request}')
            flagged_traffic[src_ip].pop(src_port, None)
            
    def Relay(self, data_from_client, client_address):
        relay = True
        sock = socket(AF_INET, SOCK_DGRAM)
        ## -------------- ##
        ## Iterating over DNS Server List and Sending to first server that is available.
        for server in self.dnsList:
            if (server[1] == True):
                sock.sendto(data_from_client, (server[0], DNS))
                print(f'Request Relayed to {server[0]}: {DNS}')

                ## Waiting for response from server then parsing packet and rewriting
                ## TTL to 5 minutes.
                data_from_server, _ = sock.recvfrom(1024)
                packet = PacketManipulation(data_from_server)
                packet.Rewrite()

                ## Relaying packet from server back to host
                packet_from_server = packet.send_data
#                print('Request Received')
                break
        else:
            Sys = System()
            Sys.Log('DNS: Both configured DNS Servers are unreachable to DNX Relay')
            relay = False

        if (relay):
            self.sock.sendto(packet_from_server, client_address)
            print(f'Request Relayed to {client_address[0]}: {client_address[1]}') 

class PacketManipulation:
    def __init__(self, data):
        self.data = data

    def Parse(self):
        self.QType()
        self.QName()

    def QType(self):
        self.dns_payload = self.data[12:]
        j = self.dns_payload.index(0) + 1 + 4
        self.qtype = self.dns_payload[j-3:j-2]

    def QName(self):
        qn = self.data[12:].split(b'\x00',1)
        qt = qn[1]
        qn = qn[0]
        b = len(qn)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', qn[0:eoqname])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        # coverting query name from bytes to string
        length = qname[0] + 1
        self.qname = ''
        for byte in qname:
            if (length != 0):
                self.qname += chr(byte)
                length -= 1
                continue
                
            length = byte
            self.qname += '.'
    
    def Rewrite(self):
        qname = self.data[12:].split(b'\x00',1)[0]

        offset = len(qname) + 1
            
        eoqname = 12+offset
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
            if i != 1:
                ttl_bytes = rrpart[4:8]
                ttl_check = struct.unpack('>L', ttl_bytes)[0]
                if (ttl_check > 299):
                    rr += rrname + rrpart[:4] + ttl_bytes_override + rrpart[8:]
                else:
                    rr += rrname + rrpart

        self.send_data = splitdata[0] + rr
