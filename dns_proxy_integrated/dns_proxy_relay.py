#!/usr/bin/python3

import os, sys, subprocess
import struct
import traceback
import time
import threading
import json
import random
import ssl

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from copy import deepcopy
from socket import socket, timeout, AF_INET, SOCK_DGRAM, SOCK_STREAM

from dnx_syslog.log_main import SyslogService
from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_system_info import System as Sys

DNS_TLS_PORT = 853
DNS_PORT = 53
TCP = 6
UDP = 17

class DNSRelay:
    def __init__(self, dnsproxy):
        self.path = os.environ['HOME_DIR']
        self.dnsproxy = dnsproxy
        self.System = Sys()
        self.Syslog = SyslogService()
        
        with open(f'{self.path}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)

        self.lan_int = self.setting['Settings']['Interface']['Inside']
        self.wan_int = self.setting['Settings']['Interface']['Outside']

        Int = Interface()
        self.laddr = Int.IP(self.lan_int)
        self.qaddr = Int.IP(self.wan_int)

        self.dns_connection_tracker = {}
        self.dns_tls_queue = []
               
    def Start(self):
        self.CheckSettings(thread=False)

        if (self.protocol == TCP):           
            threading.Thread(target=self.TLSQueryQueue).start()
        
        threading.Thread(target=self.Reachability).start()
        threading.Thread(target=self.Main).start()
        threading.Thread(target=self.CheckSettings, args=(True,)).start()

    def CheckSettings(self, thread=False):
        while True:
            with open(f'{self.path}/data/dns_server.json', 'r') as dns_settings:
                dns_setting = json.load(dns_settings)
            dns_servers = dns_setting['DNSServer']['Resolvers']

            self.dns_servers = {}
            dns1 = dns_servers['Server1']['IP Address']
            dns2 = dns_servers['Server2']['IP Address']
            self.dns_servers[dns1] = {'Reach': True, 'TLS': True} #, 'Retry': None}
            self.dns_servers[dns2] = {'Reach': True, 'TLS': True} #, 'Retry': None}

            tls_settings = dns_setting['DNSServer']['TLS']

            self.tls_retry = tls_settings['Retry']
            self.udp_fallback = tls_settings['Fallback']
            tls_enabled = tls_settings['Enabled']
            if (tls_enabled):
                self.protocol = TCP
            else:
                self.protocol = UDP

            self.thread_lock = threading.Lock()

            if (not thread):
                break
            time.sleep(5*60)
    
    def Reachability(self):
        DEVNULL = open(os.devnull, 'wb')
        while True:
            dns_servers = deepcopy(self.dns_servers)
            for server_ip in dns_servers:
                reach = subprocess.call(['sudo', 'ping', '-c', '1', server_ip], stdout=DEVNULL)
                if (reach == 0):
                    self.dns_servers[server_ip].update({'Reach': True})
                else:
                    self.dns_servers[server_ip].update({'Reach': True})

            with open(f'{self.path}/data/dns_server_status.json', 'w') as dns_server:
                json.dump(self.dns_servers, dns_server, indent=4)
        
            time.sleep(10)

    def Main(self):       
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.laddr, DNS_PORT))

        print(f'[+] Listening -> {self.laddr}:{DNS_PORT}')
        while True:
            data_from_client, client_address = self.sock.recvfrom(1024)
            try:
                packet = PacketManipulation(data_from_client, protocol=UDP)
                packet.Parse()
                ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                ## to handle the rest of the process and sending client data in for relay to dns server        
                if (packet.qtype == 1):
                    threading.Thread(target=self.SignatureCheck, args=(packet, data_from_client, client_address)).start()
            except Exception as E:
                traceback.print_exc()
                print(f'MAIN: {E}')

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

        if (relay and self.protocol == UDP):
            print(f'Relay Allowed: {src_ip}:{src_port} | {request}')
            self.UDPRelay(data_from_client, client_address)
        elif (relay and self.protocol == TCP):
            print(f'Relay Allowed: {src_ip}:{src_port} | {request}')
            self.TLSQueue(data_from_client, client_address)
        else:
            print(f'Relay Denied: {src_ip}:{src_port} | {request}')
            flagged_traffic[src_ip].pop(src_port, None)
            
    def UDPRelay(self, data_from_client, client_address, fallback=False):
        relayed = True
        sock = socket(AF_INET, SOCK_DGRAM)
        ## -------------- ##
        ## Iterating over DNS Server List and Sending to first server that is available.
        for server_ip, server_info in self.dns_servers:
            if (server_info['Reach'] is True):
                sock.sendto(data_from_client, (server_ip, DNS_PORT))
                print(f'Request Relayed to {server_ip}: {DNS_PORT}')

                ## Waiting for response from server then parsing packet and rewriting
                ## TTL to 5 minutes.
                data_from_server, _ = sock.recvfrom(1024)
                packet = PacketManipulation(data_from_server, protocol=UDP)
                packet.Rewrite()

                ## Relaying packet from server back to host
                packet_from_server = packet.send_data
#                print('Request Received')
                break
        else:
            message = 'Both configured DNS Servers are unreachable from the DNS Relay'

            self.System.Log(f'DNS: {message}')
            self.Syslog.AddtoQueue(module='DNSRelay', msg_type=3, msg_level=1, message=message)
            relayed = False

        if (relayed):
            self.sock.sendto(packet_from_server, client_address)
            print(f'Request Relayed to {client_address[0]}: {client_address[1]}')

    def TLSQueue(self, data_from_client, client_address):
        packet = PacketManipulation(data_from_client, protocol=UDP)
#        packet.Parse()
        client_dns_id = packet.DNS()

        tcp_dns_id = self.GenerateIDandStore()
        dns_payload = packet.UDPtoTLS(tcp_dns_id)
        print(f'Relayed Client {client_address} with DNS ID: {tcp_dns_id}')
        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'Client ID': client_dns_id, 'Client Address': client_address}})
        self.dns_tls_queue.append(dns_payload)

    def TLSQueryQueue(self):
        while True:
            secure_socket = None
            msg_queue = list(self.dns_tls_queue)
            if (msg_queue):
                for secure_server, server_info in self.dns_servers.items():
                    now = time.time()
                    retry = now - server_info.get('Retry', now)
                    if (server_info['TLS'] or retry >= self.tls_retry):
                        secure_socket = self.Connect(secure_server)
                    if (secure_socket):
                        break
                else:
                    ##Fallback to UDP if configured ||||ASDFASFGASDFAS FFSGDFGXDSDG SDGVSDFG SD
                    if (self.udp_fallback):
                        pass
            
            if (secure_socket):
                threading.Thread(target=self.TLSResponseHandler, args=(secure_socket,)).start()
                for message in msg_queue:
                    try:
                        secure_socket.send(message)
                        self.dns_tls_queue.pop()
                    except Exception as E:
                        traceback.print_exc()
                        print(f'SEND: {E}')
            time.sleep(.01)

    def TLSResponseHandler(self, secure_socket):
#        self.packet_checks = {}
        while True:
            try:
                data_from_server = secure_socket.recv(4096)
                if data_from_server:
                    # Checking the DNS ID in packet, Adjusted to ensure uniqueness
                    packet = PacketManipulation(data_from_server, protocol='TCP')
                    tcp_dns_id = packet.DNS()
                    print(f'Secure Request Received from Server. DNS ID: {tcp_dns_id}')

#                    self.packet_checks[tcp_dns_id] = data_from_server
                    # Checking client DNS ID and Address info to relay query back to host
                    client_dns_id = self.dns_connection_tracker[tcp_dns_id]['Client ID']
                    client_address = self.dns_connection_tracker[tcp_dns_id]['Client Address']

                    ## Parsing packet and rewriting TTL to 5 minutes and changing DNS ID back to original.
                    packet.Rewrite(dns_id=client_dns_id)
                    packet_from_server = packet.send_data

                    ## Relaying packet from server back to host
                    self.sock.sendto(packet_from_server, client_address)
                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')

                    self.dns_connection_tracker.pop(tcp_dns_id)
            except KeyError:
                pass
            except timeout:
                secure_socket.close()
                break
            except Exception as E:
                secure_socket.close()
                traceback.print_exc()
                print(f'RECEIVE: {E}')
                break

    def GenerateIDandStore(self):
        while True:
            self.thread_lock.acquire()
            self.dns_id_lock = True
            dns_id = random.randint(1, 32000)
            if (dns_id not in self.dns_connection_tracker):
                
                self.dns_connection_tracker.update({dns_id: ''})
                self.thread_lock.release()
                return dns_id

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def Connect(self, secure_server):
        attempt = 0
        while True:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(3)

            context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

            # Wrap socket and Connect. If exception will add to attempt value and mark as status
            # as false. If successful connect will break while loop and allow queue handler to
            # send DNS query
            try:
                print(f'Opening Secure socket to {secure_server}: 853')
                secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
                secure_socket.connect((secure_server, DNS_TLS_PORT))
                #print(self.secure_socket.getpeercert())
            except Exception as E:
                traceback.print_exc()
                print(f'CONNECT: {E}')
                secure_socket = False
                attempt += 1

            if (secure_socket):
                break
            elif (attempt >= 3):
                now = round(time.time())
                self.dns_servers[secure_server].update({'TLS': False, 'Retry': now})          

        return secure_socket

class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

    def Parse(self):
        self.DNS()
        self.QType()
        self.QName()

    def DNS(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

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
    
    def Rewrite(self, dns_id=None):
        qname = self.data[12:].split(b'\x00',1)[0]
        dns_id = struct.pack('!H', dns_id)

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

        # Replacing tcp dns id with original client dns id if id is present
        if (not dns_id):
            self.send_data = splitdata[0] + rr
        else:
            self.send_data = dns_id + splitdata[0][2:] + rr

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return(tcp_dns_payload)
