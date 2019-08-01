#!/usr/bin/python3

import os, sys, subprocess
import struct
import traceback
import time
import threading
import json
import random
import ssl
import asyncio

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from copy import deepcopy
from socket import socket, timeout, error, AF_INET, SOCK_DGRAM, SOCK_STREAM

from dnx_syslog.syl_main import SyslogService
from dnx_configure.dnx_system_info import Interface

DNS_TLS_PORT = 853
DNS_PORT = 53
TCP = 6
UDP = 17

A_RECORD = 1

class DNSRelay:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy
        self.Syslog = SyslogService()

        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)

        self.lan_int = self.setting['settings']['interface']['inside']
        self.wan_int = self.setting['settings']['interface']['outside']

        Int = Interface()
        self.lan_ip = Int.IP(self.lan_int)
        self.wan_ip = Int.IP(self.wan_int)

        self.dns_connection_tracker = {}
        self.dns_tls_queue = []

    def Start(self):
        time.sleep(10)
        threading.Thread(target=self.TLSQueryQueue).start()
        self.Main()

    async def CheckSettings(self):
        while True:
            with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_settings:
                dns_setting = json.load(dns_settings)
            dns_servers = dns_setting['dns_server']['resolvers']

            self.dns_servers = {}
            dns1 = dns_servers['server1']['ip_address']
            dns2 = dns_servers['server2']['ip_address']
            self.dns_servers[dns1] = {'reach': True, 'tls': True} #, 'retry': None}
            self.dns_servers[dns2] = {'reach': True, 'tls': True} #, 'retry': None}

            tls_settings = dns_setting['dns_server']['tls']

            self.tls_retry = tls_settings['retry']
            self.udp_fallback = tls_settings['fallback']
            tls_enabled = tls_settings['enabled']
            if (tls_enabled):
                self.protocol = TCP
            else:
                self.protocol = UDP

            self.thread_lock = threading.Lock()

            await asyncio.sleep(5*60)

    async def Reachability(self):
        loop = asyncio.get_running_loop()
        while True:
            dns_servers = deepcopy(self.dns_servers)
            for server_ip in dns_servers:
                reach = await asyncio.create_subprocess_shell(
                f'ping -c 1 {server_ip}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)

                await reach.communicate()

                previous_status = self.dns_servers[server_ip].get('reach')
                if (reach.returncode == 0):
                    self.dns_servers[server_ip].update({'reach': True})
                else:
                    self.dns_servers[server_ip].update({'reach': False})
                current_status = self.dns_servers[server_ip].get('reach')
                if (current_status != previous_status):
                    message = (f'DNS Server {server_ip} reachability status changed to {current_status}.')
                    await loop.run_in_executor(None, self.DNSProxy.Log.AddtoQueue, message)

            with open(f'{HOME_DIR}/data/dns_server_status.json', 'w') as dns_server:
                json.dump(self.dns_servers, dns_server, indent=4)

            await asyncio.sleep(10)

    def Main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.lan_ip, DNS_PORT))

        print(f'[+] Listening -> {self.lan_ip}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(4096)
                if (not data_from_client):
                    break
            except error:
                break

            try:
                packet = PacketManipulation(data_from_client, protocol=UDP)
                packet.Parse()
            except Exception:
                pass

            ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
            ## to handle the rest of the process and sending client data in for relay to dns server
            if (packet.qtype == A_RECORD):
                # throttling thread call | a .01 theoretical limit is 100 dns a record requests per second before
                # it will start to fall behind.
                time.sleep(0.01)
                threading.Thread(target=self.SignatureCheck, args=(packet, data_from_client, client_address)).start()

        # Recursive call back to re establish the main socket listening for dns requests
        self.Main()

    def SignatureCheck(self, packet, data_from_client, client_address):
        print(f'2 ||| {time.time()} || RELAY RECEIVED: {client_address[0]}: {client_address[1]}: {packet.qname.lower()}')
        ## -- 50 ms delay on all requests to give proxy more time to react --
        time.sleep(.05)
        ## ## ## ## ## ##
        req1 = packet.qname.lower() # www.micro.com or micro.com || sd.micro.com
        req = req1.split('.')
        req2 = f'{req[-2]}.{req[-1]}' # micro.com or co.uk

        src_ip = client_address[0]
        src_port = client_address[1]

        #send to check the signature
        relay = True
        flagged_traffic = self.DNSProxy.flagged_traffic
        try:
            if (req1 == flagged_traffic[src_ip][src_port]):
                relay = False
                request = req1
            elif (req2 == flagged_traffic[src_ip][src_port]):
                relay = False
                request = req2
            ## temporary until figure out load issue. this might be required under high loads. can put a log here to notify load
            ## may be excessive for system to handle.
            else:
                flagged_traffic[src_ip].pop(src_port, None)
        except KeyError:
            print(f'KEY ERROR ON {src_ip}:{src_port}:{req1}')

        if (relay and self.protocol == UDP):
#           print(f'Relay Allowed: {src_ip}:{src_port} | {request}')
            self.UDPRelay(data_from_client, client_address)
        elif (relay and self.protocol == TCP):
#           print(f'Relay Allowed: {src_ip}:{src_port} | {request}')
            self.TLSQueue(data_from_client, client_address)
        else:
            flagged_traffic[src_ip].pop(src_port, None)
            print(f'Relay Denied: {src_ip}:{src_port} | {request}')

    def UDPRelay(self, data_from_client, client_address, fallback=False):
        relayed = True
        if (fallback):
            packet = PacketManipulation(data_from_client, protocol=TCP)
            tcp_dns_id = packet.DNS()
            data_from_client = data_from_client[2:]

            client_address = self.dns_connection_tracker[tcp_dns_id].get('client_address')
            udp_dns_id = self.dns_connection_tracker[tcp_dns_id].get('client_id')
            self.dns_connection_tracker.pop(tcp_dns_id, None)

        ## Iterating over DNS Server List and Sending to first server that is available.
        for server_ip, server_info in self.dns_servers.items():
            if (server_info['reach'] is True):
                try:
                    sock = socket(AF_INET, SOCK_DGRAM)
                    sock.bind((self.wan_ip, 0))

                    sock.sendto(data_from_client, (server_ip, DNS_PORT))
#                    print(f'Request Relayed to {server_ip}: {DNS_PORT}')

                    break
                except Exception:
                    traceback.print_exc()
        else:
            message = 'Both configured DNS Servers are unreachable from the DNS Relay'

            self.DNSProxy.Log.AddtoQueue(f'DNS: {message}')
            relayed = False

        ## if no error in send/recieve to/from server the packet will be relayed back to host
        if (relayed):
            try:
                data_from_server = sock.recv(1024)

                packet = PacketManipulation(data_from_server, protocol=UDP)
                if (fallback):
                    packet.Rewrite(dns_id=udp_dns_id)
                else:
                    packet.Rewrite()
                packet_from_server = packet.send_data

                if (packet_from_server):
                    self.sock.sendto(packet_from_server, client_address)
#                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')
            except Exception:
                traceback.print_exc()

            sock.close()

    def TLSQueue(self, data_from_client, client_address):
        packet = PacketManipulation(data_from_client, protocol=UDP)
        client_dns_id = packet.DNS()

        tcp_dns_id = self.GenerateIDandStore()
        dns_payload = packet.UDPtoTLS(tcp_dns_id)
#        print(f'Relayed Client {client_address} with DNS ID: {tcp_dns_id}')
        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'client_id': client_dns_id, 'client_address': client_address}})
        self.dns_tls_queue.append(dns_payload)

    def TLSQueryQueue(self):
        while True:
            secure_socket = None
            msg_queue = list(self.dns_tls_queue)
            if (msg_queue):
                for secure_server, server_info in self.dns_servers.items():
                    now = time.time()
                    retry = now - server_info.get('retry', now)
                    if (server_info['tls'] or retry >= self.tls_retry):
                        secure_socket = self.Connect(secure_server)
                    if (secure_socket):
                        break
                ## UDP Fallback Section | if enabled will create thread to UDPRelay for each message in queue
                ## if not enabled, all messages will be dropped.
                else:
                    if (self.udp_fallback):
                        for message in msg_queue:
                            threading.Thread(target=self.UDPRelay, args=(message, None, True))

            ## TLS Section | Start handeler thread which will recieve all messages sent from queue, then if successful
            ## remove the message from the queue
            if (secure_socket):
                msg_count = len(msg_queue)
                threading.Thread(target=self.TLSResponseHandler, args=(secure_socket, msg_count)).start()
                # this time delay solved issues with seg faults in libssl, also were getting double frees and double linked lists
                time.sleep(.001)
                for message in msg_queue:
                    try:
                        secure_socket.send(message)
                    except Exception:
                        traceback.print_exc()

                    self.dns_tls_queue.pop(0)
            time.sleep(.01)

    ## TLS handler for all message responses sent from TLS queue. once it receivesthe expected amount it tears down
    ##  the socket and closes the thread for performance. duplicates can cause issues because of this, but the initial
    ## query was UDP so unrealiable anyways.
    def TLSResponseHandler(self, secure_socket, msg_count):
        recv_count = 0
        # loop will not continue once the received message count equals the expected count. this ensures sockets do not
        # remain open longer than they need to or have to wait for a timeout.
        while recv_count < msg_count:
            try:
                data_from_server = secure_socket.recv(4096)
                recv_count += 1
                if (not data_from_server):
                    break

            except (timeout, BlockingIOError) as E:
#                print(f'TLS TIMEOUT | BLOCK: {E}')
                break
            except Exception:
                traceback.print_exc()
                break

            try:
                # Checking the DNS ID in packet, Adjusted to ensure uniqueness
                packet = PacketManipulation(data_from_server, protocol=TCP)
                tcp_dns_id = packet.DNS()
#                print(f'Secure Request Received from Server. DNS ID: {tcp_dns_id}')

                # Checking client DNS ID and Address info to relay query back to host
                client_dns_id = self.dns_connection_tracker[tcp_dns_id]['client_id']
                client_address = self.dns_connection_tracker[tcp_dns_id]['client_address']

                ## Parsing packet and rewriting TTL to 5 minutes and changing DNS ID back to original.
                packet.Rewrite(dns_id=client_dns_id)
                packet_from_server = packet.send_data

                ## Relaying packet from server back to host if dns response portion is not empty
                if (packet_from_server):
                    self.sock.sendto(packet_from_server, client_address)
#                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')
            except Exception:
                traceback.print_exc()

            self.dns_connection_tracker.pop(tcp_dns_id, None)

        secure_socket.close()

    ## Generate a unique DNS ID to be used by TLS connections only. applies a lock on the function to ensure this
    ## id is thread safe and no duplicate ids will be generated.
    def GenerateIDandStore(self):
        self.thread_lock.acquire()
        while True:
            dns_id = random.randint(1, 32000)
            if (dns_id not in self.dns_connection_tracker):
                self.dns_connection_tracker.update({dns_id: ''})
                self.thread_lock.release()

                return dns_id

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def Connect(self, secure_server):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.wan_ip, 0))
        sock.settimeout(3)

        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
#        context.options |= (ssl.PROTOCOL_TLSv1_2)
        context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

        # Wrap socket and Connect. If exception will add to attempt value and mark as status
        # as false. If successful connect will break while loop and allow queue handler to
        # send DNS query
        try:
#            print(f'Opening Secure socket to {secure_server}: 853')
            secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))
            #print(self.secure_socket.getpeercert()) # will show server certificate details
        except Exception:
            traceback.print_exc()
            secure_socket = None

        if (not secure_socket):
            now = round(time.time())
            self.dns_servers[secure_server].update({'tls': False, 'retry': now})

        return secure_socket

class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

        self.qtype = 0

    def Parse(self):
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

        qname = struct.unpack(f'!{b}B', qn[:eoqname])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        # coverting query name from bytes to string
        length = qname[0]
        self.qname = ''
        for byte in qname[1:]:
            if (length != 0):
                self.qname += chr(byte)
                length -= 1
                continue

            length = byte
            self.qname += '.'

    def Rewrite(self, dns_id=None):
        qname = self.data[12:].split(b'\x00',1)[0]
        if (dns_id):
            dns_id = struct.pack('!H', dns_id)

        offset = len(qname) + 1
        end_of_qname = 12 + offset
        end_of_query = end_of_qname + 4
        start_of_record = end_of_query
        request_header = self.data[:end_of_query]
        request_record = self.data[start_of_record:]

        # assigning pointer variable, which is a protocol constant and ttl for 5 minutes in packet form.
        pointer = b'\xc0\x0c'
#        ttl_bytes_override = b'\x00\x00\x01+'

        # FOR TESTIN ONLY
        ttl_bytes_override = b'\x00\x00\x00\x05'

        # splitting the dns packet on the compressed pointer if present, if not splitting on qname.
        if (request_record[0:2] == pointer):
            rr_splitdata = request_record.split(pointer)
            rr_name = pointer
            offset = 0
        else:
            rr_splitdata = request_record.split(qname)
            rr_name = qname

        # checking to see whether a record is present in response. if so, reset record and prep to rewrite.
        # rewrite the dns record TTL to 5 minutes if not already lower to ensure clients to not keep records
        # cached for exessive periods making dns proxy ineffective.
        send_data = False
        if (request_record):
            send_data = True
            request_record = b''
            for rr_part in rr_splitdata[1:]:
                type_check = rr_part[offset + 2:offset + 4]
                type_check = struct.unpack('!H', type_check)[0]
                if (type_check == A_RECORD):
                    ttl_bytes = rr_part[offset + 4:offset + 8]
                    ttl_check = struct.unpack('>L', ttl_bytes)[0]
                    if (ttl_check > 299):
                        request_record += rr_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
                    else:
                        request_record += rr_name + rr_part
                else:
                    request_record += rr_name + rr_part

        # Replacing tcp dns id with original client dns id if id is present
        if (send_data and dns_id):
            self.send_data = dns_id + request_header[2:] + request_record
        elif (send_data and not dns_id):
            self.send_data = request_header + request_record
        else:
            self.send_data = None

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return tcp_dns_payload
