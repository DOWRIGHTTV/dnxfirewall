#!usr/bin/env python3

import os, sys
import time
import random
import threading
import traceback
import ssl

from collections import deque
from socket import socket, timeout, AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_WR

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dns_proxy.dns_proxy_packets import PacketManipulation


class UDPRelay:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy

    def SendQuery(self, packet, client_address, fallback=False):
        # grabbing the data object from packet class being passed around
        if (not fallback):
            data_from_client = packet.data
        # removing packet length | already in byte form
        else:
            data_from_client = packet[2:]

        # Iterating over DNS Server List and Sending to first server that is available.
        for server_ip, server_info in self.DNSProxy.dns_servers.items():
            if (server_info['reach'] is True):
                try:
                    udp_socket = socket(AF_INET, SOCK_DGRAM)
                    udp_socket.bind((self.DNSProxy.wan_ip, 0))

                    udp_socket.sendto(data_from_client, (server_ip, DNS_PORT))
                    print(f'Request Relayed to {server_ip}: {DNS_PORT}')

                    break
                except Exception:
                    traceback.print_exc()

        self.ReceiveQuery(udp_socket, client_address, fallback)

    def ReceiveQuery(self, udp_socket, client_address, fallback=False):
        ## if no error in send/recieve to/from server the packet will be relayed back to host
        try:
            data_from_server = udp_socket.recv(4096)

            self.ParseServerResponse(data_from_server, client_address, fallback)

#                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')
        except Exception:
            traceback.print_exc()

        udp_socket.close()

    def ParseServerResponse(self, data_from_server, client_address, fallback=False):
        packet = PacketManipulation(data_from_server, protocol=UDP)
        packet.Parse()

        if (not fallback):
            packet.Rewrite()
        ## Grabbing information from TLS Connection tracker to ensure request gets back to correct client
        else:
            client_address = self.DNSProxy.TLSRelay.dns_connection_tracker[packet.dns_id].get('client_address')
            original_dns_id = self.DNSProxy.TLSRelay.dns_connection_tracker[packet.dns_id].get('client_id')
            self.DNSProxy.TLSRelay.dns_connection_tracker.pop(packet.dns_id, None)

            packet.Rewrite(dns_id=original_dns_id)

        self.DNSProxy.DNSRelay.SendtoClient(packet, client_address)

        # adding packets to cache if not already in and incrimenting the counter for the requested domain.
        self.DNSProxy.DNSCache.Add(packet, client_address)
        self.DNSProxy.DNSCache.IncrementCounter(packet.request)

class TLSRelay:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy

        self.dns_connection_tracker = {}
        self.dns_tls_queue = deque()

        self.unique_id_lock = threading.Lock()

    def AddtoQueue(self, packet, client_address):
        tcp_dns_id = self.GenerateIDandStore()
        dns_payload = packet.UDPtoTLS(tcp_dns_id)

        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'client_id': packet.dns_id, 'client_address': client_address}})

        self.dns_tls_queue.append(dns_payload)

    def ProcessQueue(self):
        while True:
            now = time.time()
            if (not self.dns_tls_queue):
            # waiting 1ms before checking queue again for idle perf
                time.sleep(.001)
                continue

            for secure_server, server_info in self.DNSProxy.dns_servers.items():
                retry = now - server_info.get('retry', now)
                if (server_info['tls'] or retry >= self.DNSProxy.tls_retry):
                    secure_socket = self.Connect(secure_server)
                if (secure_socket):
                    self.QueryThreads(secure_socket)

                    break
            ## UDP Fallback Section | if enabled will create thread to UDPRelay for each message in queue
            ## if not enabled, all messages will be dropped.
            print(f'UDP FALLBACK SETTING: {self.DNSProxy.udp_fallback}')
            if (not secure_socket and self.DNSProxy.udp_fallback):
                print('TLS Failure! Sending Queries over UDP.')
                while self.dns_tls_queue:
                    dns_request = self.dns_tls_queue.popleft()
                    ## calling udp relay as a backup due to both tls server sockets returning None. passing original
                    # message, No client info, and setting fallback argument to True.
                    threading.Thread(target=self.DNSProxy.UDPRelay.SendQuery, args=(dns_request, None, True)).start()

    def QueryThreads(self, secure_socket):
        threading.Thread(target=self.ReceiveQueries, args=(secure_socket,)).start()
        time.sleep(.0001)
        self.SendQueries(secure_socket)

    def SendQueries(self, secure_socket):
        try:
            while self.dns_tls_queue:
                message = self.dns_tls_queue.popleft()

                secure_socket.send(message)

            secure_socket.shutdown(SHUT_WR)

        except Exception as E:
            print(f'TLSQUEUE | SEND: {E}')

    ## TLS handler for all message responses sent from TLS queue. once it receivesthe expected amount it tears down
    ##  the socket and closes the thread for performance. duplicates can cause issues because of this, but the initial
    ## query was UDP so unrealiable anyways.
    def ReceiveQueries(self, secure_socket):
        while True:
            try:
                data_from_server = secure_socket.recv(4096)
                if (not data_from_server):
                    break

                self.ParseServerResponse(data_from_server)
            except (timeout, BlockingIOError):
                break
            except Exception:
                traceback.print_exc()
                break

        secure_socket.close()

    # Response Handler will match all recieved request responses from the server, match it to the host connection
    # and relay it back to the correct host/port. this will happen as they are recieved. the socket will be closed
    # once the recieved count matches the expected/sent count or from socket timeout
    def ParseServerResponse(self, data_from_server):
        try:
            # Checking the DNS ID in packet, Adjusted to ensure uniqueness
            packet = PacketManipulation(data_from_server, protocol=TCP)
            dns_id = packet.DNSID()
            # Checking client DNS ID and Address info to relay query back to host
            dns_query_info = self.dns_connection_tracker.get(dns_id, None)
            if (dns_query_info):
                packet.Parse()
                print(f'Secure Request Received from Server. DNS ID: {packet.dns_id} | {packet.request}')

                client_dns_id = dns_query_info.get('client_id')
                client_address = dns_query_info.get('client_address')
                ## Parsing packet and rewriting TTL to minimum 5 minutes/max 1 hour and changing DNS ID back to original.
                packet.Rewrite(dns_id=client_dns_id)

                client_ip, client_port = client_address
                # these vars will be set to none if it was a request generated by the caching system.
                if (client_ip and client_port):
                    self.DNSProxy.DNSRelay.SendtoClient(packet, client_address)

                # adding packets to cache if not already in and incrimenting the counter for the requested domain.
                self.DNSProxy.DNSCache.Add(packet, client_address)
                self.DNSProxy.DNSCache.IncrementCounter(packet.request)

            #see if this can be in the if statement. cant remember why it was pulled out.
            self.dns_connection_tracker.pop(packet.dns_id, None)
        except ValueError:
            print(data_from_server)
            traceback.print_exc()
        except Exception:
            traceback.print_exc()

    ## Generate a unique DNS ID to be used by TLS connections only. Applies a lock on the function to ensure this
    ## id is thread safe and uniqueness is guranteed. IDs are stored in a dictionary for reference.
    def GenerateIDandStore(self):
        with self.unique_id_lock:
            while True:
                dns_id = random.randint(1, 32000)
                if (dns_id not in self.dns_connection_tracker):
                    self.dns_connection_tracker.update({dns_id: ''})

                    return dns_id

    def Connect(self, secure_server):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.DNSProxy.wan_ip, 0))

        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

        # Wrap socket and Connect. If successful connect will break while loop and allow
        # queue handler to send DNS queries in queue
        try:
            print(f'Opening Secure socket to {secure_server}: 853')
            secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))

        except Exception:
            traceback.print_exc()
            secure_socket = None

        # resetting server tls status if connection was successful
        if (secure_socket):
            self.DNSProxy.dns_servers[secure_server].update({'tls': True})
        # setting server tls status to down due to connection issue with server/port over tls
        else:
            self.DNSProxy.dns_servers[secure_server].update({'tls': False, 'retry': time.time()})

        return secure_socket
