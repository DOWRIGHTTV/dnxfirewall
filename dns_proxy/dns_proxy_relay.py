#!/usr/bin/python3

import os, sys
import traceback
import time
import threading
import json
import asyncio

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from copy import deepcopy
from collections import Counter
from socket import socket, timeout, error, AF_INET, SOCK_DGRAM

from dnx_configure.dnx_constants import *
from dns_proxy.dns_proxy_protocols import UDPRelay, TLSRelay
from dns_proxy.dns_proxy_packets import PacketManipulation
from dnx_configure.dnx_system_info import Interface


class DNSRelay:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy

        self.dns_connection_tracker = {}
        self.unique_id_lock = threading.Lock()

        self.protocol = 0

    def Start(self):
        threading.Thread(target=self.DNSProxy.DNSCache.AutoClear).start()
        threading.Thread(target=self.DNSProxy.DNSCache.TopDomains).start()
        threading.Thread(target=self.DNSProxy.TLSRelay.ProcessQueue).start()
        self.Main()

    def Main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.DNSProxy.lan_ip, DNS_PORT))

        print(f'[+] Listening -> {self.DNSProxy.lan_ip}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(4096)
                if (not data_from_client):
                    break
                self.ParseQueries(data_from_client, client_address)
            except error:
                break

        # Recursive call back to re establish the main socket listening for dns requests
        self.Main()

    def ParseQueries(self, data_from_client, client_address):
        try:
            packet = PacketManipulation(data_from_client, protocol=UDP)
            packet.Parse()
        except Exception:
            traceback.print_exc()

        ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
        ## to handle the rest of the process and sending client data in for relay to dns server
        if (packet.qtype == A_RECORD):
            threading.Thread(target=self.RequestHandler, args=(packet, client_address)).start()
            time.sleep(.001)

    def RequestHandler(self, packet, client_address):
        cached_packet = None
        # checking request status, if request is in allowed/flagged dict the process will break and continue to process
        # loop will re check status every 1 ms, then timeout at 50ms
        for attempt in range(1,51):
            decision = self.DecisionCheck(packet, client_address, attempt)
            if (decision is not None):
                break

            time.sleep(.001)

        # for testing
        src_ip, src_port = client_address

        # Checking for cached Query
        if (decision == ALLOWED):
            cached_packet = self.DNSProxy.DNSCache.Search(packet.request, packet.dns_id)

        # dropping packet as soon as possible
        if (decision == FLAGGED):
            print(f'Relay Denied: {src_ip}:{src_port}: packet.request') # replace will pass

        elif (cached_packet):
            self.SendtoClient(cached_packet, client_address, from_cache=True)
            print(f'CACHED REQUEST: {src_ip}:{src_port}: {packet.request}')

        elif (self.protocol == UDP):
            self.DNSProxy.UDPRelay.SendQuery(packet, client_address)
            print(f'UDP Relay ALLOWED: {src_ip}:{src_port}: {packet.request}')

        elif (self.protocol == TCP):
            self.DNSProxy.TLSRelay.AddtoQueue(packet, client_address)
            print(f'TLS Relay ALLOWED: {src_ip}:{src_port}: {packet.request}')
        else:
            print(f'Relay Timeout: {src_ip}:{src_port} | DNS ID: {packet.dns_id} | REQUESTS: {packet.request} | {packet.request2}')

    def DecisionCheck(self, packet, client_address, attempt):
        src_ip, src_port = client_address
        for decision in [ALLOWED, FLAGGED]:
            query_check = getattr(self.DNSProxy, f'{decision}_request')
            client_ip = query_check.get(src_ip, None)
            if (not client_ip):
                continue
            query = query_check[src_ip].get(src_port, -1)
            if (query in {packet.request, packet.request2}):
                query_check[src_ip].pop(src_port, False)

                break
            else:
                print(f'CLIENT: {src_ip}:{src_port} | REQUEST: {packet.request} | 1: {packet.request} | 2: {packet.request2} | {decision}_request')
        else:
            decision = None

        return decision

    def SendtoClient(self, packet, client_address, from_cache=False):
        ## Relaying packet from server back to host
        self.sock.sendto(packet.send_data, client_address)
#        print(f'Request Relayed to {client_address[0]}: {client_address[1]}')


class DNSCache:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy
        self.dns_cache = {}

        self.domain_counter = Counter()
        self.top_domains = {}

        self.domain_counter_lock = threading.Lock()
        self.clear_dns_cache = False
        self.clear_top_domains = False

    # queries will be added to cache if it is not already cached or has expired or if the dns response is the
    # result from an internal dns request for top domains
    def Add(self, packet, client_address):
        expire = int(time.time()) + packet.cache_ttl
        client_ip, client_port = client_address
        if ((packet.request not in self.dns_cache and packet.data_to_cache)
                or (not client_ip and not client_port)):
            self.dns_cache.update({packet.request: {
                                            'packet': packet.data_to_cache,
                                            'expire': expire}})

            print(f'CACHE ADD | NAME: {packet.request} TTL: {packet.cache_ttl}')

    # will check to see if query is cached/ has been requested before. if not will add to queue for standard query
    def Search(self, request, client_dns_id):
        now = int(time.time())
        cached_query = self.dns_cache.get(request, None)
        if (cached_query and cached_query['expire'] > now):
            calculated_ttl = cached_query['expire'] - now
            cached_packet = PacketManipulation(cached_query['packet'], protocol=UDP)
            cached_packet.Parse()

#            print(f'CALCULATED TTL: {calculated_ttl}')
            if (calculated_ttl > DEFAULT_TTL):
                calculated_ttl = DEFAULT_TTL

            cached_packet.Rewrite(dns_id=client_dns_id, response_ttl=calculated_ttl)

            return cached_packet

    def IncrementCounter(self, domain):
        with self.domain_counter_lock:
            self.domain_counter[domain] += 1

    # automated process to flush the cache if expire time has been reached. runs every 1 minute.
    def AutoClear(self):
        while True:
            now = time.time()
            if (self.clear_dns_cache):
                self.ClearCache('dns_cache')

            self.top_domains = {domain: count for count, domain in enumerate(self.domain_counter, 1) \
                if count < TOP_DOMAIN_COUNT}
            query_cache = deepcopy(self.dns_cache)
            for domain, info in query_cache.items():
                if (info['expire'] > now and domain not in self.top_domains):
                    self.dns_cache.pop(domain, None)

            print('CLEARED EXPIRED CACHE.')

            time.sleep(5 * 60)

    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    def TopDomains(self):
        client_address = (None, None)
        while True:
            if self.clear_top_domains:
                self.ClearCache('top_domains')

            for domain in self.top_domains:
                cached_packet_info = self.dns_cache.get(domain, None)
                if (cached_packet_info):
                    # reverting the dns response packet to a standard query
                    packet = PacketManipulation(cached_packet_info['packet'], protocol=UDP)
                    packet.RevertResponse()

                    self.DNSProxy.TLSRelay.AddtoQueue(packet, client_address)

            with open('{HOME_DIR}/data/dns_cache.json', 'w') as top_domains:
                json.dump(self.top_domains, top_domains, indent=4)

            print(f'RE CACHED TOP DOMAINS. TOTAL: {len(self.top_domains)}')
            # logging top domains in cache for reference. if top domains are useless, will work on a way to ensure only important domains
            # are cached. worst case can make them configurable.
            with open('top_domains_cached.txt', 'a+') as top_domains:
                top_domains.write(f'{self.top_domains}\n')

            time.sleep(5 * 60)

    # method called to reset dictionary cache for sent in value (standard or top domains) and then reset the flag in the json file back to
    # false. the settings automation will check and revert the class var to false so not doing that here.
    def ClearCache(self, cache_type):
        setattr(self, cache_type, {})

        with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_settings:
            dns_setting = json.load(dns_settings)

        cache_setting = dns_setting['dns_server']['cache']
        cache_setting.update({cache_type: False})

        with open(f'{HOME_DIR}/data/dns_server.json', 'w') as dns_settings:
            json.dump(dns_setting, dns_settings, indent=4)
