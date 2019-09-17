#!/usr/bin/env python3

import os, sys
import time
import json
import asyncio

from copy import deepcopy

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *


class Automate:
    def __init__(self, DNSProxy):
        self.DNSProxy = DNSProxy

    async def LogSettings(self):
        print(f'[+] Log Settings Timer')
        while True:
            with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
                setting = json.load(settings)

            self.DNSProxy.logging_level = setting['settings']['logging']['level']

            await asyncio.sleep(SETTINGS_TIMER)

    async def DNSRecords(self):
        print(f'[+] DNS Records Timer')
        while True:
            with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_records:
                dns_record = json.load(dns_records)

            self.DNSProxy.dns_records = dns_record['dns_server']['records']

            await asyncio.sleep(SETTINGS_TIMER)

    async def UserDefinedLists(self):
        print(f'[+] User Defined Lists Timer')
        while True:
            current_time = time.time()
            ## --------------------------------------------- ##
            ## -- IP WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##
            with open(f'{HOME_DIR}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.DNSProxy.ip_whitelist = whitelist['whitelists']['ip_whitelist']

            ## ---------------------------------------------- ##
            ## -- DNS WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##
            with open(f'{HOME_DIR}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.DNSProxy.dns_whitelist = whitelist['whitelists']['domains']

            write_whitelist = False
            dns_whitelist = deepcopy(self.DNSProxy.dns_whitelist)
            for domain, info in dns_whitelist.items():
                if current_time > info['expire']:
                    self.DNSProxy.dns_whitelist.pop(domain)
                    write_whitelist = True

            if (write_whitelist):
                 with open(f'{HOME_DIR}/data/whitelist.json', 'w') as whitelists:
                    json.dump(whitelist, whitelists, indent=4)

            ## -------------------------------------------##
            ## -- BLACKLIST CHECK AND CLEAN/ IF NEEDED -- ##
            with open(f'{HOME_DIR}/data/blacklist.json', 'r') as blacklists:
                blacklist = json.load(blacklists)
            self.DNSProxy.dns_blacklist = blacklist['blacklists']['domains']

            write_blacklist = False
            dns_blacklist = deepcopy(self.DNSProxy.dns_blacklist)
            for domain, info in dns_blacklist.items():
                if current_time > info['expire']:
                    self.DNSProxy.dns_blacklist.pop(domain)
                    write_blacklist = True

            if (write_blacklist):
                 with open(f'{HOME_DIR}/data/blacklist.json', 'w') as blacklists:
                    json.dump(blacklist, blacklists, indent=4)

            print('Updating white/blacklists in memory.')
            await asyncio.sleep(SETTINGS_TIMER)

    async def Reachability(self):
        print(f'[+] DNS Public Server Reachability Timer')
        loop = asyncio.get_running_loop()
        while True:
            for server_ip in self.DNSProxy.dns_servers:
                reach = await asyncio.create_subprocess_shell(
                f'ping -c 2 {server_ip}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)

                await reach.communicate()

                previous_status = self.DNSProxy.dns_servers[server_ip].get('reach')
                if (reach.returncode == 0):
                    self.DNSProxy.dns_servers[server_ip].update({'reach': True})
                else:
                    self.DNSProxy.dns_servers[server_ip].update({'reach': False})
                current_status = self.DNSProxy.dns_servers[server_ip].get('reach')
                if (current_status != previous_status):
                    message = (f'DNS Server {server_ip} reachability status changed to {current_status}.')
                    await loop.run_in_executor(None, self.DNSProxy.Log.AddtoQueue, message)

            with open(f'{HOME_DIR}/data/dns_server_status.json', 'w') as dns_server:
                json.dump(self.DNSProxy.dns_servers, dns_server, indent=4)

            await asyncio.sleep(SHORT_POLL)

    async def Settings(self):
        print(f'[+] General Settings Timer')
        while True:
            with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_settings:
                dns_setting = json.load(dns_settings)
            dns_servers = dns_setting['dns_server']['resolvers']

            if (dns_servers != self.DNSProxy.dns_servers):
                self.DNSProxy.dns_servers = {}
                dns1 = dns_servers['server1']['ip_address']
                dns2 = dns_servers['server2']['ip_address']
                self.DNSProxy.dns_servers[dns1] = {'reach': True, 'tls': True}
                self.DNSProxy.dns_servers[dns2] = {'reach': True, 'tls': True}

            tls_settings = dns_setting['dns_server']['tls']

            self.DNSProxy.tls_retry = tls_settings['retry']
            self.DNSProxy.udp_fallback = tls_settings['fallback']
            tls_enabled = tls_settings['enabled']
            if (tls_enabled):
                self.DNSProxy.DNSRelay.protocol = TCP
            else:
                self.DNSProxy.DNSRelay.protocol = UDP

            cache_settings = dns_setting['dns_server']['cache']
            # CLEAR DNS or TOP Domains cache
            self.DNSProxy.DNSCache.clear_dns_cache = cache_settings['standard']
            self.DNSProxy.DNSCache.clear_top_domains = cache_settings['top_domains']

            await asyncio.sleep(SETTINGS_TIMER)

    # automated process to flush the cache if expire time has been reached. runs every 1 minute.
    async def ClearCache(self):
        print(f'[+] DNS Local Cache Clearing Timer')
        while True:
            now = time.time()
            query_cache = deepcopy(self.DNSProxy.DNSCache.dns_query_cache)
            for domain, info in query_cache.items():
                if (now > info['expire']):
                    self.DNSProxy.DNSCache.dns_query_cache.pop(domain, None)

            cache_size = sys.getsizeof(self.DNSProxy.DNSCache.dns_query_cache)
            num_records = len(self.DNSProxy.DNSCache.dns_query_cache)
            print(f'CACHE SIZE: {cache_size} | NUMBER OF RECORDS: {num_records}')
            await asyncio.sleep(SHORT_POLL)
