#!/usr/bin/env python3

import os, sys
import json
import time
import asyncio

from subprocess import Popen

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *


class Automate:
    def __init__(self, IPS):
        self.IPS = IPS

    async def DDOSCalculation(self):
        loop = asyncio.get_running_loop()
        await asyncio.sleep(2)
        print('[+] Starting: DDOS Detection Thread.')
        while True:
            ddos_detected = {}
            if (self.IPS.ddos_prevention):
                timestamp = time.time()
                for protocol in self.IPS.protocol_conversion.values():
                    protocol_result = await self.DDOSCalculationWorker(protocol, timestamp)
                    if (protocol_result):
                        ddos_detected.update(protocol_result)

                        print(f'{protocol} ddos detected! :/')

                for protocol, tracked_ip in ddos_detected.items():
                    logging_options = {'ip': tracked_ip, 'protocol': protocol,
                                        'attack_type': DDOS, 'action': 'filtered'}
#                   await loop.run_in_executor(None, self.Logging, timestamp, logging_options)

                if (not ddos_detected):
                    self.IPS.active_ddos = False

                await asyncio.sleep(5)
            else:
                await asyncio.sleep(SETTINGS_TIMER)

    async def DDOSCalculationWorker(self, protocol, timestamp):
        blocked_hosts = {}

        ddos_tracker = getattr(self, f'{protocol}_ddos_tracker')
        src_limit = getattr(self, f'{protocol}_src_limit')
        ddos_tracker_copy = ddos_tracker.copy()
        for tracked_ip, info in ddos_tracker_copy.items():
            count = info['count']
            initial_time = info['timestamp']
            elapsed_time = time.time() - initial_time
            print(f'COUNT: {count} | PPS: {count/elapsed_time}')
            block_host = False
            with self.IPS.fw_rule_creation_lock:
                if (count/elapsed_time >= src_limit and tracked_ip not in self.IPS.fw_rules):
                    self.IPS.fw_rules.update({tracked_ip: timestamp})
                    blocked_hosts.update({protocol: tracked_ip})
                    block_host = True

            # see about adding check for successful entry. if fail to create iptable log the result
            if (block_host):
                self.IPS.active_ddos = True
                await asyncio.create_subprocess_shell(f'sudo iptables -t mangle -A IPS -s {tracked_ip} -j DROP',
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)

                print(f'BLOCKED: {tracked_ip}')

            ddos_tracker.pop(tracked_ip, None)

        return blocked_hosts

    ## TEST THIS
    async def ClearIPTables(self):
        print('[+] Starting: IP Tables Removal Thread.')
        while True:
            fw_rules = self.IPS.fw_rules.copy()
            if (self.IPS.block_length > 0):
                now = time.time()
                for src_ip, time_added in fw_rules.items():
                    if (now - time_added >= self.IPS.block_length):
                        Popen(f'sudo iptables -t mangle -D IPS -s {src_ip} -j DROP', shell=True)
                        self.IPS.fw_rules.pop(src_ip, None)

            await asyncio.sleep(SHORT_TIMER)

    async def IPSSettings(self):
        print('[+] Starting: IPS Settings Update Thread.')
        while True:
            with open(f'{HOME_DIR}/data/ips.json', 'r') as ips_settings:
                settings = json.load(ips_settings)

            self.IPS.ddos_prevention = settings['ips']['ddos']['enabled']
            self.IPS.portscan_prevention = settings['ips']['port_scan']['prevention']

            # ddos PPS THRESHHOLD CHECK
            self.IPS.tcp_src_limit = settings['ips']['ddos']['limits']['source']['tcp'] # Make this configurable
            self.IPS.udp_src_limit = settings['ips']['ddos']['limits']['source']['udp']
            self.IPS.icmp_src_limit = settings['ips']['ddos']['limits']['source']['icmp']
            self.IPS.combined_dst_limit = settings['ips']['ddos']['limits']['destination']['combined']

            ##Checking length(hours) to leave IP Table Rules in place for Portscan
            self.IPS.block_length = settings['ips']['port_scan']['length'] * 3600

            ## OPEN PORTS CHECK - TIED TO PUBLIC > PRIVATE NAT
            self.IPS.icmp_allow = settings['ips']['open_protocols']['icmp']
            open_tcp_ports = settings['ips']['open_protocols']['tcp']
            open_udp_ports = settings['ips']['open_protocols']['udp']
            self.IPS.open_tcp_ports = {int(i) for i in open_tcp_ports}
            self.IPS.open_udp_ports = {int(i) for i in open_udp_ports}

            ## Reject packet (tcp reset and icmp port unreachable)
            self.IPS.portscan_reject = settings['ips']['port_scan']['reject']

            ## whitelist configured dns servers
            self.IPS.whitelist_dns_servers = settings['ips']['whitelist']['dns_servers']

            await asyncio.sleep(SETTINGS_TIMER)

    async def IPWhitelist(self):
        await asyncio.sleep(2)
        print('[+] Starting: IP Whitelist Update Thread.')
        while True:
            with open(f'{HOME_DIR}/data/ips.json', 'r') as whitelists:
                whitelist = json.load(whitelists)

            ip_whitelist = set(whitelist['ips']['whitelist']['ip_whitelist'])

            with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_servers:
                dns_server = json.load(dns_servers)
            dns1 = dns_server['dns_server']['resolvers']['server1']['ip_address']
            dns2 = dns_server['dns_server']['resolvers']['server2']['ip_address']

            if (self.IPS.whitelist_dns_servers):
                self.IPS.ip_whitelist = ip_whitelist.union({dns1, dns2})

            await asyncio.sleep(SETTINGS_TIMER)