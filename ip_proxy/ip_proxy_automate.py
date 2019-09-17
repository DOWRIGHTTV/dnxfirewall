#!/usr/bin/env python3

import os, sys
import time
import json
import asyncio

from subprocess import Popen

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *

class Automate:
    def __init__(self, IPProxy):
        self.IPProxy = IPProxy

    ## TEST THIS
    async def ClearIPTables(self):
        print('[+] Starting: IP Tables Removal Thread')
        Popen('sudo iptables -t mangle -F MALICIOUS && \
                sudo iptables -t mangle -F TOR',shell=True)
        one_hour = 3600
        while True:
            now = time.time()
            fw_rules = self.IPProxy.fw_rules.copy()
            for ip_address, ip_info in fw_rules.items():
                time_added = ip_info[0]
                chain = self.IPProxy.chain_settings[ip_info[1]]
                if (now - time_added > one_hour):
                    #asyncronously running ip table rule removal
                    await asyncio.create_subprocess_shell(
                        f'sudo iptables -D {chain} -s {ip_address} -j DROP && \
                            sudo iptables -D {chain} -d {ip_address} -j DROP',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE)

                    self.IPProxy.fw_rules.pop(ip_address, None)
            await asyncio.sleep(SHORT_TIMER)

    async def Blocking(self):
        while True:
            with open(f'{HOME_DIR}/data/ip_proxy.json', 'r') as fw_settings:
                settings = json.load(fw_settings)
                #move these to settings section
            direction_settings = settings['ip_proxy']['direction']
            block_settings = settings['ip_proxy']['lists']

            self.IPProxy.mal_block = direction_settings['mal']
            self.IPProxy.tor_block = direction_settings['tor']

            self.IPProxy.tor_entry_block = block_settings['tor']['entry']['enabled']
            self.IPProxy.tor_exit_block = block_settings['tor']['exit']['enabled']
            self.IPProxy.malware_block = block_settings['malware']['enabled']
            self.IPProxy.compromised_block = block_settings['compromised']['enabled']

            await asyncio.sleep(SETTINGS_TIMER)

    async def OpenPorts(self):
        while True:
            with open(f'{HOME_DIR}/data/ips.json', 'r') as ips_settings:
                settings = json.load(ips_settings)

            self.IPProxy.open_tcp_ports = settings['ips']['open_protocols']['tcp']
            self.IPProxy.open_udp_ports = settings['ips']['open_protocols']['udp']

            await asyncio.sleep(SETTINGS_TIMER)
