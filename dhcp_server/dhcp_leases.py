#!/usr/bin/python3

import os, sys
import time
import json
import threading, asyncio
import struct
import random

from ipaddress import IPv4Address
from subprocess import run, CalledProcessError, DEVNULL

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_system_info import Interface, System

class DHCPLeases:
    def __init__(self, DHCPServer):
        self.DHCPServer = DHCPServer
        self.Sys = System()

        self.icmp_check = DHCPServer.icmp_check

        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        local_net = setting['settings']['local_net']['subnet']
        self.ip_range = '.'.join(local_net.split('.')[:3])
        self.lease_table = {}

        self.dhcp_range_start = IPv4Address(f'{self.ip_range}.{16}')
        self.dhcp_range_end = IPv4Address(f'{self.ip_range}.{220}')

    ## -- DHCP Server Operations -- ##
    def Release(self, ip, mac):
        lease_ip = self.lease_table.get(ip, None)
        if (lease_ip and lease_ip[1] == mac and lease_ip[0] != -1):
            self.lease_table[ip] = None

    def Handout(self, mac_address):
        if (mac_address in self.dhcp_reservations):
            return self.dhcp_reservations[mac_address]['ip_address']

        ## iterating over the lease table to see give same ip host already had
        ## if new host, will call the set lease method to generate a random ip.
        for ip_address, value in self.lease_table.items():
            if (value is not None and value[1] == mac_address):
                timestamp = time.time()
                self.lease_table.update({ip_address: [timestamp, mac_address]})
                break
        else:
            ip_address = self.SetLease(mac_address)

        return ip_address

    def SetLease(self, mac_address):
        status = False
        max_check = 205
        count = 0
        while not status:
            if (count == max_check):
                self.DHCPServer.Log.AddtoQueue('DHCP Server: IP handout error | No Available IPs in range.')

                ip_address = None
                break

            ip_suffix = random.randint(16,221)
            ip_address = f'{self.ip_range}.{ip_suffix}'

            lease = self.lease_table.get(ip_address, None)
            if (not lease):
                status = True

            if (self.icmp_check):
                result = self.ICMPCheck(ip_address)
                if (result):
                    status = False

            if (status):
                timestamp = time.time()
                self.lease_table.update({ip_address: [timestamp, mac_address]})
                print(f'returning {ip_address}')

            count += 1

        return ip_address

    ## ----------------------------------- ##
    ## -- Reading Lease table from Json -- ##
    def LoadLeases(self):
        print('[+] DHCP: Loading leases from file.')
        with open(f'{HOME_DIR}/data/dhcp_server.json', 'r') as dhcp_settings:
            dhcp_setting = json.load(dhcp_settings)
        self.lease_table.update(dhcp_setting['dhcp_server']['leases'])

    #### -- Initializing lease database operations -- ####
    def BuildRange(self):
        print('[+] DHCP: Building handout range.')
        timestamp = time.time()
        threads = []
        for i in range(16,221):
            hostip = f'{self.ip_range}.{i}'
            thread = threading.Thread(target=self.ICMPCheck, args=(hostip, timestamp, True))
            threads.append(thread)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def ICMPCheck(self, hostip, timestamp=None, initial_check=False):
        result = True
        try:
            response = run(f'ping -c 1 {hostip}', stdout=DEVNULL)
            response.check_returncode()

        except CalledProcessError:
            result = False

        if (initial_check and result):
            self.lease_table[hostip] = [timestamp, None]
        elif (initial_check and not result):
            self.lease_table[hostip] = None

        return result

    #### --         Async auto timers section         -- ####
    ## -- Purging Lease table / Checked every 5 minutes -- ##
    async def LeaseTimer(self):
        while True:
            await asyncio.sleep(5 * 60)
            for ip, value in self.lease_table.items():
                 if (value is not None and value != -1):
                    timestamp = time.time()
                    time_elapsed = timestamp - value[0]
                    if (time_elapsed >= 86800):
                        self.lease_table[ip] = None

    ## -- Lease Table Backup / RUNs EVERY HOUR -- ##
    async def WritetoFile(self):
        while True:
            await asyncio.sleep(60 * 60)
            with open(f'{HOME_DIR}/data/dhcp_server.json', 'r') as dhcp_settings:
                dhcp_setting = json.load(dhcp_settings)
            server_settings = dhcp_setting['dhcp_server']

            new_leases = {}
            for ip, value in self.lease_table.items():
                if (value is not None and value != -1):
                    new_leases.update({ip: value})

            server_settings['leases'] = new_leases
            with open(f'{HOME_DIR}/data/dhcp_server.json', 'w') as dhcp_settings:
                json.dump(dhcp_setting, dhcp_settings, indent=4)

            self.DHCPServer.Log.AddtoQueue('DHCP Server: Backed Up DNX DHCP Leases')

    ## -- Updating DHCP Reservations / Checked every 5 minutes -- #
    async def ReservationTimer(self):
        while True:
            with open(f'{HOME_DIR}/data/dhcp_server.json', 'r') as dhcp_settings:
                dhcp_setting = json.load(dhcp_settings)
            self.dhcp_reservations = dhcp_setting['dhcp_server']['reservations']

            ## -- Configuring DHCP Reservations -- ##
            for res, res_info in self.dhcp_reservations.items():
                ip_address = IPv4Address(res_info['ip_address'])
                self.lease_table[ip_address] = [-1, res]

            await asyncio.sleep(5 * 60)
