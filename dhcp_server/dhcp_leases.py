#!/usr/bin/python3

import os, sys, time, json, subprocess
import threading, asyncio
import struct

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface, System

class DHCPLeases:
    def __init__(self, icmp_check):
        self.path = os.environ['HOME_DIR']
        self.Sys = System()

        with open(f'{self.path}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        self.local_net = setting['Settings']['LocalNet']['Subnet']
        self.ip_range = '.'.join(self.local_net.split('.')[:3])
        self.lease_table = {}

        self.icmp_check = icmp_check

    ## -- DHCP Server Operations -- ##
    def Release(self, ip, mac):
        lease_ip = self.lease_table.get(ip, None)
        if (lease_ip):
            if (lease_ip[1] == mac and lease_ip[0] != -1):
                self.lease_table[ip] = None

    def Handout(self, mac):
        if (mac in self.dhcp_reservations):
            return self.dhcp_reservations[mac]['IP Address']
                    
        while True:
            for ip, value in self.lease_table.items():
                if (value is not None and value[1] == mac):
                    timestamp = round(time.time())
                    self.lease_table[ip] = [timestamp, mac]

                    return ip

            for ip, value in self.lease_table.items():
                if (value is None):
                    if (self.icmp_check):
                        result = self.ICMPCheck(ip)
                        if result:
                            continue

                    timestamp = round(time.time())
                    self.lease_table[ip] = [timestamp, mac]

                    return ip
            else:
                self.Sys.Log('DHCP Server: IP handout error | No Available IPs in range.')

                return None
    ## ----------------------------------- ##
    ## -- Reading Lease table from Json -- ##
    def LoadLeases(self):
        print('[+] DHCP: Loading leases from file.')
        with open(f'{self.path}/data/dhcp_server.json', 'r') as stored_leases:
            leases = json.load(stored_leases)
        self.lease_table.update(leases['Reservations'])

    #### -- Initializing lease database operations -- ####
    def BuildRange(self):
        print('[+] DHCP: Building handout range.')
        timestamp = round(time.time())
        threads = []
        for i in range(16,221):
            hostip = f'{self.ip_range}.{i}'
            thread = threading.Thread(target=self.ICMPThread, args=(hostip, timestamp))
            threads.append(thread)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
    def ICMPThread(self, hostip, timestamp):
        response = self.ICMPCheck(hostip)
        if (response):
            self.lease_table[hostip] = [timestamp, None]
        else:
            self.lease_table[hostip] = None

    def ICMPCheck(self, hostip):
        DEVNULL = open(os.devnull, 'wb')
        response = subprocess.call(['ping', '-c', '1', hostip], stdout=DEVNULL)	

        if (response == 0):
            result = True
        else:
            result = False

        return(result)

    #### --         Async auto timers section         -- #### 
    ## -- Purging Lease table / Checked every 5 minutes -- ##        
    async def LeaseTimer(self):
        while True:     
            await asyncio.sleep(5 * 60)
            for ip, value in self.lease_table.items():
                if (value is None or value == -1):
                    pass
                else:
                    timestamp = round(time.time())
                    time_elapsed = timestamp - value[0]
                    if (time_elapsed >= 86800):
                        self.lease_table[ip] = None

    ## -- Lease Table Backup / RUNs EVERY HOUR -- ##
    async def WritetoFile(self):
        while True:
            await asyncio.sleep(60 * 60)
            with open(f'{self.path}/data/dhcp_server.json', 'r') as dhcp_server:
                server_leases = json.load(dhcp_server)

            new_leases = {}
            for ip, value in self.lease_table.items():
                if (value is not None and value != -1):
                    new_leases.update({ip: value})

            server_leases['Leases'] = new_leases
            with open(f'{self.path}/data/dhcp_server.json', 'w') as dhcp_server:
                json.dump(server_leases, dhcp_server, indent=4)

            self.Sys.Log('DHCP Server: Backed Up DNX DHCP Leases')

    ## -- Updating DHCP Reservations / Checked every 5 minutes -- #
    async def ReservationTimer(self):
        while True:
            with open(f'{self.path}/data/dhcp_server.json', 'r') as dhcp_reservations:
                dhcp_reservation = json.load(dhcp_reservations)
            self.dhcp_reservations = dhcp_reservation['Reservations']

            ## -- Configuring DHCP Reservations -- ##
            for reservation in self.dhcp_reservations:
                res_ip = self.dhcp_reservations[reservation]['IP Address']
                res = int(res_ip.split('.')[3])
                if (res in range(16,221)):
                    self.lease_table[res_ip] = [-1, reservation]

            await asyncio.sleep(5 * 60)

