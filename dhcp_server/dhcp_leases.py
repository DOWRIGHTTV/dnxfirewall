#!/usr/bin/python3

import os, sys, time, json, subprocess
import threading, asyncio
import struct

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface

class DHCPLeases:
    def __init__(self, localNet):
        self.path = os.environ['HOME_DIR']

        self.localNet = localNet
        self.leasetable = {}
        ipoctet = self.localNet.split('.')
        self.iprange = '{}.{}.{}'.format(ipoctet[0], ipoctet[1], ipoctet[2])

    ## -- Reading Lease table from file -- ##
    def ReadLeases(self):
        try:
            with open('{}/dhcp_server/dnx.leases'.format(self.path), 'r') as leases:
                while True:
                    line = leases.readline().strip().lower()
                    if (not line):
                        break
                    line = line.split(' ')
                    ip = line[0]
                    timestamp = line[1]
                    mac = line[2]
                    self.leasetable[ip] = [timestamp, mac]
        except Exception as E:
            print(E)

    #### -- Initializing lease database operations -- ####
    def BuildRange(self):        
    ## -- Building standard lease table -- ##
        timestamp = int(time.time())
        threads = []
        for i in range(16,221):
            hostip = '{}.{}'.format(self.iprange, i)
            threads.append(threading.Thread(target=self.ICMPThread, args=(hostip, timestamp)))
        for t in threads:    
            t.start()
        for t in threads:
            t.join()
        
    def ICMPThread(self, hostip, timestamp):
        response = self.ICMPWorker(hostip)
        if (response == 0):
            self.leasetable[hostip] = [timestamp, None]
        else:
            self.leasetable[hostip] = None

    def ICMPWorker(self, hostip):
        DEVNULL = open(os.devnull, 'wb')
        res = subprocess.call(['ping', '-c', '1', str(hostip)], stdout = DEVNULL)	

        return(res)
    #### -- Ending Initializing lease database operations -- ####


    ## -- DHCP Release section -- ##
    def Release(self, ip, mac):
        try:
            lease_ip = self.leasetable[ip]
            if (lease_ip is not None):
                if (lease_ip[1] == mac and lease_ip[0] != '-1'):
                    print('Releasing {} : {} from table'.format(ip, mac))
                    self.leasetable[ip] = None
            else:
                pass
        except Exception:
            pass

    ## -- Handing out IP Addresses to response class -- ##
    def Handout(self, mac):
        for reservation in self.dhcp_reservations:
            if (mac == reservation):
                return self.dhcp_reservations[mac]['IP Address']
            else:
                pass
                    
        else:
            while True:
                for ip, value in self.leasetable.items():
                    if (value is None):
                        pass
                    elif (value[1] == mac):
                        timestamp = int(time.time())
                        self.leasetable[ip] = [timestamp, mac]
                        return ip
                    else:
                        pass
                for ip, value in self.leasetable.items():
                    if (value is None):
                        timestamp = int(time.time())
                        self.leasetable[ip] = [timestamp, mac]
                        return ip
                    else:
                        pass
                else:
                    return None

    #### --         Async auto timers section         -- #### 
    ## -- Purging Lease table / Checked every 5 minutes -- ##        
    async def LeaseTimer(self):
        while True:     
            await asyncio.sleep(5 * 60)
            print('Purging DNX Lease Table (if needed)')
            for ip, value in self.leasetable.items():
                if (value is None or value == '-1'):
                    pass
                else:
                    timestamp = int(time.time())
                    time_elapsed = timestamp - int(value[0])
                    if (time_elapsed >= 86800):
                        self.leasetable[ip] = None
                    else:
                        pass

    #Lease Table Backup / RUNs EVERY HOUR#
    async def WritetoFile(self):
        while True:
            await asyncio.sleep(60 * 60)
            print('Backing up DNX DHCP Leases')
            with open('{}/dhcp_server/dnx.leases'.format(self.path), 'w+') as leases:
                for ip, value in self.leasetable.items():
                    if (value is not None and value != '-1'):
                        leases.write('{} {} {}\n'.format(ip, value[0], value[1]))

    ## -- Updating DHCP Reservations / Checked every 5 minutes -- #
    async def ReservationTimer(self):
        while True:          
            with open('{}/data/config.json'.format(self.path), 'r') as settings:
                setting = json.load(settings)

            self.dhcp_reservations = setting['Settings']['DHCPReservations']

            ## -- Configuring DHCP Reservations -- ##
            for reservation in self.dhcp_reservations:
                res_ip = self.dhcp_reservations[reservation]['IP Address']
                res = res_ip.split('.')
                if (int(res[3]) in range(16,221)):
                    self.leasetable[res_ip] = ['-1', reservation]
                else:
                    pass

            await asyncio.sleep(5 * 60)

