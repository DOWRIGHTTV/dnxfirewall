#!/usr/bin/python3

import os, time, subprocess
import threading, asyncio
import struct

from socket import *
from system_info import Interface

class DHCPLeases:
    def __init__(self, setting, whitelist):
        self.setting = setting
        self.whitelist = whitelist
        LocalNET = self.setting['Settings']['LocalNET']['IP Address']
        self.MACS = self.whitelist['Whitelists']['Users']
        self.dhcp_reservations = self.setting['Settings']['DHCPReservations']
        self.leasetable = {}
        self.whitelist = {}
        ipoctet = LocalNET.split('.')
        self.iprange = '{}.{}.{}'.format(ipoctet[0], ipoctet[1], ipoctet[2])

    #--Persistent lease operations--#
    async def WritetoFile(self):
    #Lease Table Backup / RUNs EVERY HOUR#
        while True:
#            await asyncio.sleep(60)
            await asyncio.sleep(60 * 60)
            print('Backing up DNX DHCP Leases')
            with open('dnx.leases', 'w+') as leases:
                for ip, value in self.leasetable.items():
                    if (value is not None and value != '-1'):
                        leases.write('{} {} {}\n'.format(ip, value[0], value[1]))

    def ReadLeases(self):
        try:
            with open('dnx.leases', 'r') as leases:
                while True:
                    urlHex = ''
                    line = leases.readline().strip().lower()
                    if (not line):
                        break
                    line = line.split(' ')
                    ip = line[0]
                    timestamp = line[1]
                    mac = line[2]
                    self.leasetable[line[0]] = [timestamp, mac]
        except Exception as E:
            print(E)
    ## -- End of Persistent lease operations -- ##

    ## -- Initializing lease database operations -- ##
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

    ## -- Configuring DHCP Reservations -- ##
        for reservation in self.dhcp_reservations:
            res_ip = self.dhcp_reservations[reservation]['IP Address']
            res = res_ip.split('.')
            if (int(res[3]) in range(16,221)):
                self.leasetable[res_ip] = ['-1', reservation]
            else:
                pass            
        
    def ICMPThread(self, hostip, timestamp):
        response = self.ICMPWorker(hostip)
#        print('{} : {}'.format(hostip, response))
        if (response == 0):
            self.leasetable[hostip] = [timestamp, None]
        else:
            self.leasetable[hostip] = None

    def ICMPWorker(self, hostip):
        DEVNULL = open(os.devnull, 'wb')
        res = subprocess.call(['ping', '-c', '1', str(hostip)], stdout = DEVNULL)	
        return(res)

    ## -- Ending Initializing lease database operations -- ##
    
    ## -- Purging Lease table / Checked every 5 minutes -- ##        
    async def Timer(self):
        while True:     
#            await asyncio.sleep(45)
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

    def Release(self, ip, mac):    
        try:
            self.leasetable[ip] = lease_ip
            if (lease_ip is not None):
                if (lease_ip[1] == mac and lease_ip[0] != '-1'):
                    print('Releasing {} : {} from table'.format(ip, mac))
                    self.leasetable[ip] = None
            else:
                pass
        except Exception as E:
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
