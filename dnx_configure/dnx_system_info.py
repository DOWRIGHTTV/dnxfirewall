#!/usr/bin/python3

import os
import datetime
import json

from collections import OrderedDict
from subprocess import check_output

class Interface:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        
    def IP(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass
            elif('inet' in line):
                line = line.strip().split(' ')
                ip = line[1]
#                print(ip)
                return(ip)

    def MTU(self, interface):
        i = 0
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if(i == 0):
                i += 1
                line = line.strip().split(' ')
                mtu = line[4]
#                print(mtu)
                return(mtu)

    def Netmask(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('netmask' in line):
                line = line.strip().split(' ')
                netmask = line[4]
#                print(netmask)
                return(netmask)

    def Broadcast(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('broadcast' in line):
                line = line.strip().split(' ')
                broadcast = line[7]
#                print(broadcast)
                return(broadcast)

    def Bandwidth(self):
        intstat = {}
        with open('{}/data/interface_speed.json'.format(self.path), 'r') as speed:
            bandwidth = json.load(speed)
        for key, value in bandwidth.items():
            intstat[key] = [round(int(value[0])*8/1024, 2), round(int(value[1])*8/1024, 2)]

#        print(intstat)
        return intstat
        
class System:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        
    def CPU(self):
        with open('/proc/stat', 'r') as CPU:
            for i, line in enumerate(CPU):
                if (i == 0):         
                    line = line.split()
                    idle = int(line[4])
                    b = 0
                    for entry in line:
                        if 'cpu' not in entry:
                            b += int(entry)
                    idle *= 100
                    idle /= b
                utilization = '{}%'.format(round(100 - idle, 2))
#        print(utilization)
        return utilization
                    

    def Uptime(self):
        with open('/proc/uptime', 'r') as uptime:
            for line in uptime:       
                uptime = line.split()[0]
                uptime = datetime.timedelta(0, int(float(uptime)))
                utime = str(uptime).split()
                if ('day' in str(uptime) or 'days' in str(uptime)):         
                    uptime = '{} days {} hours {} minutes'.format(\
                    utime[0], utime[2].split(':')[0], utime[2].split(':')[1])
                else:
                    uptime = '{} days {} hours {} minutes'.format(\
                    0, utime[0].split(':')[0], utime[0].split(':')[1])
#        print(uptime)
        return uptime
            
    def RAM(self):
        meminfo = []     
        with open('/proc/meminfo', 'r') as RAM:
            for i, line in enumerate(RAM, 1):
                if (i == 1 or i == 3):
                    usage = line.split()[1]
                    meminfo.append(usage)
                    
        ram = round(int(meminfo[1]) / int(meminfo[0]) * 100, 1)            
        ram = '{}%'.format(ram)
#        print(ram)
        return(ram)
    
    def DNSStatus(self):
        with open('{}/data/dnsstatus.json'.format(self.path)) as dnsstat:
            dnsstatus = json.load(dnsstat)
#        print(dnsstatus)
        return dnsstatus 
                                
if __name__ == '__main__':
    Int = Interface()
#    Sys = System()
#    Int.IP(INIFACE)
#    Int.MTU(INIFACE)
#    Int.Netmask(INIFACE)
#    Int.Broadcast(INIFACE)
#    Int.Bandwidth()
#    Sys.CPU()
#    Sys.Uptime()
#    Sys.RAM()
#    Sys.DNSStatus()