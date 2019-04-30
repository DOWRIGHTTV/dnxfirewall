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
        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass
            elif('inet' in line):
                line = line.strip().split()
                ip = line[1]
#                print(ip)
                return(ip)

    def MTU(self, interface):
        i = 0
        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if(i == 0):
                i += 1
                line = line.strip().split()
                mtu = line[3]
#                print(mtu)
                return(mtu)

    def MAC(self, interface):
        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:       
            if('ether' in line):
                line = line.strip().split()
                mac = line[1]
#                print(mac)
                return(mac)

    def Netmask(self, interface):
        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('netmask' in line):
                line = line.strip().split()
                netmask = line[3]
#                print(netmask)
                return(netmask)

    def Broadcast(self, interface):
        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('broadcast' in line):
                line = line.strip().split()
                broadcast = line[5]
#                print(broadcast)
                return(broadcast)

    def DefaultGateway(self):
        output = check_output('ip route', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('default' in line):
                dfg = line.split()[2]
        
                return dfg
                    
    def IPtoMAC(self, ipa):
        output = check_output('arp -n', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if (line and line.split()[0] == ipa):
                ipa_mac = line.split()[2]
                break
        else:
            ipa_mac = None
                
        return ipa_mac

    def Bandwidth(self):
        intstat = {}
        with open('{}/data/interface_speed.json'.format(self.path), 'r') as speed:
            bandwidth = json.load(speed)
        for key, value in bandwidth.items():
            intstat[key] = [round(int(value[0])*8/1024, 2), round(int(value[1])*8/1024, 2)]

#        print(intstat)
        return intstat

    def WANSubnet(self, interface, dfg):
        masks = [0, 128, 192, 224, 240, 248, 250]
        hosts = [254, 126, 62, 30, 14, 6, 2]
        ip_range = set()

        output = check_output(f'ifconfig {interface}', shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet' in line):
                line = line.strip().split()
                ip = line[1]
                netmask = line[3]
                break
        
        ip = ip.split('.')
        dfg = dfg.split('.')
        netmask = netmask.split('.')
        network = f'{ip[0]}.{ip[1]}.{ip[2]}'
        for i, mask in enumerate(masks):
            if (int(netmask[3]) == mask):
                usable_ips = [dfg[3]+1, dfg[3]+hosts[i]]

        for ip in range(usable_ips[0], usable_ips[1]):
            ip_range.add(f'{network}.{ip}')
#                print(ip)
        return(ip_range)



        
