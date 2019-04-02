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
        
