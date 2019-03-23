#!/usr/bin/python3

import os, sys, json

from dnx_configure.dnx_iptables import Defaults

class Configure:
    def __init__(self):
        path = os.environ['HOME_DIR']

        with open('{}/data/config.json'.format(path), 'r') as settings:
            self.setting = json.load(settings)
        
        self.Interface()
        self.DNS()
        self.LocalNet()
        self.ExternalDNS()
        self.IPTables()

        with open('{}/data/config.json'.format(path), 'w') as settings:
            json.dump(self.setting, settings, indent=4)

    def Interface(self):
        wan_int = input('Wan interface name? ex. eth0: ')
        inside_int = input('Inside interface name? ex. eth1: ')

        ints = self.setting['Settings']['Interface']

        ints.update({'Outside': wan_int})
        ints.update({'Inside': inside_int})
        
    def DNS(self):
        dns_serv1 = input('Primary DNS Server IP?: ')
        dns_serv2 = input('PSecondary DNS Server IP?: ')
        dns_servers = [dns_serv1, dns_serv2]

        dns_servs = self.setting['Settings']['DNSServers']
        for server in dns_servers:
            dns_servs.update({'Server 1': { 
                            'Name': 'Server1',
                            'IP Address': server}})

    def LocalNet(self):
        local_net = input('Local IP range? ex. 192.168.10.0/24: ')

        l_n = self.setting['Settings']['LocalNet']
        l_n.update({'IP Address': local_net})

    def ExternalDNS(self):
        external_dns = input('Block direct external DNS queries? (Recommended) [Y/n]: ')
        if (external_dns.lower() == 'y'):
            ena = 0
        elif (external_dns.lower() == 'n'):
            ena = 1

        ext_dns = self.setting['Settings']['ExternalDNS']
        ext_dns.update({'Enabled': ena})

    def IPTables(self):
        answer = input('Run IPTables automated script? [Y/n]: ')
        if (answer.lower() == 'y' or answer == ''):
            IPT = Defaults()
            IPT.Start()
        elif (answer.lower() == 'n'):
            self.IPTables()
            print()
        else:
            print('Exiting Configuration Manager')    

