#!/usr/bin/python3

import os, time
import json
import threading

from subprocess import run
from dnx_configure.dnx_system_info import Interface

class Defaults:
    def __init__(self):
        Int = Interface()
        self.dns_chains = ['MALICIOUS', 'WHITELIST' , 'BLACKLIST']
        self.custom_chains = ['MALICIOUS', 'WHITELIST' , 'BLACKLIST', 'FIREWALL', 'NAT']
        self.path = os.environ['HOME_DIR']

        with open('{}/config.json'.format(self.path), 'r') as cfg:
            settings = json.load(cfg)

        self.inside_int = settings['Settings']['Interface']['Inside']
        self.wan_int = settings['Settings']['Interface']['Inside']

        self.homedir = settings['Settings']['HOMEDIR']['Path']
        self.extdns = settings['Settings']['ExternalDNS']['Enabled']
        self.localnet = settings['Settings']['LocalNet']['IP Address']

        self.insideip = Int.IP(self.inside_int)
        self.wanip = Int.IP(self.wan_int)

    def Start(self):
        try:
            self.create_new_chains()
            self.main_forward_set()
            self.main_input_set()
            self.main_output_set()
            self.NAT()
        except Exception as E:
            print(E)
            
    def create_new_chains(self):
        for chain in self.custom_chains:
            run('iptables -N {}'.format(chain), shell=True, check=True) # Creating Custom Chains for use
            run('iptables -A {} -j RETURN'.format(chain), shell=True) # Appending return action to bottom of all custom chains
        
    def main_forward_set(self):
        run('iptables -P FORWARD DROP', shell=True) # Default DROP
        run('iptables -A INPUT -i {} -j NAT'.format(self.wan_int), shell=True) # Checking Port Forward Allow Rules
        if (self.extdns == 0):
            run('iptables -A FORWARD -p udp --dport 53 -j REJECT', shell=True) # Block External DNS Queries UDP (Public Resolver)
            run('iptables -A FORWARD -p tcp --dport 53 -j REJECT', shell=True) # Block External DNS Queries TCP (Public Resolver)
        elif (self.extdns == 1):
#            for chain in self.dns_chains:
#                run('iptables -A FORWARD -p udp --sport 53 -j {}'.format(chain),shell=True) # Return Traffic From External DNS Server
            for chain in self.dns_chains:
                run('iptables -A FORWARD -p udp --dport 53 -j {}'.format(chain), shell=True) # Initial DNS Request from Internal Host
        run('iptables -A FORWARD -i {} -j FIREWALL'.format(self.inside_int), shell=True) # Allowing traffic to go to WAN from Inside Interface
        run('iptables -A FORWARD -i {} -j ACCEPT'.format(self.inside_int), shell=True) # Allowing traffic to go to WAN from Inside Interface
        run('iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back to Inside
        
    def main_input_set(self):
        run('iptables -P INPUT DROP', shell=True) # Default DROP
        run('iptables -A INPUT -i {} -p icmp --icmp-type any -j ACCEPT'.format(self.inside_int), shell=True) # Allow ICMP to Firewall
        run('iptables -A INPUT -i {} -p udp --dport 67 -j ACCEPT'.format(self.inside_int), shell=True) # DHCP Server listening port
        run('iptables -A INPUT -i {} -p udp --dport 53 -j ACCEPT'.format(self.inside_int), shell=True) # DNS Query(To firewall DNS Relay) is allowed in, block will be applied on outbound if necessary
        run('iptables -A INPUT -i {} -p tcp --dport 443 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTPS to Firewalls Web server (internal only)
        run('iptables -A INPUT -i {} -p tcp --dport 80 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTP to Firewalls Web server (internal only)
        run('iptables -A INPUT -i {} -p tcp --dport 5000 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTP to Firewalls Web server (internal only)
        run('iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back Firewall itself
                
    def main_output_set(self):
        run('iptables -P OUTPUT DROP', shell=True) # Default DROP
        for chain in self.dns_chains:
            run('iptables -A OUTPUT -s {} -p udp --dport 53 -j {}'.format(self.wanip, chain), shell=True) # DNS Queries pushed to custom DNS chains for inspection
        run('iptables -A OUTPUT -s {} -j ACCEPT'.format(self.wanip), shell=True) # allowing all outgoing connections from Firewall (replacing default Allow)
        
    def NAT(self):
        run('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(self.wan_int), shell=True) # Main masquerade rule. Inside to Outside
        run('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True) # Allow forwarding through system, required for NAT to work.

if __name__ == '__main__':
    IPT = Defaults()
    IPT.Start()
        
