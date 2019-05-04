
#!/usr/bin/env python3

import os, sys, time
import json
import threading

from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface

class Defaults:
    def __init__(self):
        Int = Interface()
        self.dns_chains = ['MALICIOUS', 'WHITELIST' , 'BLACKLIST']
        self.custom_chains = ['MALICIOUS', 'WHITELIST' , 'BLACKLIST', 'FIREWALL', 'NAT', 'TOR']

        self.path = os.environ['HOME_DIR']

        with open('{}/data/config.json'.format(self.path), 'r') as cfg:
            settings = json.load(cfg)

        self.inside_int = settings['Settings']['Interface']['Inside']
        self.wan_int = settings['Settings']['Interface']['Outside']
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
            run('iptables -t nat -N NAT', shell=True)
            run('iptables -t nat -A NAT -j RETURN', shell=True)
            run('iptables -t nat -A PREROUTING -j NAT', shell=True)

    def main_forward_set(self):
        run('iptables -P FORWARD DROP', shell=True) # Default DROP
        run('iptables -A FORWARD -i {} -p tcp --dport 53 -j REJECT'.format(self.inside_int), shell=True) # Block External DNS Queries TCP (Public Resolver)
        run('iptables -A FORWARD -i {} -j WHITELIST'.format(self.inside_int), shell=True)
        run('iptables -A FORWARD -i {} -j TOR'.format(self.inside_int), shell=True)
        run('iptables -A FORWARD -i {} -j FIREWALL'.format(self.inside_int), shell=True) # Allowing traffic to go to WAN from Inside Interface
        run('iptables -A FORWARD -i {} -j ACCEPT'.format(self.inside_int), shell=True) # Allowing traffic to go to WAN from Inside Interface
        run('iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back to Inside

    def main_input_set(self):
        run('iptables -P INPUT DROP', shell=True) # Default DROP
        run('iptables -A INPUT -i {} -j TOR'.format(self.inside_int), shell=True)
        run('iptables -A INPUT -i {} -j FIREWALL'.format(self.inside_int), shell=True)
        run('iptables -A INPUT -i {} -j NAT'.format(self.wan_int), shell=True) # Checking Port Forward Allow Rules
        run('iptables -A INPUT -i {} -p icmp --icmp-type any -j ACCEPT'.format(self.inside_int), shell=True) # Allow ICMP to Firewall
        run('iptables -A INPUT -i {} -p udp --dport 67 -j ACCEPT'.format(self.inside_int), shell=True) # DHCP Server listening port
        run('iptables -A INPUT -i {} -p udp --dport 53 -j ACCEPT'.format(self.inside_int), shell=True) # DNS Query(To firewall DNS Relay) is allowed in, block will be applied on outbound if necessary
        run('iptables -A INPUT -i {} -p tcp --dport 443 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTPS to Firewalls Web server (internal only)
        run('iptables -A INPUT -i {} -p tcp --dport 80 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTP to Firewalls Web server (internal only)
        run('iptables -A INPUT -i {} -p tcp --dport 5000 -j ACCEPT'.format(self.inside_int), shell=True) # Allowing HTTP to Firewalls Web server (internal only)
        run('iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back Firewall itself

    def main_output_set(self):
        for chain in self.dns_chains:
            run('iptables -A OUTPUT -p udp --dport 53 -j {}'.format(chain), shell=True) # DNS Queries pushed to custom DNS chains for inspection

    def NAT(self):
        run('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(self.wan_int), shell=True) # Main masquerade rule. Inside to Outside
        run('iptables -t nat -A PREROUTING -i {} -p udp --dport 53 -j REDIRECT --to-port 53'.format(self.inside_int), shell=True)
        run('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True) # Allow forwarding through system, required for NAT to work.

class IPTables:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

    def Restore(self):
        run('sudo iptables-restore < {}/data/iptables_backup.cnf'.format(self.path), shell=True)

    def Commit(self):
        run('sudo iptables-save > {}/data/iptables_backup.cnf'.format(self.path), shell=True)

if __name__ == '__main__':
    IPT = Defaults()
    IPT.Start()
        
