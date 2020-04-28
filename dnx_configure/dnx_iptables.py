#!/usr/bin/python3

import os, sys
import time
import fcntl
import json
import threading
import asyncio

from subprocess import run, run, CalledProcessError, DEVNULL
from types import SimpleNamespace as SName

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_file_operations import load_configuration

__all__ = (
    'Defaults', 'IPTableManager'
)


class Defaults:
    def start(self):
        self.get_settings()
        try:
            self.create_new_chains()
            self.prerouting_set()
            self.mangle_forward_set()
            self.main_forward_set()
            self.main_input_set()
            self.main_output_set()
            self.nat()
            self.network_forwarding()
            self.block_ipv6()
        except Exception as E:
            print(E)

    def create_new_chains(self):
        for chain in self.custom_chains:
            run(f'iptables -N {chain}', shell=True) # Creating Custom Chains for uses

        run(' iptables -t mangle -N IPS', shell=True) # for DDOS prevention
        run(' iptables -t nat -N NAT', shell=True)

    def prerouting_set(self):
        run(' iptables -t nat -A PREROUTING -j NAT', shell=True) # User DNATS insert into here
        run(' iptables -t mangle -A PREROUTING -j IPS', shell=True) # IPS rules insert into here

    def mangle_forward_set(self):
        # this will mark all packets to be inspected by ip proxy and allow it to pass packet on to other rules
        run(f'iptables -t mangle -A FORWARD -i {self.lan_int} -j MARK --set-mark 10', shell=True) # lan > wan
        run(f'iptables -t mangle -A FORWARD -i {self.wan_int} -j MARK --set-mark 11', shell=True) # wan > lan

        run(' iptables -t mangle -A INPUT -j MARK --set-mark 20', shell=True)

    def main_forward_set(self):
        run('iptables -P FORWARD DROP', shell=True) # Default DROP
        run('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back to Inside
        # standard blocking for unwanted DNS protocol/ports to help prevent proxy bypass
        run(f'iptables -A FORWARD -i {self.lan_int} -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable', shell=True) # Block External DNS over TLS Queries UDP (Public Resolver)
        run(f'iptables -A FORWARD -i {self.lan_int} -p tcp --dport  53 -j REJECT --reject-with tcp-reset', shell=True) # Block External DNS Queries TCP (Public Resolver)
        run(f'iptables -A FORWARD -i {self.lan_int} -p tcp --dport 853 -j REJECT --reject-with tcp-reset', shell=True) # Block External DNS over TLS Queries TCP (Public Resolver)
        run(f'iptables -A FORWARD -i {self.lan_int} -j DOH', shell=True)

        run(f'iptables -A FORWARD -i {self.lan_int} -p icmp -j ACCEPT', shell=True) # ALLOW ICMP OUTBOUND
        run(' iptables -A FORWARD -p tcp -m mark --mark 10 -j NFQUEUE --queue-num 1', shell=True) # IP Proxy TCP
        run(' iptables -A FORWARD -p tcp -m mark --mark 11 -j NFQUEUE --queue-num 1', shell=True) # IP Proxy TCP
        run(' iptables -A FORWARD -p udp -m mark --mark 10 -j NFQUEUE --queue-num 1', shell=True) # IP Proxy UDP
        run(' iptables -A FORWARD -p udp -m mark --mark 11 -j NFQUEUE --queue-num 1', shell=True) # IP Proxy UDP
        # ip proxy drop, but allowing ips to inspect to ddos
        run(f'iptables -A FORWARD -m mark --mark 25 -j NFQUEUE --queue-num 2', shell=True) # IPS UDP
        # IPS proper
        run(f'iptables -A FORWARD -p icmp -m mark --mark 11 -j NFQUEUE --queue-num 2', shell=True) # IPS ICMP - only type 8 will be checked, rest forwaded
        run(f'iptables -A FORWARD -m mark --mark 20 -j NFQUEUE --queue-num 2', shell=True) # IPS TCP/UDP
        # custom chains
        run(' iptables -A FORWARD -m mark --mark 30 -j FIREWALL', shell=True) # User configured firewall rules go HERE
        run(f'iptables -A FORWARD -i {self.wan_int} -m mark --mark 30 -j NAT', shell=True) # Checking Port Forward Allow Rules
        run(f'iptables -A FORWARD -i {self.lan_int} -m mark --mark 30 -j ACCEPT', shell=True) # Allowing traffic to go to WAN from Inside Interface

    def main_input_set(self):
        run(' iptables -P INPUT DROP', shell=True) # Default DROP
        run(' iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back Firewall itself

        run(' iptables -A INPUT -p tcp --dport 22 -j ACCEPT', shell=True) # NOTE: SSH CONN FOR LAB TESTING
        run(' iptables -A INPUT -p udp -d 127.0.0.53 --dport 53 -j ACCEPT', shell=True) # NOTE: TEMP FOR UBUNTU DNS SERVICE
        run(' iptables -A INPUT -s 127.0.0.1/24 -d 127.0.0.1/24 -j ACCEPT', shell=True) # PGRES SQL LOCAL PORT
        run(f'iptables -A INPUT -i {self.lan_int} -p icmp --icmp-type any -j ACCEPT', shell=True) # Allow ICMP to Firewall
        run(f'iptables -A INPUT -i {self.lan_int} -p udp --dport 67 -j ACCEPT', shell=True) # DHCP Server listening port
        run(f'iptables -A INPUT -i {self.lan_int} -p udp --dport 53 -j ACCEPT', shell=True) # DNS Query(To firewall DNS Relay) is allowed in,
        run(f'iptables -A INPUT -i {self.lan_int} -p tcp --dport 443 -j ACCEPT', shell=True) # Allowing HTTPS to Firewalls Web server (internal only)
        run(f'iptables -A INPUT -i {self.lan_int} -p tcp --dport 80 -j ACCEPT', shell=True) # Allowing HTTP to Firewalls Web server (internal only)

        # required for portscan and ddos protection logic
        run(f'iptables -A INPUT -i {self.wan_int} -p tcp -m mark --mark 20 -j NFQUEUE --queue-num 2', shell=True)
        run(f'iptables -A INPUT -i {self.wan_int} -p udp -m mark --mark 20 -j NFQUEUE --queue-num 2', shell=True)
        run(f'iptables -A INPUT -i {self.wan_int} -p icmp -m icmp --icmp-type 8 -m mark --mark 20 -j NFQUEUE --queue-num 2', shell=True)

    def main_output_set(self):
        run('iptables -P OUTPUT ACCEPT', shell=True) # Default ALLOW

    def nat(self):
        run(f'iptables -t nat -A POSTROUTING -o {self.wan_int} -j MASQUERADE', shell=True) # Main masquerade rule. Inside to Outside
        run(f'iptables -t nat -I PREROUTING  -i {self.lan_int} -p udp --dport 53 -j REDIRECT --to-port 53', shell=True)

    def network_forwarding(self):
        run('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True) # Allow forwarding through system, required for NAT to work.

    def block_ipv6(self):
        run(f'ip6tables -P INPUT DROP', shell=True, stdout=DEVNULL)
        run(f'ip6tables -P FORWARD DROP', shell=True, stdout=DEVNULL)
        run(f'ip6tables -P OUTPUT DROP', shell=True, stdout=DEVNULL)

    def get_settings(self):
        interface_settings = load_configuration('config')

        interface = interface_settings['settings']['interfaces']
        self.lan_int = interface['lan']['ident']
        self.wan_int = interface['wan']['ident']

        self.custom_chains = ['FIREWALL', 'NAT', 'DOH']


_err_write = sys.stderr.write


class IPTableManager:
    ''' This is the IP Table rule adjustment manager. if class is called in as a context manager, all method calls
    must be ran in the context where the class instance itself is returned as the object. Changes as part of a context
    will be automatically saved upon exit of the context, otherwise they will have to be saved manually.
    '''
    def __init__(self):
        interface_settings = load_configuration('config')

        interface_settings = interface_settings['settings']['interfaces']
        self._wan_int = interface_settings['wan']['ident']
        self._lan_int = interface_settings['lan']['ident']

        self._iptables_lock_file = f'{HOME_DIR}/dnx_system/iptables.lock'

    def __enter__(self):
        self._iptables_lock = open(self._iptables_lock_file, 'r+')
        fcntl.flock(self._iptables_lock, fcntl.LOCK_EX)

        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if (exc_type is None):
            run(f'sudo iptables-save > {HOME_DIR}/dnx_system/iptables/iptables_backup.cnf', shell=True)

        fcntl.flock(self._iptables_lock, fcntl.LOCK_UN)
        self._iptables_lock.close()

        return True

    def commit(self):
        '''explicit, process safe, call to save iptables to backup file. this is not needed if using
        within a context manager as the commit happens on exit.'''
        run(f'sudo iptables-save > {HOME_DIR}/dnx_system/iptables/iptables_backup.cnf', shell=True)

    def restore(self):
        '''process safe restore of iptable rules in/from backup file.'''
        run(f'sudo iptables-restore < {HOME_DIR}/dnx_system/iptables/iptables_backup.cnf', shell=True)

    @staticmethod
    def purge_proxy_rules(*, table, chain):
        run(f'sudo iptables -t {table} -F {chain}', shell=True)

    @staticmethod
    def proxy_add_rule(ip_address, *, table, chain):
        run(
            f'sudo iptables -t {table} -A {chain} -s {ip_address} -j DROP && \
            sudo iptables -t {table} -A {chain} -d {ip_address} -j DROP', shell=True
            )

        _err_write(f'RULE INSERTED: {ip_address} | {fast_time()}')

    @staticmethod
    def proxy_del_rule(ip_address, *, table, chain):
        run(
            f'sudo iptables -t {table} -D {chain} -s {ip_address} -j DROP && \
            sudo iptables -t {table} -D {chain} -d {ip_address} -j DROP', shell=True
            )

        _err_write(f'RULE REMOVED: {ip_address} | {fast_time()}')

    def add_rule(self, iptable_rule):
        opt = SName(**iptable_rule)

        firewall_rule = None
        if (opt.protocol == 'any'):
            firewall_rule  = f'sudo iptables -I FIREWALL {opt.pos} -s {opt.src_ip}/{opt.src_netmask} '
            firewall_rule += f'-d {opt.dst_ip}/{opt.dst_netmask} -j {opt.action}'

        elif (opt.protocol == 'icmp'):
            firewall_rule  = f'sudo iptables -I FIREWALL {opt.pos} -p icmp -s {opt.src_ip}/{opt.src_netmask} '
            firewall_rule += f'-d {opt.dst_ip}/{opt.dst_netmask} -j {opt.action}'

        elif (opt.protocol in {'tcp', 'udp'}):
            firewall_rule  = f'sudo iptables -I FIREWALL {opt.pos} -p {opt.protocol} -s {opt.src_ip}/{opt.src_netmask} '
            firewall_rule += f'-d {opt.dst_ip}/{opt.dst_netmask} --dport {opt.dst_port} -j {opt.action}'

        if (firewall_rule):
            run(firewall_rule, shell=True)

    def delete_rule(self, fw_rule, *, chain):
        run(f'sudo iptables -D {chain} {fw_rule}', shell=True)

    def add_nat(self, protocol, dst_port, host_ip, host_port):
        nat_rule, nat_allow = None, None

        if (protocol == 'icmp'):
            nat_rule = [f'sudo iptables -t nat -I NAT -i {self._wan_int} ',
                f'-p {protocol} -j DNAT --to-destination {host_ip}']

            nat_allow = [f'sudo iptables -I NAT -i {self._wan_int} ',
                f'-p {protocol} -j ACCEPT']

        else:
            nat_rule = [f'sudo iptables -t nat -I NAT -i {self._wan_int} -p {protocol} '
                f'--dport {dst_port} -j DNAT --to-destination {host_ip}']

            if (dst_port != host_port):
                nat_rule.append(f':{host_port}')

            nat_allow = [f'sudo iptables -I NAT -i {self._wan_int} '
                f'-p {protocol} --dport {host_port} -j ACCEPT']

        if (nat_rule and nat_allow):
            run(''.join(nat_rule), shell=True)
            run(''.join(nat_allow), shell=True)

    def delete_nat(self, nat_rule):
        run(f'sudo iptables -t nat -D NAT {nat_rule}', shell=True)
        run(f'sudo iptables -D NAT {nat_rule}', shell=True)

    def update_ip_whitelist(self, ip_address, whitelist_type, action):
        action = {True: '-A', False: '-D'}[action]
        if (whitelist_type == 'global'):
            run(f'sudo iptables {action} IP_WHITELIST -s {ip_address} -j ACCEPT', shell=True)

        elif (whitelist_type == 'tor'):
            run(f'sudo iptables -t mangle {action} TOR_WHITELIST -s {ip_address} -j ACCEPT', shell=True)

    @staticmethod
    def update_dns_over_https():
        with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/dns-over-https.ips') as ips_to_block:
            ips_to_block = [sig.strip().split()[0] for sig in ips_to_block.readlines()]

        for ip in ips_to_block:
            run(f'sudo iptables -A DOH -p tcp -d {ip} --dport 443 -j REJECT --reject-with tcp-reset', shell=True)

    @staticmethod
    def clear_dns_over_https():
        run(f'sudo iptables -F DOH', shell=True)

if __name__ == '__main__':
    Defaults().start()
    IPTableManager().commit()
    _err_write('COMMITED IP TABLES')
