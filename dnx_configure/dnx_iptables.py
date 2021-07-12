#!/usr/bin/python3

import os, sys
import fcntl

from subprocess import run, CalledProcessError, DEVNULL
from types import SimpleNamespace as SName

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_file_operations import load_configuration

__all__ = (
    'IPTableManager'
)

_system = os.system

# TODO: reverse inspection order for forward chain.
# PROXY ACCEPT MARK WILL BE AT TOP OF CHAIN | is this some kind of weird optimization?
# 1. internal to wan ip proxy
#    - source zone/ip/port to dst zone/ip/port
#       a. deny, drop packet
#       b. accept, forward packet
#       c. ip proxy, send to ip proxy queue, if no policy vio mark proxy accept, then repeat
class _Defaults:
    '''class containing methods to build default iptable rulesets.'''

    def __init__(self, interfaces):

        for zone, intf in interfaces.items():
            setattr(self, f'_{zone}_int', intf)

   # calling all methods in the class dict.
    @classmethod
    def load(cls, interfaces):
        # initializing instance of self Class. this is to allow caller to not have to initialize class instance.
        self = cls(interfaces)
        for n, f in cls.__dict__.items():
            if '__' not in n and n != 'load':
                try:
                    f(self)
                except Exception as E:
                    write_log(E)

    def get_settings(self):
        dnx_settings = load_configuration('config')['settings']

        self._lan_int = dnx_settings['interfaces']['lan']['ident']
        self._wan_int = dnx_settings['interfaces']['wan']['ident']

        self.custom_filter_chains = ['GLOBAL_INTERFACE', 'WAN_INTERFACE', 'LAN_INTERFACE', 'DMZ_INTERFACE', 'NAT', 'DOH']
        self.custom_nat_chains = ['DSTNAT', 'SRCNAT']

    def create_new_chains(self):
        for chain in self.custom_filter_chains:
            run(f'iptables -N {chain}', shell=True) # Creating Custom Chains for uses

        for chain in self.custom_nat_chains:
            run(f'iptables -t nat -N {chain}', shell=True)

        run(' iptables -t mangle -N IPS', shell=True) # for DDOS prevention
        # run(' iptables -t nat -N NAT', shell=True) # wan to dmz nat rules (shouldnt need since rules will be put in firewall chain)

    def prerouting_set(self):
        # run(' iptables -t nat -A PREROUTING -j NAT', shell=True) # User DNATS insert into here
        run(' iptables -t mangle -A PREROUTING -j IPS', shell=True) # IPS rules insert into here

    def mangle_forward_set(self):
        run(f'iptables -t mangle -A INPUT -i {self._wan_int} -j MARK --set-mark {SEND_TO_IPS}', shell=True) # wan > closed port/ips

        # this will mark all packets to be inspected by ip proxy and allow it to pass packet on to other rules
        run(f'iptables -t mangle -A FORWARD -i {self._lan_int} -j MARK --set-mark {LAN_IN}', shell=True) # lan > any
        run(f'iptables -t mangle -A FORWARD -i {self._wan_int} -j MARK --set-mark {WAN_IN}', shell=True) # wan > any
        run(f'iptables -t mangle -A FORWARD -i {self._dmz_int} -j MARK --set-mark {DMZ_IN}', shell=True) # dmz > any # pylint: disable=no-member

    def main_forward_set(self):
        run('iptables -P FORWARD DROP', shell=True) # Default DROP

        # TODO: figure out how this will be handled with multiple local interfaces.
        # HTTPS Proxy (JA3 only) | NOTE: this is before conntracking, but wont actually match unless connection first gets allowed
            # since its target the 4th and 5th packet in the stream.
        # run(f'iptables -A FORWARD -i {self._lan_int} -p tcp -m tcp --dport 443 -m connbytes --connbytes 4:4 '
        #     '--connbytes-mode packets --connbytes-dir both -j NFQUEUE --queue-num 3', shell=True)
        # run(f'iptables -A FORWARD -i {self._wan_int} -p tcp -m tcp --sport 443 -m connbytes --connbytes 5:5 '
        #     '--connbytes-mode packets --connbytes-dir both -j NFQUEUE --queue-num 3', shell=True)

        # tracking connection state for return traffic from WAN back to inside
        run('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', shell=True)

        # standard blocking for unwanted DNS protocol/ports to help prevent proxy bypass (all interal zones)
        run(f'iptables -A FORWARD ! -i {self._wan_int} -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable', shell=True) # Block External DNS over TLS Queries UDP (Public Resolver)
        run(f'iptables -A FORWARD ! -i {self._wan_int} -p tcp --dport 853 -j REJECT --reject-with tcp-reset', shell=True) # Block External DNS over TLS Queries TCP (Public Resolver)
        run(f'iptables -A FORWARD ! -i {self._wan_int} -p tcp --dport  53 -j REJECT --reject-with tcp-reset', shell=True) # Block External DNS Queries TCP (Public Resolver)
        run(f'iptables -A FORWARD ! -i {self._wan_int} -j DOH', shell=True)

        # TODO: ip proxy should inspect icmp to prevent blocked hosts from probing with icmp. currently the ips will check
        #   for icmp flood. icmp is block by default inbound, but can be allowed by the user in the FIREWALL chain. if that happens,
        #   we want to make sure the security modules vet the packet first like the other two protocols.
        #       1. if blocked host detected
        #           a. if INBOUND and icmp type 8, tag IP_PROXY_DROP then forward
        #               alt: if not type 8, we can silently drop in the ip proxy
        #           b. if OUTBOUND, silently drop in ip proxy
        #       2. if not blocked host detected
        #           a. if INBOUND and icmp type 8, tag SEND_TO_IPS
        #           b. if OUTBOUND, SEND_TO_FIREWALL (can be controlled by user ip tables)
        #
        # run(f'iptables -A FORWARD -i {self._lan_int} -p icmp -j ACCEPT', shell=True) # ALLOW ICMP OUTBOUND
        for zone in [LAN_IN, WAN_IN, DMZ_IN]:
            run(f'iptables -A FORWARD -p tcp -m mark --mark {zone} -j NFQUEUE --queue-num 1', shell=True) # ip proxy TCP
            run(f'iptables -A FORWARD -p udp -m mark --mark {zone} -j NFQUEUE --queue-num 1', shell=True) # ip proxy UDP
            run(f'iptables -A FORWARD -p icmp -m mark --mark {zone} -j NFQUEUE --queue-num 1', shell=True) # ip proxy ICMP

        # ip proxy drop, but allowing ips to inspect for ddos
        run(f'iptables -A FORWARD -m mark --mark {IP_PROXY_DROP} -j NFQUEUE --queue-num 2', shell=True) # IPS inspect on ip proxy drop

        # IPS proper
        run(f'iptables -A FORWARD -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2', shell=True) # IPS TCP/UDP
        # this should now be handled by the ip proxy. it will forward to the ips if needed. this was here to fill the gap when icmp
        # was bypassing the ip proxy.
#        run(f'iptables -A FORWARD -p icmp -m icmp --icmp-type 8 -m mark --mark {WAN_IN} -j NFQUEUE --queue-num 2', shell=True) # IPS ICMP - only type 8 will be checked, rest forwaded

        # block WAN > LAN | explicit deny nat into LAN as an extra safety mechanism. NOTE: this should be evaled to see if this should be optional.
        run(f'iptables -A FORWARD -i {self._wan_int} -o {self._lan_int} -m mark --mark {SEND_TO_FIREWALL} -j DROP', shell=True)

        # NOTE: GLOBAL FIREWALL
        run(f'iptables -A FORWARD -m mark --mark {SEND_TO_FIREWALL} -j GLOBAL_INTERFACE', shell=True)

        # ============================================

        # NOTE: WAN INTERFACE FIREWALL
        run(f'iptables -A FORWARD -i {self._wan_int} -m mark --mark {SEND_TO_FIREWALL} -j WAN_INTERFACE', shell=True)

        # ============================================

        # NOTE: LAN INTERFACE FIREWALL
        run(f'iptables -A FORWARD -i {self._lan_int} -m mark --mark {SEND_TO_FIREWALL} -j LAN_INTERFACE', shell=True)

        # IMPORTANT: default allow any outbound. this is to make the firewall plug and play for non power users source.
        # ip network is hardcoded, but may change at a later date abd the setup does not allow user to change this value.
        run(f'iptables -A LAN_INTERFACE -s 192.168.83.0/24 -d 0.0.0.0/0 -j ACCEPT', shell=True)

        # ============================================

        # NOTE: DMZ INTERFACE FIREWALL
        run(f'iptables -A FORWARD -i {self._dmz_int} -m mark --mark {SEND_TO_FIREWALL} -j DMZ_INTERFACE', shell=True) # pylint: disable=no-member

    def main_input_set(self):
        run(' iptables -P INPUT DROP', shell=True) # default DROP
        run(' iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', shell=True) # Tracking connection state for return traffic from WAN back Firewall itself

#        run(' iptables -A INPUT -p tcp --dport 22 -j ACCEPT', shell=True) # NOTE: SSH CONN FOR LAB TESTING
        run(' iptables -A INPUT -p udp -d 127.0.0.53 --dport 53 -j ACCEPT', shell=True) # NOTE: TEMP FOR UBUNTU DNS SERVICE

        # TODO: this should probably be modified for zone functionality, using WAN_ZONE mark. input mangle rule would need adjusting too.
        # required for portscan and ddos protection logic
        run(f'iptables -A INPUT -i {self._wan_int} -p tcp -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2', shell=True)
        run(f'iptables -A INPUT -i {self._wan_int} -p udp -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2', shell=True)
        run(f'iptables -A INPUT -i {self._wan_int} -p icmp -m icmp --icmp-type 8 -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2', shell=True)

        # dnxfirewall firewall services access (all local network interfaces). dhcp, dns, icmp, etc.
        run(f'iptables -A INPUT ! -i {self._wan_int} -p icmp --icmp-type any -j ACCEPT', shell=True) # Allow ICMP to Firewall
        run(f'iptables -A INPUT ! -i {self._wan_int} -s 127.0.0.1/24 -d 127.0.0.1/24 -j ACCEPT', shell=True) # PGRES SQL/ LOCAL SOCKETS
        run(f'iptables -A INPUT ! -i {self._wan_int} -p udp --dport 67 -j ACCEPT', shell=True) # DHCP Server listening port
        run(f'iptables -A INPUT ! -i {self._wan_int} -p udp --dport 53 -j ACCEPT', shell=True) # DNS Query(To firewall DNS Relay) is allowed in,
        run(f'iptables -A INPUT ! -i {self._wan_int} -p tcp --dport 443 -j ACCEPT', shell=True) # Allowing HTTPS to Firewalls Web server (internal only)
        run(f'iptables -A INPUT ! -i {self._wan_int} -p tcp --dport 80 -j ACCEPT', shell=True) # Allowing HTTP to Firewalls Web server (internal only)

    def main_output_set(self):
        run('iptables -P OUTPUT ACCEPT', shell=True) # Default ALLOW

    # TODO: implement commands to check source and dnat changes in nat table. what does this even mean?
    def nat(self):
        # rules to check custom nat chains
        run(f'iptables -t nat -I POSTROUTING -j SRCNAT', shell=True)
        run(f'iptables -t nat -I PREROUTING -j DSTNAT', shell=True)

        run(f'iptables -t nat -A POSTROUTING -o {self._wan_int} -j MASQUERADE', shell=True) # Main masquerade rule. Inside to Outside
        run(f'iptables -t nat -I PREROUTING ! -i {self._wan_int} -p udp --dport 53 -j REDIRECT --to-port 53', shell=True) # internal zones dns redirct into proxy


class IPTableManager:
    ''' This is the IP Table rule adjustment manager. if class is called in as a context manager, all method calls
    must be ran in the context where the class instance itself is returned as the object. Changes as part of a context
    will be automatically saved upon exit of the context, otherwise they will have to be saved manually.
    '''

    __slots__ = (
       '_intf_to_zone', '_zone_to_intf',

        '_iptables_lock_file', '_iptables_lock'
    )

    def __init__(self):
        dnx_intf_settigs = load_configuration('config')['settings']['interfaces']

        self._intf_to_zone = {
            dnx_intf_settigs[zone]['ident']: zone for zone in ['wan', 'lan', 'dmz']
        }

        self._zone_to_intf = {
            zone: dnx_intf_settigs[zone]['ident'] for zone in ['wan', 'lan', 'dmz']
        }

        self._iptables_lock_file = f'{HOME_DIR}/dnx_system/iptables/iptables.lock'

    def __enter__(self):
        self._iptables_lock = open(self._iptables_lock_file, 'r+')
        fcntl.flock(self._iptables_lock, fcntl.LOCK_EX)

        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if (exc_type is None):
            self.commit()

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

    # TODO: think about the duplicate rule check before running this as a safety for creating duplicate rules
    def apply_defaults(self, *, suppress=False):
        ''' convenience function wrapper around the iptable Default class. all iptable default rules will
        be loaded. if used within the context manager (recommended), the iptables lock will be aquired
        before continuing (will block until done). iptable commit will be done on exit.

        NOTE: this method should not be called more than once during system operation or duplicate rules
        will be inserted into iptables.'''

        _Defaults.load(self._zone_to_intf)

        if (not suppress):
            write_log('dnxfirewall iptable defaults applied.')

    def add_rule(self, rule):
        if (rule.protocol == 'any'):
            firewall_rule = (
                f'sudo iptables -I {rule.zone} {rule.position} -s {rule.src_ip}/{rule.src_netmask} '
                f'-d {rule.dst_ip}/{rule.dst_netmask} -j {rule.action}'
            )

        elif (rule.protocol == 'icmp'):
            firewall_rule = (
                f'sudo iptables -I {rule.zone} {rule.position} -p icmp -s {rule.src_ip}/{rule.src_netmask} '
                f'-d {rule.dst_ip}/{rule.dst_netmask} -j {rule.action}'
            )

        elif (rule.protocol in ['tcp', 'udp']):
            firewall_rule = (
                f'sudo iptables -I {rule.zone} {rule.position} -p {rule.protocol} -s {rule.src_ip}/{rule.src_netmask} '
                f'-d {rule.dst_ip}/{rule.dst_netmask} --dport {rule.dst_port} -j {rule.action}'
            )

        run(firewall_rule, shell=True)

    def delete_rule(self, rule):
        run(f'sudo iptables -D {rule.zone} {rule.position}', shell=True)

    def add_nat(self, rule):
        src_interface = self._zone_to_intf[f'{rule.src_zone}']

        # implement dnat into iptables
        if (rule.nat_type == 'DSTNAT'):

            if (rule.protocol == 'icmp'):
                nat_rule = (
                    f'sudo iptables -t nat -I DSTNAT -i {src_interface} '
                    f'-p {rule.protocol} -j DNAT --to-destination {rule.host_ip}'
                )

            else:
                nat_rule = [
                    f'sudo iptables -t nat -I DSTNAT -i {src_interface} ',
                    f'-p {rule.protocol} --dport {rule.dst_port} -j DNAT --to-destination {rule.host_ip}'
                ]

                # inserting destination ip directly following interface argument
                if (rule.dst_ip):
                    nat_rule.insert(1, f'-d {rule.dst_ip} ')

                if (rule.dst_port != rule.host_port):
                    nat_rule.append(f':{rule.host_port}')

                nat_rule = str_join(nat_rule)

        elif (rule.nat_type == 'SRCNAT'):

            nat_rule = (
                'sudo iptables -t nat -I SRCNAT '
                f'-i {src_interface} -o {self._zone_to_intf["wan"]} '
                f'-s {rule.orig_src_ip}  -j SNAT --to-source {rule.new_src_ip}'
            )

        # TODO: make an auto creation firewall rule option

        run(nat_rule, shell=True)

    def delete_nat(self, rule):
        run(f'sudo iptables -t nat -D {rule.nat_type} {rule.position}', shell=True)

    @staticmethod
    # this allows forwarding through system, required for SNAT/MASQUERADE to work.
    def network_forwarding():
        run('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

    @staticmethod
    def block_ipv6():
        run('ip6tables -P INPUT DROP', shell=True)
        run('ip6tables -P FORWARD DROP', shell=True)
        run('ip6tables -P OUTPUT DROP', shell=True)

    @staticmethod
    def purge_proxy_rules(*, table, chain):
        '''removing all rules from the sent in table and chain. this should be used only be called during
        proxy initialization.'''

        run(f'sudo iptables -t {table} -F {chain}', shell=True)

    @staticmethod
    def proxy_add_rule(ip_address, *, table, chain):
        '''inject ip table rules into the sent in table and chain. the ip_address argument will be blocked
        as a source or destination of traffic. both rules are sharing a single os.system call.'''
        _system(
            f'sudo iptables -t {table} -A {chain} -s {ip_address} -j DROP && '
            f'sudo iptables -t {table} -A {chain} -d {ip_address} -j DROP'
        )

        # NOTE: this should be removed one day
        write_log(f'RULE INSERTED: {ip_address} | {fast_time()}')

    @staticmethod
    def proxy_del_rule(ip_address, *, table, chain):
        '''remove ip table rules from sent in table and chain. both rules are sharing a single os.system call.'''
        _system(
            f'sudo iptables -t {table} -D {chain} -s {ip_address} -j DROP && '
            f'sudo iptables -t {table} -D {chain} -d {ip_address} -j DROP'
        )

        # NOTE: this should be removed one day
        write_log(f'RULE REMOVED: {ip_address} | {fast_time()}')

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
    with IPTableManager() as iptables:
        iptables.apply_defaults()
