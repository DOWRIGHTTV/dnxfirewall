#!/usr/bin/python3

import os, sys
import fcntl

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

from dnx_gentools.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.file_operations import load_configuration

__all__ = (
    'IPTablesManager'
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

        self.custom_nat_chains = ['DSTNAT', 'SRCNAT', 'REDIRECT_OVERRIDE']

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

    def create_new_chains(self):
        for chain in self.custom_nat_chains:
            shell(f'iptables -t nat -N {chain}')

        shell('iptables -N MGMT')
        shell('iptables -t raw -N IPS') # ddos prevention rule insertion location

    def default_actions(self):
        shell('iptables -P FORWARD DROP') # Default DROP
        shell('iptables -P INPUT DROP') # default

        # default allow just in case it was changed prior.
        shell('iptables -P OUTPUT ACCEPT')

    def cfirewall_hook(self):
        # standard conntrack permit. cfirewall will deal with all tcp, udp, and icmp packet as a basic ip/protocol
        # filter and as a security module inspection pre preprocessor.

        # FORWARD #
        shell('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')

        shell(f'iptables -A FORWARD -p tcp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        shell(f'iptables -A FORWARD -p udp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        shell(f'iptables -A FORWARD -p icmp -j NFQUEUE --queue-num {Queue.CFIREWALL}')

        # INPUT #
        shell(' iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')

        # user configured services access will be kept as iptables for now. note: the implicit allows like dhcp and dns
        # will be handled by cfirewall from this point on. mark filter to ensure wan doesnt match as extra precaution.
        shell(f'iptables -m mark ! --mark {WAN_IN} -j MGMT ')

        shell(f'iptables -A INPUT -p tcp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        shell(f'iptables -A INPUT -p udp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        shell(f'iptables -A INPUT -p icmp -j NFQUEUE --queue-num {Queue.CFIREWALL}')

    def prefilter_set(self):
        # filtering out broadcast packets to the wan. These can be prevalent if in a double nat scenario and would never
        # be used for anything.
        shell(f'iptables -I INPUT -i {self._wan_int} -m addrtype --dst-type BROADCAST -j DROP') # pylint: disable=no-member

    # TODO: implement commands to check source and dnat changes in nat table. what does this even mean?
    def nat(self):
        shell('iptables -t raw -A PREROUTING -j IPS')  # action to check custom ips chain

        # internal zones dns redirect into proxy
        shell('iptables -t nat -A PREROUTING -j REDIRECT_OVERRIDE')
        # TODO: add config option in dns server settings to define up to 2 internal servers (check for RFC1918) as
        #  internal recursive resolvers. dns requests to the configured servers will be exempt from this redirect. this
        #  will allow all internal zones to have access to a centralized local dns server (like windows dns in an active
        #  directory domain).
        shell(f'iptables -t nat -A PREROUTING -m mark ! --mark {WAN_IN} -p udp --dport 53 -j REDIRECT --to-port 53')

        # user defined chain for dnat
        shell(f'iptables -t nat -A PREROUTING -j DSTNAT')

        # user defined chain for src nat
        shell(f'iptables -t nat -A POSTROUTING -j SRCNAT')

        # implicit masquerade rule for users. lan/dmz > wan
        shell(f'iptables -t nat -A POSTROUTING -o {self._wan_int} -j MASQUERADE') # pylint: disable=no-member


class IPTablesManager:
    ''' This is the IP Table rule adjustment manager. if class is called in as a context manager, all method calls
    must be ran in the context where the class instance itself is returned as the object. Changes as part of a context
    will be automatically saved upon exit of the context, otherwise they will have to be saved manually.
    '''

    __slots__ = (
        '_intf_to_zone', '_zone_to_intf',

        '_iptables_lock_file', '_iptables_lock'
    )

    def __init__(self):
        dnx_intf_settigs = load_configuration('config')['interfaces']['builtins']

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

        shell(f'sudo iptables-save > {HOME_DIR}/dnx_system/iptables/iptables_backup.cnf', check=True)

    def restore(self):
        '''process safe restore of iptable rules in/from backup file.'''

        shell(f'sudo iptables-restore < {HOME_DIR}/dnx_system/iptables/iptables_backup.cnf', check=True)

    # TODO: think about the duplicate rule check before running this as a safety for creating duplicate rules
    def apply_defaults(self, *, suppress=False):
        '''convenience function wrapper around the iptable Default class. all iptable default rules will
        be loaded. if used within the context manager (recommended), the iptables lock will be acquired
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

        shell(firewall_rule, check=True)

    def delete_rule(self, rule):
        shell(f'sudo iptables -D {rule.zone} {rule.position}', check=True)

    def modify_management_access(self, fields):
        '''add or remove management access rule as configured by webui. ports must be a list, even if only one port is needed.'''

        zone = globals()[f'{fields.zone.upper()}_IN']
        action = '-A' if fields.action is CFG.ADD else '-D'

        # icmp/ping rule is one off check.
        if (fields.service_ports == 1):
            shell(f'sudo iptables {action} MGMT -m mark --mark {zone} -p icmp --icmp-type 8 -j ACCEPT', check=True)

            return

        # iterate over ports to make it easier to deal with singular or multiple port cases
        for port in fields.service_ports:

            shell(f'sudo iptables {action} MGMT -m mark --mark {zone} -p tcp --dport {port} -j ACCEPT', check=True)

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

        shell(nat_rule, check=True)

    def delete_nat(self, rule):
        shell(f'sudo iptables -t nat -D {rule.nat_type} {rule.position}', check=True)

    def remove_passive_block(self, host_ip, timestamp):
        shell(f'sudo iptables -t raw -D IPS -s {host_ip} -j DROP -m comment --comment {timestamp}', check=True)

    @staticmethod
    # this allows forwarding through system, required for SNAT/MASQUERADE to work.
    def network_forwarding():
        shell('echo 1 > /proc/sys/net/ipv4/ip_forward')

    @staticmethod
    def block_ipv6():
        shell('ip6tables -P INPUT DROP')
        shell('ip6tables -P FORWARD DROP')
        shell('ip6tables -P OUTPUT DROP')

    @staticmethod
    def purge_proxy_rules(*, table, chain):
        '''removing all rules from the sent in table and chain. this should be used only be called during
        proxy initialization.'''

        shell(f'sudo iptables -t {table} -F {chain}')

    @staticmethod
    def proxy_add_rule(ip_address, timestamp, *, table, chain):
        '''inject iptable rule into the specified table and chain. the ip_address argument will be blocked
        as a source and timestamp will be set as a comment.'''

        comment = f'-m comment --comment {timestamp}'

        _system(f'sudo iptables -t {table} -A {chain} -s {ip_address} -j DROP {comment}')

    @staticmethod
    def proxy_del_rule(ip_address, timestamp, *, table, chain):
        '''remove iptable rule from specified table and chain.'''

        comment = f'-m comment --comment {timestamp}'

        _system(f'sudo iptables -t {table} -D {chain} -s {ip_address} -j DROP {comment}')

    @staticmethod
    def update_dns_over_https():
        with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/dns-over-https.ips') as ips_to_block:
            ips_to_block = [sig.strip().split()[0] for sig in ips_to_block.readlines()]

        for ip in ips_to_block:
            shell(f'sudo iptables -A DOH -p tcp -d {ip} --dport 443 -j REJECT --reject-with tcp-reset')

    @staticmethod
    def clear_dns_over_https():
        shell(f'sudo iptables -F DOH')

if __name__ == '__main__':
    with IPTablesManager() as iptables:
        iptables.apply_defaults()
