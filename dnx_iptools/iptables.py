#!/usr/bin/python3

from __future__ import annotations

import fcntl

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import Queue, CFG
from dnx_gentools.file_operations import load_configuration

try:
    from dnx_iptools.cprotocol_tools import itoip
except ImportError:
    pass

__all__ = (
    'IPTablesManager'
)

# aliases for readability
FILE_LOCK = fcntl.flock
EXCLUSIVE_LOCK = fcntl.LOCK_EX
UNLOCK_LOCK = fcntl.LOCK_UN

def ipt_shell(command: str, table: str = 'filter', action: str = '-A') -> None:
    '''iptables wrapper of the dnx shell function.

    provides rule check functionality prior to applying any configured rule.
    '''
    shell(f'iptables -t {table} -C {command} || iptables -t {table} {action} {command}')


class _Defaults:
    '''class containing methods to build default IPTable rule sets.
    '''
    def __init__(self, interfaces: dict):

        self._wan_int: str = ''
        self._lan_int: str = ''
        self._dmz_int: str = ''

        for zone, intf in interfaces.items():
            setattr(self, f'_{zone}_int', intf)

        self.custom_nat_chains: list[str] = ['DSTNAT', 'SRCNAT']

    @classmethod
    # calling all methods in the class dict.
    def load(cls, interfaces: dict) -> None:

        # self init, dynamically calling each method
        self = cls(interfaces)
        for n, f in cls.__dict__.items():
            if '__' not in n and n != 'load':
                try:
                    f(self)
                except Exception as E:
                    console_log(f'{E}')

    def create_new_chains(self) -> None:
        for chain in self.custom_nat_chains:
            ipt_shell(f'{chain}', table='nat', action='-N')

        ipt_shell('IPS', table='raw', action='-N')  # ddos prevention rule insertion location

    def default_actions(self) -> None:
        '''default allow is explicitly set if they were previously changed from default.
        '''
        shell('iptables -P INPUT DROP')
        shell('iptables -P FORWARD DROP')
        shell('iptables -P OUTPUT ACCEPT')

    def cfirewall_hook(self) -> None:
        '''IPTable rules to give cfirewall control of all tcp, udp, and icmp packets.

        cfirewall operates as a basic ip/protocol filter and as a security module inspection pre-preprocessor.

        standard conntrack permit/allow control is left to IPTables for now.
        '''
        # FORWARD
        # NOTE: cfirewall must mark connections with connmark to offload the connection to the kernel, otherwise all
        # packets of the connection must be processed/handled by cfirewall.
        ipt_shell('FORWARD -m connmark --mark 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', action='-I')

        ipt_shell(f'FORWARD -p tcp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        ipt_shell(f'FORWARD -p udp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        ipt_shell(f'FORWARD -p icmp -j NFQUEUE --queue-num {Queue.CFIREWALL}')

        # INPUT
        # NOTE: letting iptables control return traffic for DNX sourced traffic
        ipt_shell('INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', action='-I')

        # allow local socket communications.
        # NOTE: control sock is AF_INET, so we need this rule
        ipt_shell('INPUT -s 127.0.0.0/24 -d 127.0.0.0/24 -j ACCEPT')

        ipt_shell(f'INPUT -p tcp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        ipt_shell(f'INPUT -p udp  -j NFQUEUE --queue-num {Queue.CFIREWALL}')
        ipt_shell(f'INPUT -p icmp -j NFQUEUE --queue-num {Queue.CFIREWALL}')

    def prefilter_set(self) -> None:
        # filtering out broadcast packets to the wan.
        # These can be prevalent if in a double nat scenario and would never be used for anything.
        ipt_shell(f'INPUT -i {self._wan_int} -m addrtype --dst-type BROADCAST -j DROP', action='-I')

    # TODO: implement commands to check source and dnat changes in nat table. what does this even mean?
    def nat(self) -> None:
        ipt_shell('PREROUTING -j IPS', table='raw')  # action to check the custom ips chain

        # user defined chain for dnat
        ipt_shell(f'PREROUTING -j DSTNAT', table='nat')

        # user defined chain for src nat
        ipt_shell(f'POSTROUTING -j SRCNAT', table='nat')

        # implicit masquerade rule for users. lan/dmz > wan
        ipt_shell(f'POSTROUTING -o {self._wan_int} -j MASQUERADE', table='nat')


class IPTablesManager:
    '''This is the IP Tables rule manager.

    if class is called in as a context manager, all method calls must be run in the context where the class instance
    itself is returned as the object.

    Changes as part of a context will be automatically saved upon exit of the context, otherwise they will have to be
    saved manually.
    '''
    __slots__ = (
        '_intf_to_zone', '_zone_to_intf',

        '_iptables_lock'
    )

    def __init__(self) -> None:
        interfaces: ConfigChain = load_configuration('system', cfg_type='global')

        builtins = interfaces.get_items('interfaces->builtin')

        self._intf_to_zone: dict[str, int] = {
            info['ident']: zone for zone, info in builtins
        }

        self._zone_to_intf: dict[str, int] = {
            zone: info['ident'] for zone, info in builtins
        }

        self._iptables_lock = open(f'{HOME_DIR}/dnx_profile/iptables/iptables.lock', 'r+')

    def __enter__(self) -> IPTablesManager:
        FILE_LOCK(self._iptables_lock, EXCLUSIVE_LOCK)

        return self

    def __exit__(self, exc_type, exc_val, traceback) -> bool:
        if (exc_type is None):
            self.commit()

        FILE_LOCK(self._iptables_lock, UNLOCK_LOCK)
        self._iptables_lock.close()

        return True

    def commit(self) -> None:
        '''explicit, process safe, call to save iptables to back-up file.

        this is not needed if using the context manager as the commit happens on exit.
        '''
        shell(f'sudo iptables-save > {HOME_DIR}/dnx_profile/iptables/iptables_backup.cnf', check=True)

    def restore(self) -> None:
        '''process safe restore of iptables rules from the system file.
        '''
        shell(f'sudo iptables-restore < {HOME_DIR}/dnx_profile/iptables/iptables_backup.cnf', check=True)

    # TODO: think about the duplicate rule check before running this as a safety for creating duplicate rules
    def apply_defaults(self, *, suppress: bool = False) -> None:
        '''convenience function wrapper around the iptables Default class.

        all iptables default rules will be loaded.
        if used within the context manager (recommended), the iptables lock will be acquired before continuing (will
        block until done) and an iptables commit will be done on exit.

        NOTE: this method should not be called more than once during system operation or duplicate rules will be
        inserted into iptables.
        '''
        _Defaults.load(self._zone_to_intf)

        if (not suppress):
            console_log('dnxfirewall iptable defaults applied.')

    def add_nat(self, rule: config) -> None:
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

        # covering unexpected conditions. this should be redundant to webui input validations, but piece of mind
        else:
            raise ValueError

        # TODO: make an auto creation rules rule option

        shell(nat_rule, check=True)

    def delete_nat(self, rule: config) -> None:
        shell(f'sudo iptables -t nat -D {rule.nat_type} {rule.position}', check=True)

    def remove_passive_block(self, host: int, timestamp: int) -> None:
        shell(f'sudo iptables -t raw -D IPS -s {itoip(host)} -j DROP -m comment --comment {timestamp}', check=True)

    @staticmethod
    # this allows forwarding through system, required for SNAT/MASQUERADE to work.
    def network_forwarding() -> None:
        shell('echo 1 > /proc/sys/net/ipv4/ip_forward')

    @staticmethod
    def block_ipv6() -> None:
        shell('ip6tables -P INPUT DROP')
        shell('ip6tables -P FORWARD DROP')
        shell('ip6tables -P OUTPUT DROP')

    @staticmethod
    def purge_proxy_rules(*, table: str, chain: str) -> None:
        '''removing all rules from the passed in table and chain.

        this should be used only be called during proxy initialization.
        '''
        shell(f'sudo iptables -t {table} -F {chain}')

    @staticmethod
    def proxy_add_rule(ip_address: int, timestamp: int, *, table: str, chain: str) -> None:
        '''inject an iptable rule into the passed in table and chain.

        the ip_address argument will be blocked as a source and timestamp will be set as a comment.
        '''
        comment = f'-m comment --comment {timestamp}'

        shell(f'sudo iptables -t {table} -A {chain} -s {itoip(ip_address)} -j DROP {comment}')

    @staticmethod
    def proxy_del_rule(ip_address: str, timestamp: int, *, table: str, chain: str) -> None:
        '''remove an iptable rule from the passed in table and chain.
        '''
        comment = f'-m comment --comment {timestamp}'

        shell(f'sudo iptables -t {table} -D {chain} -s {ip_address} -j DROP {comment}')

    @staticmethod
    def update_dns_over_https() -> None:
        with open(f'{HOME_DIR}/dnx_profile/signatures/ip_lists/dns_https.ips') as ips_to_block:
            ips_to_block = [sig.strip().split()[0] for sig in ips_to_block.readlines()]

        for ip in ips_to_block:
            shell(f'sudo iptables -A DOH -p tcp -d {ip} --dport 443 -j REJECT --reject-with tcp-reset')

    @staticmethod
    def clear_dns_over_https() -> None:
        shell(f'sudo iptables -F DOH')


def run():
    with IPTablesManager() as iptables:
        iptables.apply_defaults()

# worthless unless we want to implement log handling on direct call.
if (INITIALIZE_MODULE('iptables')):
    pass
