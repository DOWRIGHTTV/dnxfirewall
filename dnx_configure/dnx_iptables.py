#!/usr/bin/python3

import os, sys
import fcntl

from subprocess import run, CalledProcessError, DEVNULL
from types import SimpleNamespace as SName

HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_file_operations import load_configuration

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
        dnx_settings = load_configuration('config')

        self._lan_int = dnx_settings['interfaces']['lan']['ident']
        self._wan_int = dnx_settings['interfaces']['wan']['ident']

        self.custom_filter_chains = ['GLOBAL_ZONE', 'WAN_ZONE', 'LAN_ZONE', 'DMZ_ZONE', 'MGMT', 'NAT', 'DOH']
        self.custom_nat_chains = ['DSTNAT', 'SRCNAT', 'REDIRECT_OVERRIDE']

    def create_new_chains(self):
        # creating custom chains for user defined rules
        for chain in self.custom_filter_chains:
            shell(f'iptables -N {chain}')

        for chain in self.custom_nat_chains:
            shell(f'iptables -t nat -N {chain}')

        # NOTE: retaining ips chain in mangle for backwards compatibility or easy switch between the two.
        shell('iptables -t raw -N IPS') # ddos prevention rule insertion location

        shell('iptables -t mangle -N IPS') # ddos prevention rule insertion location

    def prerouting_set(self):
        shell('iptables -t raw -A PREROUTING -j IPS') # action to check custom ips chain

        shell('iptables -t mangle -A PREROUTING -j IPS') # action to check custom ips chain

    def mangle_set(self):
        # zones need mark on input for either dropped packets to wan, or device access from inside.
        shell(f'iptables -t mangle -A INPUT -i {self._wan_int} -j MARK --set-mark {SEND_TO_IPS}') # wan > closed port/ips
        shell(f'iptables -t mangle -A INPUT -i {self._lan_int} -j MARK --set-mark {LAN_IN}')
        shell(f'iptables -t mangle -A INPUT -i {self._dmz_int} -j MARK --set-mark {DMZ_IN}') # pylint: disable=no-member

        # this will mark all packets to be inspected by ip proxy and allow it to pass packet on to other rules
        shell(f'iptables -t mangle -A FORWARD -i {self._lan_int} -j MARK --set-mark {LAN_IN}') # lan > any
        shell(f'iptables -t mangle -A FORWARD -i {self._wan_int} -j MARK --set-mark {WAN_IN}') # wan > any
        shell(f'iptables -t mangle -A FORWARD -i {self._dmz_int} -j MARK --set-mark {DMZ_IN}') # dmz > any # pylint: disable=no-member

    def main_forward_set(self):
        shell('iptables -P FORWARD DROP') # Default DROP

        # TODO: figure out how this will be handled with multiple local interfaces.
        # HTTPS Proxy (JA3 only) | NOTE: this is before conntracking, but wont actually match unless connection first gets allowed
            # since its target the 4th and 5th packet in the stream.
        # shell(f'iptables -A FORWARD -i {self._lan_int} -p tcp -m tcp --dport 443 -m connbytes --connbytes 4:4 '
        #     '--connbytes-mode packets --connbytes-dir both -j NFQUEUE --queue-num 3')
        # shell(f'iptables -A FORWARD -i {self._wan_int} -p tcp -m tcp --sport 443 -m connbytes --connbytes 5:5 '
        #     '--connbytes-mode packets --connbytes-dir both -j NFQUEUE --queue-num 3')

        # tracking connection state for return traffic from WAN back to inside
        shell('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')

        # standard blocking for unwanted DNS protocol/ports to help prevent proxy bypass (all interal zones)
        shell(f'iptables -A FORWARD -m mark ! --mark {WAN_IN} -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable') # Block External DNS over TLS Queries UDP (Public Resolver)
        shell(f'iptables -A FORWARD -m mark ! --mark {WAN_IN} -p tcp --dport 853 -j REJECT --reject-with tcp-reset') # Block External DNS over TLS Queries TCP (Public Resolver)
        shell(f'iptables -A FORWARD -m mark ! --mark {WAN_IN} -p tcp --dport  53 -j REJECT --reject-with tcp-reset') # Block External DNS Queries TCP (Public Resolver)
        shell(f'iptables -A FORWARD -m mark ! --mark {WAN_IN} -j DOH')

        for zone in [LAN_IN, WAN_IN, DMZ_IN]:
            shell(f'iptables -A FORWARD -p tcp -m mark --mark {zone} -j NFQUEUE --queue-num 1') # ip proxy TCP
            shell(f'iptables -A FORWARD -p udp -m mark --mark {zone} -j NFQUEUE --queue-num 1') # ip proxy UDP
            shell(f'iptables -A FORWARD -p icmp -m mark --mark {zone} -j NFQUEUE --queue-num 1') # ip proxy ICMP

        # ip proxy drop, but allowing ips to inspect for ddos
        shell(f'iptables -A FORWARD -m mark --mark {IP_PROXY_DROP} -j NFQUEUE --queue-num 2') # IPS inspect on ip proxy drop

        # IPS proper
        shell(f'iptables -A FORWARD -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2') # IPS TCP/UDP

        # block WAN > LAN | implicit deny nat into LAN for users as an extra safety mechanism. NOTE: this should be evaled to see if this should be optional.
        shell(f'iptables -A FORWARD -o {self._lan_int} -m mark --mark {WAN_ZONE_FIREWALL} -j DROP')

        # NOTE: GLOBAL FIREWALL
        for zone in [LAN_ZONE_FIREWALL, WAN_ZONE_FIREWALL, DMZ_ZONE_FIREWALL]:
            shell(f'iptables -A FORWARD -m mark --mark {zone} -j GLOBAL_ZONE')

        # ============================================

        # NOTE: LAN ZONE FIREWALL
        shell(f'iptables -A FORWARD -m mark --mark {LAN_ZONE_FIREWALL} -j LAN_ZONE')

        # IMPORTANT: default allow any outbound. this is to make the firewall plug and play for non power users.
        # ip network is hardcoded since the setup does this is a dnxfirewall constant, but that may change at a later date.
        shell(f'iptables -A LAN_ZONE -s 192.168.83.0/24 -j ACCEPT')

        # ============================================

        # NOTE: WAN ZONE FIREWALL
        shell(f'iptables -A FORWARD -m mark --mark {WAN_ZONE_FIREWALL} -j WAN_ZONE')

        # ============================================

        # NOTE: DMZ INTERFACE FIREWALL
        shell(f'iptables -A FORWARD -m mark --mark {DMZ_ZONE_FIREWALL} -j DMZ_ZONE')

    def main_input_set(self):
        shell(' iptables -P INPUT DROP') # default DROP
        shell(' iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') # Tracking connection state for return traffic from WAN back Firewall itself

        # filtering out broadcast packets to the wan. These can be prevelent if in a double nat scenario and would never be
        # used for anything. the ips current does checks to filter this. evaluate/see if we can depricate that for this.
        shell(f'iptables -A INPUT -i {self._wan_int} -m addrtype --dst-type BROADCAST -j DROP')

        # local ubuntu DNS proxy
        shell(' iptables -A INPUT -p udp -d 127.0.0.53 --dport 53 -j ACCEPT')

        # local socket communication
        shell(f'iptables -A INPUT -s 127.0.0.1/24 -d 127.0.0.1/24 -j ACCEPT')

        shell(f'iptables -A INPUT -p tcp -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2')
        shell(f'iptables -A INPUT -p udp -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2')
        shell(f'iptables -A INPUT -p icmp -m icmp --icmp-type 8 -m mark --mark {SEND_TO_IPS} -j NFQUEUE --queue-num 2')

        # dnxfirewall services access (all local network interfaces). dhcp, dns, icmp, etc.

        # implicit ICMP allow for users > firewall
        shell(f'iptables -A INPUT -m mark ! --mark {WAN_IN} -p icmp --icmp-type any -j ACCEPT')

        # DHCP discover/request allow
        shell(f'iptables -A INPUT -m mark ! --mark {WAN_IN} -p udp --dport 67 -j ACCEPT')

        # implicit DNS allow for local users
        shell(f'iptables -A INPUT -m mark ! --mark {WAN_IN} -p udp --dport 53 -j ACCEPT')

        # implicit http/s allow to dnx-web for local LAN users
        shell(f'iptables -A INPUT -m mark --mark {LAN_IN} -p tcp --dport 443 -j ACCEPT')
        shell(f'iptables -A INPUT -m mark --mark {LAN_IN} -p tcp --dport 80 -j ACCEPT')

        # additional access to the system is checked here. access set via web ui, but lan > web mgmt will always be allowed above.
        shell(f'iptables -A INPUT -m mark ! --mark {WAN_IN} -j MGMT')

    def main_output_set(self):

        # default allow just incase it was changed prior.
        shell('iptables -P OUTPUT ACCEPT')

    # TODO: implement commands to check source and dnat changes in nat table. what does this even mean?
    def nat(self):
        # internal zones dns redirct into proxy
        shell('iptables -t nat -A PREROUTING -j REDIRECT_OVERRIDE')
        # TODO: add config option in dns server settings to define up to 2 internal servers (check for RFC1918) as internal recursive
        # resolvers. dns requests to the configured servers will be exempt from this redirect. this will allow all internal zones
        # to have access to a centralized local dns server (like windows dns in an active directory domain).
        shell(f'iptables -t nat -A PREROUTING -m mark ! --mark {WAN_IN} -p udp --dport 53 -j REDIRECT --to-port 53')

        # user defined chain for dnat
        shell(f'iptables -t nat -A PREROUTING -j DSTNAT')


        # user defined chain for src nat
        shell(f'iptables -t nat -A POSTROUTING -j SRCNAT')

        # implicit masquerade rule for users. lan/dmz > wan
        shell(f'iptables -t nat -A POSTROUTING -o {self._wan_int} -j MASQUERADE')


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
        dnx_intf_settigs = load_configuration('config')['interfaces']

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

        shell(firewall_rule, check=True)

    def delete_rule(self, rule):
        shell(f'sudo iptables -D {rule.zone} {rule.position}', check=True)

    def modify_management_access(self, fields):
        '''add or remove mangement access rule as configured by webui. ports must be a list, even if only one port is needed.'''

        zone = globals()[f'{fields.zone.upper()}_IN']
        action = '-A' if fields.action is CFG.ADD else '-D'

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

        # NOTE: this should be removed one day
        # write_log(f'RULE INSERTED: {ip_address} | {fast_time()}')

    @staticmethod
    def proxy_del_rule(ip_address, timestamp, *, table, chain):
        '''remove iptable rule from specified table and chain.'''

        comment = f'-m comment --comment {timestamp}'

        _system(f'sudo iptables -t {table} -D {chain} -s {ip_address} -j DROP {comment}')

        # NOTE: this should be removed one day
        # write_log(f'RULE REMOVED: {ip_address} | {fast_time()}')

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
