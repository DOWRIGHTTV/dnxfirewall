#!/usr/bin/env python3

from __future__ import annotations

from csv import reader as csv_reader
from ipaddress import IPv4Address
from fcntl import ioctl
from socket import socket, inet_aton, if_nameindex, AF_INET, SOCK_DGRAM

from dnx_gentools.def_constants import HOME_DIR, INTF, CFG, fast_sleep, ONE_SEC
from dnx_gentools.def_typing import *
from dnx_gentools.file_operations import load_configuration, ConfigurationManager, json_to_yaml

from dnx_iptools.def_structs import fcntl_pack, long_unpack
from dnx_iptools.protocol_tools import int_to_ip

from dnx_system.sys_action import system_action

__all__ = (
    'get_intf_builtin', 'load_interfaces',
    'set_wan_interface', 'set_wan_mac', 'set_wan_ip',
    'wait_for_interface', 'wait_for_ip',
    'get_mac', 'get_netmask', 'get_ip_address', 'get_masquerade_ip',
    'get_arp_table'
)

_s = socket(AF_INET, SOCK_DGRAM)
DESCRIPTOR = _s.fileno()

# NOTE: this may no longer be needed even though it was recently overhauled. the inclusion of the excluded
# filter in the load_interfaces() function should be able to replace this function. keep for now just in case.
def get_intf_builtin(zone_name):
    intf_settings = load_configuration('config')

    intf_path = f'interfaces->builtins->{zone_name}'
    system_interfaces = {v: k for k, v in if_nameindex()[1:]}

    intf_index = system_interfaces.get(intf_settings[f'{intf_path}->ident'], None)
    if (not intf_index):
        raise RuntimeError('failed to determine interface from provided builtin zone.')

    return {intf_index: (intf_settings[f'{intf_path}->zone'], intf_settings[f'{intf_path}->ident'])}

def load_interfaces(intf_type: INTF = INTF.BUILTINS, *, exclude: list = []) -> List[Optional[Tuple[int, int, str]]]:
    '''
    return list of tuples of specified interface type.

        [(intf_index, zone, ident)]
    '''
    intf_settings = load_configuration('config')

    dnx_interfaces = intf_settings.get_items(f'interfaces->{intf_type.name.lower()}')

    # filtering out loopback during dict comprehension
    system_interfaces: dict = {v: k for k, v in if_nameindex()[1:]}

    collected_intfs: list = []
    if (intf_type is INTF.BUILTINS):

        for intf_name, intf_info in dnx_interfaces:

            ident: str = intf_info['ident']
            zone:  int = intf_info['zone']
            intf_index: int = system_interfaces.get(ident)
            if (not intf_index):
                raise RuntimeError('failed to associate builtin <> system interfaces.')

            if (intf_name not in exclude):
                collected_intfs.append((intf_index, zone, ident))

    else:
        raise NotImplementedError('only builtin interfaces are currently supported.')

    return collected_intfs

# TODO: fix this later
def set_wan_interface(intf_type: INTF = INTF.DHCP):
    '''
    Change wan interface state between static or dhcp.

    1. Configure interface type
    2. Create netplan config from template
    3. Move file to /etc/netplan

    This does not configure an ip address of the interface when setting to static. see: set_wan_ip()
    '''

    # changing dhcp status of wan interface in config file.
    with ConfigurationManager('config') as dnx:
        interface_settings = dnx.load_configuration()

        wan = interface_settings['interfaces']['builtins']['wan']

        wan['state'] = intf_type

        dnx.write_configuration(interface_settings)

        # template used to generate yaml file with user configured fields
        intf_template = load_configuration('intf_config', filepath='dnx_system/interfaces')

        # setting for static. removing dhcp4 and dhcp_overrides keys, then adding addresses with empty list
        # NOTE: the ip configuration will unlock after the switch and can then be updated
        if (intf_type is INTF.STATIC):
            wan_intf = intf_template['network']['ethernets'][wan['ident']]

            wan_intf.pop('dhcp4')
            wan_intf.pop('dhcp4-overrides')

            # initializing static, but not configuring an ip address
            wan_intf['addresses'] = '[]'

        # grabbing configured dns servers
        dns_server_settings = load_configuration('dns_server')['resolvers']

        dns1 = dns_server_settings['primary']['ip_address']
        dns2 = dns_server_settings['secondary']['ip_address']

        # dns server replacement in template required for static or dhcp
        converted_config = json_to_yaml(intf_template)
        converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

        # writing file into dnx_system folder due to limited permissions by the front end. netplan and the specific
        # mv args are configured as sudo/no-pass to get the config to netplan and it applied without a restart.
        with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
            dnx_intfs.write(converted_config)

        cmd_args = ['{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
        system_action(module='webui', command='os.replace', args=cmd_args)
        system_action(module='webui', command='netplan apply', args='')

# TODO: fix this later
def set_wan_mac(action: CFG, mac_address: Optional[str] = None):
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        wan_settings = dnx_settings['interfaces']['builtins']['wan']

        new_mac = mac_address if action is CFG.ADD else wan_settings['default_mac']

        wan_int = wan_settings['ident']
        # iterating over the necessary command args, then sending over local socket
        # for control service to issue the commands
        args = [f'{wan_int} down', f'{wan_int} hw ether {new_mac}', f'{wan_int} up']
        for arg in args:

            system_action(module='webui', command='ifconfig', args=arg)

        wan_settings['configured_mac'] = mac_address

        dnx.write_configuration(dnx_settings)

# TODO: fix this later
def set_wan_ip(wan_ip_settings: dict):
    '''
    Modify configured WAN interface IP address.

    1. Loads configured DNS servers
    2. Loads wan interface identity
    3. Create netplan config from template
    4. Move file to /etc/netplan
    '''

    wan_int = load_configuration('config')['interfaces']['builtins']['wan']['ident']

    # grabbing configured dns servers
    dns_server_settings = load_configuration('dns_server')['resolvers']

    dns1 = dns_server_settings['primary']['ip_address']
    dns2 = dns_server_settings['secondary']['ip_address']

    intf_template = load_configuration('intf_config', filepath='dnx_system/interfaces')

    # removing dhcp4 and dhcp_overrides keys, then adding ip address value
    wan_intf = intf_template['network']['ethernets'][wan_int]

    wan_intf.pop('dhcp4')
    wan_intf.pop('dhcp4-overrides')

    wan_intf['addresses'] = f'[{wan_ip_settings["ip"]}/{wan_ip_settings["cidr"]}]'
    wan_intf['gateway4']  = f'{wan_ip_settings["dfg"]}'

    converted_config = json_to_yaml(intf_template)
    converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

    # writing file into dnx_system folder due to limited permissions by the front end. netplan and the specific
    # mv args are configured as sudo/no-pass to get the config to netplan and it applied without a restart.
    with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
        dnx_intfs.write(converted_config)

    cmd_args = [f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
    system_action(module='webui', command='os.replace', args=cmd_args)
    system_action(module='webui', command='netplan apply')

def _is_ready(interface: str) -> int:
    with open(f'/sys/class/net/{interface}/carrier', 'r') as carrier:
        return int(carrier.read().strip())

# once interface is powered on from cable being plugged in and a remote device on the other end, the loop will break
def wait_for_interface(interface:str , delay: int = ONE_SEC):
    '''waits for interface to show powered on and waiting for network. will sleep for delay length after each check.'''

    while True:
        if _is_ready(interface):
            break

        fast_sleep(delay)

# once the lan interface ip address is configured after interface is brought online, the loop will break. this will
# allow the server to continue the startup process.
def wait_for_ip(interface: str) -> Optional[IPv4Address]:
    '''waits for interface ip address configuration then return ip address object for corresponding ip.'''

    while True:
        ipa = get_ip_address(interface=interface)
        if (ipa):
            return ipa

        fast_sleep(ONE_SEC)

def get_masquerade_ip(*, dst_ip: int, packed: bool = False) -> Union[bytes, int]:
    '''return correct source ip address for a particular destination ip address based on routing table.

    return will be bytes if packed is True or an integer otherwise. a zeroed ip will be returned if error.'''

    # TODO: see if we can reuse DESCRIPTOR socket
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((int_to_ip(dst_ip), 0))

    try:
        ip_addr = inet_aton(s.getsockname()[0])
    except:
        return b'\x00'*4 if packed else 0

    else:
        return ip_addr if packed else long_unpack(ip_addr)[0]

    finally:
        s.close()

def get_mac(*, interface: str) -> Optional[bytes]:
    '''return raw byte mac address for sent in interface. return None on OSError.'''
    try:
        return ioctl(DESCRIPTOR, 0x8927,  fcntl_pack(bytes(interface, 'utf-8')))[18:24]
    except OSError:
        return None

def get_ip_address(*, interface: str) -> Optional[IPv4Address]:
    '''return ip address object for current ip address for sent in interface. return None on OSError.'''
    try:
        return IPv4Address(ioctl(DESCRIPTOR, 0x8915, fcntl_pack(bytes(interface, 'utf-8')))[20:24])
    except OSError:
        return None

def get_netmask(*, interface: str) -> Optional[IPv4Address]:
    try:
        return IPv4Address(ioctl(DESCRIPTOR, 0x891b, fcntl_pack(bytes(interface, 'utf-8')))[20:24])
    except OSError:
        return None

def get_arp_table(*, modify: bool = False, host: Optional[str] = None) -> Union[dict, str]:
    '''
    return arp table as dictionary

        {ip_addr: mac} = get_arp_table(modify=True)

    if modify is set to True, the ":" will be removed from the mac addresses.

    if host is specified, return just the mac address of the host passed in, returning "unknown" if host is not present.
    '''

    with open('/proc/net/arp') as arp_table:
        # 'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
        arp_table = [
            x for x in csv_reader(arp_table, skipinitialspace=True, delimiter=' ')
        ][1:]

    if (modify):
        arp_table = {a[0]: a[3].replace(':', '') for a in arp_table}

    else:
        arp_table = {a[0]: a[3] for a in arp_table}

    if (host):
        return arp_table.get(host, 'unknown')

    else:
        return arp_table
