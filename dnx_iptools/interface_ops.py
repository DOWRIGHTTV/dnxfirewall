#!/usr/bin/env python3

from ipaddress import IPv4Address
from fcntl import ioctl
from socket import socket, inet_aton, if_nameindex, AF_INET, SOCK_DGRAM
from csv import reader as csv_reader

from dnx_gentools.def_constants import ONE_SEC, INTF, fast_sleep
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_iptools.def_structs import fcntl_pack, long_unpack

__all__ = (
    'get_intf_builtin', 'load_interfaces', 'wait_for_interface', 'wait_for_ip',
    'get_masquerade_ip', 'get_mac', 'get_ip_address', 'get_netmask', 'get_arp_table'
)

# NOTE: this may no longer be need even though it was recently overhauled. the inclusion of the exclude
# filter in the load_interfaces() function should be able to replace this function. keep for now just in case.
def get_intf_builtin(zone_name):
    intf_settings = load_configuration('config')['interfaces']

    intf_info = intf_settings['interfaces']['builtins'][zone_name]
    system_interfaces = {v: k for k, v in if_nameindex()[1:]}

    ident = intf_info['ident']
    intf_index = system_interfaces.get(ident, None)
    if (not intf_index):
        raise RuntimeError('failed to determine interface from provided builtin zone.')

    return {intf_index: (intf_info['zone'], ident)}

def load_interfaces(intf_type=INTF.BUILTINS, *, exclude=[]):
    '''
    return list of tuples of specified interface type.

        [(intf_index, zone, ident)]
    '''
    intf_settings = load_configuration('config')['interfaces']

    dnx_interfaces = intf_settings[intf_type.name.lower()]

    # filtering out loopback during dict comprehension
    system_interfaces = {v: k for k, v in if_nameindex()[1:]}

    collected_intfs = []
    if (intf_type is INTF.BUILTINS):

        for intf_name, intf_info in dnx_interfaces.items():

            ident = intf_info['ident']
            zone  = intf_info['zone']
            intf_index = system_interfaces.get(ident)
            if (not intf_index):
                raise RuntimeError('failed to determine associate builtin <> system interfaces.')

            if (intf_name not in exclude):
                collected_intfs.append((intf_index, zone, ident))

    else:
        raise NotImplementedError('only builtin interfaces are currently supported.')

    return collected_intfs

def _is_ready(interface):
    with open(f'/sys/class/net/{interface}/carrier', 'r') as carrier:
        result = int(carrier.read().strip())

    if (result): return True

    return False

# once interface is powered on from cable being plugged in and a remote device on the other end, the loop will break
def wait_for_interface(interface, delay=ONE_SEC):
    '''will wait for interface to show powered on and waiting for network. will sleep for delay length after each check.'''

    while True:
        if _is_ready(interface): break

        fast_sleep(delay)

# once the lan interface ip address is configured after interface is brought online, the loop will break. this will
# allow the server to continue the startup process.
def wait_for_ip(interface):
    '''will wait for interface ip address configuration then return ip address object
    for corresponding ip.'''

    while True:
        ipa = get_ip_address(interface=interface)
        if (ipa): return ipa

        fast_sleep(ONE_SEC)

def get_masquerade_ip(*, dst_ip, packed=False):
    '''return correct source ip address for a particular destination ip address based on routing table.

    return will be bytes if packed is True or an integer otherwise. a zeroed ip will be returned if error.'''

    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((f'{dst_ip}', 0))

    try:
        ip_addr = inet_aton(s.getsockname()[0])
    except:
        return b'\x00'*4 if packed else 0

    else:
        return ip_addr if packed else long_unpack(ip_addr)[0]

    finally:
        s.close()

def get_mac(*, interface):
    '''return raw byte mac address for sent in interface. will return None on OSError.'''

    s = socket(AF_INET, SOCK_DGRAM)
    try:
        return ioctl(s.fileno(), 0x8927,  fcntl_pack(bytes(interface, 'utf-8')))[18:24]
    except OSError:
        return None
    finally:
        s.close()

def get_ip_address(*, interface):
    '''return ip address object for current ip address for sent in interface. will return None on OSError.'''

    s = socket(AF_INET, SOCK_DGRAM)
    try:
        return IPv4Address(
            ioctl(s.fileno(), 0x8915, fcntl_pack(bytes(interface, 'utf-8')))[20:24]
        )
    except OSError:
        return None
    finally:
        s.close()

def get_netmask(*, interface):
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        return IPv4Address(
            ioctl(s.fileno(), 0x891b, fcntl_pack(bytes(interface, 'utf-8')))[20:24]
        )
    except OSError:
        return None
    finally:
        s.close()

def get_arp_table(*, modify=False, host=None):
    '''
    return arp table as dictionary

        {IPv4Address(ip): mac} = get_arp_table(modify=True)

    if modify is set to True, the ":" will be removed from the mac addresses.

    if host is specified, return just the mac address of the host sent in and returns None if no host is present.
    '''

    with open('/proc/net/arp') as arp_table:
        # 'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
        arp_table = list(
            csv_reader(arp_table, skipinitialspace=True, delimiter=' ')
        )

    if (modify):
        arp_table = {IPv4Address(a[0]): a[3].replace(':', '') for a in arp_table[1:]}

    else:
        arp_table = {IPv4Address(a[0]): a[3] for a in arp_table[1:]}

    if (host):
        return arp_table.get(host, None)

    else:
        return arp_table
