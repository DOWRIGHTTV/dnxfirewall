#!/usr/bin/env python3

import time
import socket

from csv import read as csv_reader
from ipaddress import IPv4Address
from fcntl import ioctl
from socket import socket, inet_aton, AF_INET, SOCK_DGRAM

from dnx_sysmods.configure.def_constants import ONE_SEC
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_iptools.def_structs import fcntl_pack

__all__ = (
    'get_intf', 'wait_for_interface', 'wait_for_ip',
    'get_src_ip', 'get_mac', 'get_ip_address',
    'get_netmask', 'get_arp_table'
)

def get_intf(intf):
    settings = load_configuration('config')

    return settings['interfaces'][intf]['ident']

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

        time.sleep(delay)

# once the lan interface ip address is configured after interface is brought online, the loop will break. this will allow
# the server to continue the startup process.
def wait_for_ip(interface):
    '''will wait for interface ip address configuration then return ip address object
    for corresponding ip.'''

    while True:
        ipa = get_ip_address(interface=interface)
        if (ipa): return ipa

        time.sleep(ONE_SEC)

def get_src_ip(*, dst_ip, packed=False):
    '''return correct source ip address for a particular destination ip address based on routing table.

    return will be bytes if packed is True or an ipv4address object otherwise. a zerod ip will be returned if error.'''

    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((f'{dst_ip}', 0))
    if (packed):
        try:
            return inet_aton(s.getsockname()[0])
        except:
            return b'\x00'*4
        finally:
            s.close()

    else:
        try:
            return IPv4Address(s.getsockname()[0])
        except:
            return IPv4Address('0.0.0.0')
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
    '''return arp table as dictionary

        {IPv4Address(ip): mac} = get_arp_table(modify=True)

    if modify is set to True, the ":" will be removed from the mac addresses.

    if host is specified, return just the mac address of the host sent in and returns None if no host is present.
    '''

    with open('/proc/net/arp') as arp_table:
        #'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
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
