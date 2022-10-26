#!/usr/bin/env python3

from __future__ import annotations

from csv import reader as csv_reader
from fcntl import ioctl
from socket import socket, inet_aton, if_nameindex, AF_INET, SOCK_DGRAM

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import fast_sleep, ONE_SEC
from dnx_gentools.def_enums import INTF
from dnx_gentools.file_operations import load_configuration

from dnx_iptools.def_structs import fcntl_pack, long_unpack
from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.protocol_tools import btoia

__all__ = (
    'get_intf_builtin', 'load_interfaces',
    'wait_for_interface', 'wait_for_ip',
    'get_mac', 'get_netmask', 'get_ipaddress', 'get_masquerade_ip',
    'get_arp_table'
)

NO_ADDRESS: int = -1

_s: Socket = socket(AF_INET, SOCK_DGRAM)
DESCRIPTOR: int = _s.fileno()

# NOTE: this may no longer be needed even though it was recently overhauled. the inclusion of the excluded
# filter in the load_interfaces() function should be able to replace this function. keep for now just in case.
def get_intf_builtin(zone_name):
    intf_settings = load_configuration('system', cfg_type='global')

    intf_path = f'interfaces->builtin->{zone_name}'
    system_interfaces = {v: k for k, v in if_nameindex()[1:]}

    intf_index = system_interfaces.get(intf_settings[f'{intf_path}->ident'], None)
    if (not intf_index):
        raise RuntimeError('failed to determine interface from provided builtin zone.')

    return {intf_index: (intf_settings[f'{intf_path}->zone'], intf_settings[f'{intf_path}->ident'])}

def load_interfaces(intf_type: INTF = INTF.BUILTINS, *, exclude: list = []) -> list[tuple[int, int, str]]:
    '''return a list of tuples for the specified interface type.

        [(intf_index, zone, ident)]
    '''
    intf_settings: ConfigChain = load_configuration('system', cfg_type='global')

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

def _is_ready(interface: str) -> int:
    with open(f'/sys/class/net/{interface}/carrier', 'r') as carrier:
        return int(carrier.read().strip())

def wait_for_interface(interface: str, delay: int = ONE_SEC) -> None:
    '''wait for the specified interface to show power with waiting for network state.

    blocks until interface is up.
    sleeps for delay length after each check.
    '''
    while True:
        if _is_ready(interface):
            break

        fast_sleep(delay)

# once the lan interface ip address is configured after interface is brought online, the loop will break. this will
# allow the server to continue the startup process.
def wait_for_ip(interface: str) -> int:
    '''wait for the ip address configuration of the specified interface.

     return will be the integer value of the corresponding ip.
    '''
    while True:
        ipa = get_ipaddress(interface=interface)
        if (ipa != NO_ADDRESS):
            return ipa

        fast_sleep(ONE_SEC)

def get_masquerade_ip(*, dst_ip: int, packed: bool = False) -> Union[bytes, int]:
    '''return correct source ip address for a destination ip address based on the routing table.

    return will be bytes if packed is True or an integer otherwise.
    a zeroed ip will be returned if error.
    '''
    # TODO: see if we can reuse DESCRIPTOR socket
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((itoip(dst_ip), 0))

    try:
        ip_addr = s.getsockname()[0]
    except:
        return b'\x00'*4 if packed else 0

    else:
        return inet_aton(ip_addr) if packed else ip_addr

    finally:
        s.close()

def get_mac(*, interface: str) -> Optional[bytes]:
    '''return raw byte mac address for sent in interface. return None on OSError.
    '''
    try:
        return ioctl(DESCRIPTOR, 0x8927,  fcntl_pack(bytes(interface, 'utf-8')))[18:24]
    except OSError:
        return None

def get_mac_string(*, interface: str) -> Optional[str]:
    '''return standard string representation of mac address for sent in interface. return None on OSError.
    '''
    try:
        mac_addr = ioctl(DESCRIPTOR, 0x8927,  fcntl_pack(bytes(interface, 'utf-8')))[18:24]
    except OSError:
        return None

    else:
        mac_hex = mac_addr.hex()
        return ':'.join([mac_hex[i:i + 2] for i in range(0, 12, 2)])


def get_ipaddress(*, interface: str) -> int:
    '''return integer value for the passed in interfaces current ip address.

    returns -1 on error.
    '''
    try:
        return btoia(ioctl(DESCRIPTOR, 0x8915, fcntl_pack(bytes(interface, 'utf-8')))[20:24])
    except OSError:
        return -1

def get_netmask(*, interface: str) -> int:
    '''return integer value for the passed in interfaces current netmask.

    returns -1 on error.
    '''
    try:
        return btoia(ioctl(DESCRIPTOR, 0x891b, fcntl_pack(bytes(interface, 'utf-8')))[20:24])
    except OSError:
        return -1

def get_arp_table(*, modify: bool = False, host: Optional[str] = None) -> Union[dict, str]:
    '''return arp table as dictionary

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
