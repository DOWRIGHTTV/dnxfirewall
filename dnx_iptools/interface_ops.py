#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
import yaml

from secrets import token_urlsafe
from csv import reader as csv_reader
from fcntl import ioctl
from socket import socket, inet_aton, if_nameindex, AF_INET, SOCK_DGRAM

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, USER, GROUP, fast_sleep, ONE_SEC
from dnx_gentools.def_enums import INTF, CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config, acquire_lock, release_lock

from dnx_iptools.def_structs import fcntl_pack
from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.protocol_tools import btoia

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T

    Intf: TypeAlias = tuple[int, str, int]
    IntfList: TypeAlias = list[Intf]

__all__ = (
    'load_interfaces',  # 'get_intf_builtin',
    'wait_for_interface', 'wait_for_ip',
    'get_mac', 'get_netmask', 'get_ipaddress', 'get_masquerade_ip',
    'get_arp_table'
)

NO_ADDRESS: int = -1

_s: Socket_T = socket(AF_INET, SOCK_DGRAM)
DESCRIPTOR: int = _s.fileno()

# NOTE: this may no longer be needed even though it was recently overhauled. the inclusion of the excluded
# filter in the load_interfaces() function should be able to replace this function. keep for now just in case.
# def get_intf_builtin(zone_name):
#     intf_settings = load_configuration('system', cfg_type='global')
#
#     intf_path = f'interfaces->built-in->{zone_name}'
#     system_interfaces = {v: k for k, v in if_nameindex()[1:]}
#
#     intf_index = system_interfaces.get(intf_settings[f'{intf_path}->ident'], None)
#     if (not intf_index):
#         raise RuntimeError('failed to determine interface from provided built-in zone.')
#
#     return {intf_index: (intf_settings[f'{intf_path}->zone'], intf_settings[f'{intf_path}->ident'])}

def load_interfaces(intf_type: INTF = INTF.BUILTIN, *, exclude: Optional[list] = None) -> IntfList:
    '''return a list of tuples for the specified interface type.

        [(intf_index, zone, ident)]

    the interface index cannot be guaranteed to be the same across system restarts.
    '''
    intf_settings: ConfigChain = load_configuration('system', cfg_type='global')

    dnx_interfaces = intf_settings.get_items(f'interfaces->{intf_type.name.lower()}')

    # filtering out loopback during dict comprehension
    system_interfaces: dict = {v: k for k, v in if_nameindex()[1:]}

    collected_intfs: IntfList = []
    if (intf_type is INTF.BUILTIN):

        for intf, intf_info in dnx_interfaces:

            name:  str = intf_info['name']
            ident: str = intf_info['ident']
            zone:  int = intf_info['zone']

            intf_index: int = system_interfaces.get(ident)
            if (not intf_index):
                raise RuntimeError('failed to associate built-in <> system interfaces.')

            if (not exclude or name not in exclude):
                collected_intfs.append((intf_index, ident, zone))

    else:
        raise NotImplementedError('only built-in interfaces are currently supported.')

    return collected_intfs

# TODO: figure out how we will modify netplan when an interface has been removed. modifying netplan isnt necessary
#  when adding since it will be done when the ip configuration is set. when removing, if we dont modify netplan, the
#  the interface will still be present in the netplan which will tie up the ip address and cause a conflict.

#   the main concern is synchronization. its possible for the system to fails or be shutdown in between the system
#   config being written and netplan being modified. because of that we wouldnt be able to guarantee that the system
#   config and netplan are in sync.

#   i think the best bet here is to remove the interface from netplan and then modify the system config. worst case
#   the user would have to redo the disassociation if the system fails before the system config is written.

#   depending on the ability of sysctl to be able to confirm it successfully ran a command, the interim solution would
#   be to have the user delete the interface from netplan, then initiate a disassociation. this could be in the form
#   of a "remove from netplan" button, then check it is removed from netplan before allowing the user to disassociate.
#       i feel like we could automate this without requiring sysctl to notify it was complete. for example, we could
#       poll the netplan config in a thread until the interface is no longer present or until a timeout is reached.
#       the webui could initiate this in a thread and if netplan was updated then system failed, the user would just
#       have to redo the disassociation as mentioned above. (can mention in the popup that it will run in the bg and
#       a page refresh may be required to see the changes)
def interface_association(intf: str, action: CFG = CFG.ADD) -> None:
    '''adds/removes system interface from dnxfirewall interface slot.

    if add, sets next available extended interface in system configuration to passed in intf string.
    if del, clears extended interface slot in system configuration for passed in intf string.
    '''
    # todo: check interface is removed from netplan config. return error if still present.
    if (action is CFG.DEL):
        pass

    with ConfigurationManager('system', cfg_type='global') as dnx:
        intf_settings = dnx.load_configuration()

        extended_interfaces = intf_settings.get_items('interfaces->extended')

        for slot, interface in extended_interfaces:

            intf_loc = f'interfaces->extended->{slot}'

            # interface identity (eg. ens160) to interface slot
            if (action is CFG.ADD and interface['ident'] is None):

                intf_settings[f'{intf_loc}->ident'] = intf

                break

            # clearing interface slot for the matching interface identity (eg. ens160)
            elif (action is CFG.DEL and interface['ident'] == intf):
                intf_settings[f'{intf_loc}->ident'] = None
                intf_settings[f'{intf_loc}->name'] = None
                intf_settings[f'{intf_loc}->zone'] = None

                break

        dnx.write_configuration(intf_settings.expanded_user_data)

# NOTE: this will only configure the interface as a system entry and does not account for dhcp due to a file lock
# / file sync issue. i would not be able to guarantee that the dhcp server config would be written to disk before
# some kind of failure.
    # side note for dhcp: thinking we will just write the settings in the dhcp server config file the first time the
    # server is enabled or changed on the interface (disabled initially by default). this would only require a basic
    # check of whether interface has been configured, and if not, copy some info over from system config.

    # todo: just putting this here cuz lazy. to add to above, we should prune down the intf info the dhcp server holds
    # in its config to only things that are unique to dhcp. the rest can be pulled from system config. this will prevent
    # storing redundant info that makes dealing with shared state more problematic and not necessary when its trivial
    # to load in config files safely and efficiently.
def configure_interface_labels(intf: config) -> None:
    '''configures the interface with the provided name and zone in system config via ConfigurationManager.
    '''
    with ConfigurationManager('system', cfg_type='global') as dnx:
        intf_settings = dnx.load_configuration()

        intf_loc = f'interfaces->extended->{intf.slot}'

        intf_settings[f'{intf_loc}->name'] = intf.name
        intf_settings[f'{intf_loc}->zone'] = intf.zone

        dnx.write_configuration(intf_settings.expanded_user_data)

def configure_interface_address(intf: config) -> None:
    '''configures the interface with the provided ip address and netmask in netplan via InterfaceManager.
    '''
    with InterfaceManager() as dnx_intf:
        dnx_intf.add_interface(intf.ident, intf.ip_addr, intf.cidr)

def _is_ready(interface: str) -> int:
    try:
        with open(f'/sys/class/net/{interface}/carrier', 'r') as carrier:
            return int(carrier.read().strip())

    except OSError:
        return 0

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


class InterfaceManager:
    '''Class to ensure process safe operations on configuration files.

    This class is written as a context manager and must be used as such. upon calling the context, a file lock will be
    obtained or block until it can acquire the lock and return the class object to the caller.
    '''
    log: LogHandler_T = None
    interface_lock_file: ConfigLock = f'{HOME_DIR}/dnx_profile/data/interfaces/interfaces.lock'

    dnx_extended_path: str = '/etc/netplan/02-dnx-interface-extended.yaml'

    cfg_path: str = f'{HOME_DIR}/dnx_profile/data/interfaces'

    __slots__ = (
        '_interface_lock', '_data_written',
        '_temp_file', '_temp_file_path',

        '_ext_intf_netplan'
    )

    @classmethod
    def set_log_reference(cls, ref: LogHandler_T) -> None:
        '''sets logging class reference for configuration manager specific errors.
        '''
        cls.log: LogHandler_T = ref

    def __init__(self) -> None:
        self._data_written = False

    # attempts to acquire lock on system config lock (blocks until acquired), then opens a temporary
    # file which the new configuration will be written to, and finally returns the class object.
    def __enter__(self) -> InterfaceManager:
        self._interface_lock = acquire_lock(self.interface_lock_file)

        # TEMP prefix is to wildcard match any orphaned files for deletion
        self._temp_file_path = f'{self.cfg_path}/TEMP_{token_urlsafe(10)}'
        self._temp_file = open(self._temp_file_path, 'w+')

        # changing file permissions and settings owner to dnx:dnx to not cause permission issues after copy.
        os.chmod(self._temp_file_path, 0o660)
        shutil.chown(self._temp_file_path, user=USER, group=GROUP)

        self.log.debug('Network interface configuration lock acquired.')

        with open('/etc/netplan/02-dnx-interface-extended.yaml') as f:
            self._ext_intf_netplan: dict = yaml.load(f.read(), Loader=yaml.Loader)

        return self

    # if no exception was raised and data was written, the netplan extended intf file will be replaced by the temp file.
    # if an exception is raised, the temporary file will be deleted. the file lock will be released upon exiting.
    def __exit__(self, exc_type, exc_val, traceback) -> bool:

        if (self._data_written):
            yaml.dump(self._ext_intf_netplan, stream=self._temp_file, Dumper=yaml.Dumper)

            self._temp_file.close()

            if (exc_type is None):
                os.replace(self._temp_file_path, self.dnx_extended_path)

            else:
                os.unlink(self._temp_file_path)

        # releasing lock for purposes specified in flock(1) man page under -u (unlock) + close file.
        release_lock(self._interface_lock)

        self.log.debug('Network interface configuration lock released.')

        if (exc_type is None):
            return True

    def add_interface(self, intf: str, ip: str, cidr: str) -> None:
        '''adds interface to extended network configuration file (netplan).

        add operation can also be used to update an existing interfaces.
        '''
        self._ext_intf_netplan['network']['ethernets'][intf] = {
            'optional': 'yes',
            'addresses': [f'{ip}/{cidr}']
        }

        self._data_written = True

    def remove_interface(self, intf: str) -> None:
        '''remove interface from extended network configuration file (netplan).

        attempting to remove a non-existent interface will result in a no op.
        '''
        if self._ext_intf_netplan['network']['ethernets'].pop(intf, None):
            self._data_written = True

