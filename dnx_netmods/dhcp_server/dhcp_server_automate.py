#!/usr/bin/env python3

from __future__ import annotations

import threading
import socket

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import DHCP
from dnx_gentools.def_namedtuples import DHCP_INTERFACE, DHCP_OPTION, RECORD_CONTAINER, DHCP_RECORD, Item
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, cfg_read_poller
from dnx_gentools.standard_tools import ConfigurationMixinBase, dnx_queue, looper

from dnx_iptools.cprotocol_tools import iptoi

from dnx_routines.logging.log_client import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


__all__ = (
    'ServerConfiguration', 'Leases'
)

# required when using configuration manager.
ConfigurationManager.set_log_reference(Log)

NULL_LEASE = DHCP_RECORD(DHCP.AVAILABLE, 0, '', '')
RESERVED_LEASE = DHCP_RECORD(DHCP.RESERVATION, -1, '', '')


class ServerConfiguration(ConfigurationMixinBase):
    interfaces:   dict[str, DHCP_INTERFACE] = {}
    valid_idents: set[int] = {0}

    # initializing the lease table dictionary and providing a reference to the reservations dict
    leases: Leases

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''tasks required by the DHCP server.

        return thread information to be run.
        '''
        self.intf_enable  = self.module_class.enable
        self.intf_disable = self.module_class.disable

        self.__class__.leases = Leases()
        self._load_interfaces()

        threads = (
            (self._get_settings, ()),
            (self._get_server_options, ()),
            (self._get_reservations, ())
        )

        return Log, threads, 3

    @cfg_read_poller('dhcp_server', cfg_type='global')
    def _get_settings(self, dhcp_settings: ConfigChain) -> None:

        # updating user configuration items per interface in memory.
        for intf in dhcp_settings.get_values('interfaces->builtin'):

            # NOTE ex. ident: eth0, lo, enp0s3
            identity: str = intf['ident']

            # filtering out interfaces not configured at install time
            if (identity is None):
                continue

            enabled:  int = intf['enabled']
            check_ip: int = intf['icmp_check']

            # en_check is both enabled and icmp check
            sock_fd = self.interfaces[identity].socket[1]
            if (enabled and not self.interfaces[identity].en_check[0]):
                self.intf_enable(sock_fd, identity)

            elif (not enabled and self.interfaces[identity].en_check[0]):
                self.intf_disable(sock_fd, identity)

            # identity will be kept in settings just in case, though they key is the identity also.
            self.interfaces[identity].en_check[:] = [enabled, check_ip]

        self._initialize.done()

    @cfg_read_poller('dhcp_server', cfg_type='global')
    def _get_server_options(self, dhcp_settings: ConfigChain) -> None:

        builtin_intfs: list[Item] = dhcp_settings.get_items('interfaces->builtin')

        # will wait for 2 threads to check in before running code.
        # allows the necessary settings to be initialized on startup before this thread continues.
        self._initialize.wait_in_line(wait_for=2)

        for intf, settings in builtin_intfs:

            # converting json keys to python ints
            configured_options: dict[int, DHCP_OPTION] = {
                int(k): DHCP_OPTION(int(k), *v) for k, v in settings['options'].items()
            }

            active_options: dict[int, DHCP_OPTION] = self.interfaces[settings['ident']].options

            # if the active interface options have not changed, we can pass
            if (configured_options == active_options):
                continue

            # inplace swap of options and only acting on a single key at a time to mitigate issues with shared state
            # over multiple threads
            options_to_remove: list[int] = [opt for opt in active_options if opt not in configured_options]
            for option in options_to_remove:

                active_options.pop(option)

            for option, value in configured_options.items():
                active_options[option] = value

        self._initialize.done()

    # loading the user configured dhcp reservations from json config file into memory.
    @cfg_read_poller('dhcp_server', cfg_type='global')
    def _get_reservations(self, dhcp_settings: ConfigChain) -> None:

        # dict comp that retains all infos of stored json data, but converts ip address into objects
        self.leases.reservations = {
            mac: info['ip_address'] for mac, info in dhcp_settings.get_items('reservations')
        }

        # loading all reserved ip addresses into a set to be referenced below
        reserved_ips = self.leases.get_reserved_ips()

        # sets reserved ip address lease records to available if they are no longer configured. not worried about thread
        # safety here since we are only removing explicitly configured reservations and pop() method.
        for ip, record in self.leases.items():

            # cross-referencing ip reservation list with current lease table to reset any leased record placeholders
            # for the reserved ip.
            if (record.rtype is DHCP.RESERVATION and ip not in reserved_ips):
                self.leases.pop(ip, None)

        self._initialize.done()

    def _load_interfaces(self) -> None:
        fw_intf: dict[str, dict] = load_configuration('system', cfg_type='global').get_dict('interfaces->builtin')

        dhcp_intfs: list[Item] = load_configuration('dhcp_server', cfg_type='global').get_items('interfaces->builtin')

        # interface friendly name e.g. wan
        for intf_name, settings in dhcp_intfs:

            identity: str = settings['ident']
            # enabled:  int = settings['enabled']
            # check_ip: int = settings['icmp_check']
            ip_range: list = settings['lease_range']

            # converting interface ip address to an integer and associating it with the intf ident in the config.
            intf_ip = iptoi(fw_intf[intf_name]['ip'])
            intf_netmask = iptoi(fw_intf[intf_name]['netmask'])

            # this is providing the first portion of creating a socket. this will allow the system to create the socket
            # store the file descriptor id, and then bind when ready per normal registration logic.
            l_sock: Socket_T = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock_refs = (l_sock, l_sock.fileno())

            # updating the interface information in server class settings object. these will never change while the
            # server is running. (the server must be restarted for interface ipaddress changes)
            self.interfaces[identity] = DHCP_INTERFACE(
                [0, 0], intf_ip, intf_ip & intf_netmask, intf_netmask, ip_range, sock_refs, {}
            )

            # local server ips added to filter responses to other servers within the broadcast domain.
            self.valid_idents.add(intf_ip)

        Log.debug(f'loaded interfaces from file: {self.interfaces}')


class Leases(dict):
    _setup: ClassVar[bool] = False

    __slots__ = (
        'reservations',
    )

    def __init__(self):
        super().__init__()

        self.reservations: dict[str, int] = {}

        self._load_leases()

        threading.Thread(target=self._storage_queue).start()
        threading.Thread(target=self._lease_table_cleanup).start()

    def __getitem__(self, key: int) -> DHCP_RECORD:
        '''return DHCP record stored with the associated ip address.

        prior to search, an ip address reservation lookup will be done and a _RESERVED_LEASE notice will be returned.
        '''
        if (key in self.reservations.values()):
            return RESERVED_LEASE

        return dict.__getitem__(self, key)

    # if missing will return an available record
    def __missing__(self, key: int) -> DHCP_RECORD:
        return NULL_LEASE

    def modify(self, ip: int, record: DHCP_RECORD = NULL_LEASE, clean_up: bool = False) -> None:
        '''modifies a record in the lease table.

        this will automatically ensure changes get written to disk. if no record is provided, a dhcp release is assumed.

        clean_up=True should only be used by an automated system that handles mutating the lease dict themselves.
        '''
        # added change to storage queue for lease persistence across device/process shutdowns.
        # will only store active leases. offers will be treated as volatile and not persist restarts
        if (record.rtype is not DHCP.OFFERED):
            self._storage_queue.add(RECORD_CONTAINER(ip, record))

        if (not clean_up):
            self[ip] = record

    def get_reserved_ips(self) -> set:
        '''return copy of reserved ip addresses as a set.
        '''
        return set(self.reservations.values())

    @dnx_queue(Log, name='Leases')
    # store lease table changes to disk. if the record is not present, it indicates the record needs to be removed.
    def _storage_queue(self, dhcp_lease: RECORD_CONTAINER):
        with ConfigurationManager('dhcp_server', ext='lease', cfg_type='global') as dnx:
            dhcp_settings: ConfigChain = dnx.load_configuration(strict=False)

            # converting ip address ints to strings since they will be json keys

            dhcp_usr_settings = dhcp_settings.expanded_user_data
            if (dhcp_lease.record is NULL_LEASE):
                dhcp_usr_settings.pop(f'{dhcp_lease.ip}', None)

            else:
                dhcp_usr_settings[f'{dhcp_lease.ip}'] = dhcp_lease.record

            dnx.write_configuration(dhcp_usr_settings)

    @looper(ONE_MIN)
    # TODO: TEST RESERVATIONS GET CLEANED UP
    def _lease_table_cleanup(self) -> None:

        ip_address: int
        lease: DHCP_RECORD

        # filtering list down to only active leases.
        active_leases = list(self.items())

        for ip_address, lease in active_leases:

            lease_type, lease_time, lease_mac, _ = lease

            # current time - lease time = time elapsed since lease was handed out
            time_elapsed = fast_time() - lease_time

            # ip reservation has been removed from the system
            if (lease_type == DHCP.RESERVATION and lease_mac not in self.reservations):
                self.pop(ip_address)

            # the client did not accept our ip offer
            elif (lease_type == DHCP.OFFERED and time_elapsed > ONE_MIN):
                self.pop(ip_address)

            # ip lease expired normally # NOTE: consider moving this value to a global constant/ make configurable
            elif (time_elapsed >= 86800):
                self.pop(ip_address)

            # unknown condition? maybe log?
            else: continue

            # adding to queue for removal from stored leases on disk. no record notifies job handler to remove vs add.
            # this is only needed to adjust the disk since the iterator handles mutating the lease dict in memory.
            self.modify(ip_address, clean_up=True)

    # loading dhcp leases from json file. only called on startup
    def _load_leases(self) -> None:

        stored_leases: dict[str, list] = load_configuration('dhcp_server', ext='lease', cfg_type='global').get_dict()

        self.update({ip: DHCP_RECORD(*lease_info) for ip, lease_info in stored_leases.items()})
