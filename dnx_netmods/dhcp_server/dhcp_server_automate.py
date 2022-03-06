#!/usr/bin/env python3

from __future__ import annotations

import threading

from socket import socket,  AF_INET, SOCK_DGRAM

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import RECORD_CONTAINER, DHCP_RECORD, DHCP_OPTION, Item
from dnx_gentools.def_enums import DHCP
from dnx_gentools.file_operations import load_configuration, cfg_read_poller, ConfigurationManager
from dnx_gentools.standard_tools import looper, dnx_queue, Initialize

from dnx_iptools.cprotocol_tools import iptoi

from dnx_routines.logging.log_client import Log

__all__ = (
    'Configuration', 'Leases'
)

# required when using configuration manager.
ConfigurationManager.set_log_reference(Log)

NULL_LEASE = DHCP_RECORD(DHCP.AVAILABLE, 0, '', '')
RESERVED_LEASE = DHCP_RECORD(DHCP.RESERVATION, -1, '', '')


class Configuration:
    _setup: ClassVar[bool] = False

    __slots__ = (
        'initialize', 'dhcp_server',
    )

    def __init__(self, name: str, server: DHCPServer_T):
        self.initialize = Initialize(Log, name)

        self.dhcp_server: DHCPServer_T = server

    @classmethod
    def setup(cls, server: DHCPServer_T) -> None:
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(server.__name__, server)
        self._load_interfaces()

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_server_options).start()
        threading.Thread(target=self._get_reservations).start()
        self.initialize.wait_for_threads(count=3)

    @cfg_read_poller('dhcp_server')
    def _get_settings(self, cfg_file: str) -> None:
        dhcp_settings: ConfigChain = load_configuration(cfg_file)

        # updating user configuration items per interface in memory.
        for settings in dhcp_settings.get_values('interfaces->builtins'):

            # NOTE ex. ident: eth0, lo, enp0s3
            intf_identity: str = settings['ident']
            enabled: int = settings['enabled']

            # TODO: compare interface status in memory with what is loaded in. if it is different then the setting was
            #  just changed and needs to be acted on. implement register/unregister methods available to external
            #  callers and use them to act on the disable of an interfaces dhcp service. this should also be the most
            #  efficient in that if all listeners are disabled only the automate class will be actively processing on
            #  file changes.
            # NOTE: .get is to cover server startup. do not change. test functionality.
            sock_fd = self.dhcp_server.intf_settings[intf_identity]['fileno']
            if (enabled and not self.dhcp_server.intf_settings[intf_identity].get('enabled', 0)):
                self.dhcp_server.enable(sock_fd, intf_identity)

            elif (not enabled and self.dhcp_server.intf_settings[intf_identity].get('enabled', 1)):
                self.dhcp_server.disable(sock_fd, intf_identity)

            # this prevents options being overridden which are being processed in another thread
            settings.pop('options')

            # identity will be kept in settings just in case, though they key is the identity also.
            self.dhcp_server.intf_settings[intf_identity].update(settings)

        self.initialize.done()

    @cfg_read_poller('dhcp_server')
    def _get_server_options(self, cfg_file: str) -> None:
        dhcp_settings: list[Item] = load_configuration(cfg_file).get_items('interfaces->builtins')

        # will wait for 2 threads to check in before running code. this will allow the necessary settings
        # to be initialized on startup before this thread continues.
        self.initialize.wait_in_line(wait_for=2)

        for intf, settings in dhcp_settings:

            # converting json keys to python ints
            configured_options = {int(k): DHCP_OPTION(int(k), *v) for k, v in settings['options'].items()}

            active_options = self.dhcp_server.intf_settings[settings['ident']]['options']

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

        self.initialize.done()

    # loading the user configured dhcp reservations from json config file into memory.
    @cfg_read_poller('dhcp_server')
    def _get_reservations(self, cfg_file: str) -> None:
        dhcp_settings: ConfigChain = load_configuration(cfg_file)

        # dict comp that retains all infos of stored json data, but converts ip address into objects
        self.dhcp_server.leases.reservations = {
            mac: info['ip_address'] for mac, info in dhcp_settings.get_items('reservations')
        }

        # loading all reserved ip addresses into a set to be referenced below
        reserved_ips: set = self.dhcp_server.leases.get_reserved_ips()

        # sets reserved ip address lease records to available if they are no longer configured. not worried about thread
        # safety here since we are only removing explicitly configured reservations and pop() method.
        dhcp_leases = self.dhcp_server.leases
        for ip, record in dhcp_leases.items():

            # cross-referencing ip reservation list with current lease table to reset any leased record placeholders
            # for the reserved ip.
            if (record.rtype is DHCP.RESERVATION and ip not in reserved_ips):
                dhcp_leases.pop(ip, None)

        self.initialize.done()

    def _load_interfaces(self) -> None:
        fw_intf: dict = load_configuration('system').get_dict('interfaces->builtins')

        dhcp_intfs: list[Item] = load_configuration('dhcp_server').get_items('interfaces->builtins')

        # interface friendly name e.g. wan
        for intf_name, settings in dhcp_intfs:

            intf_ident = settings['ident']

            # converting interface ip address to an integer and associating it with the intf ident in the config.
            intf_ip = iptoi(fw_intf[intf_name]['ip'])
            intf_netmask = iptoi(fw_intf[intf_name]['netmask'])

            # updating the interface information in server class settings object. these will never change while the
            # server is running. (the server must be restarted for interface ipaddress changes)
            self.dhcp_server.intf_settings[intf_ident] = {
                'ip': intf_ip,
                'netid': intf_ip & intf_netmask,
                'netmask': intf_netmask,
                'options': {}
            }

            # local server ips added to filter responses to other servers within the broadcast domain.
            self.dhcp_server.valid_idents.add(intf_ip)

            # initializing fileno key in the intf dict to make assignments easier in later calls.
            self._create_socket(intf_ident)

        Log.debug(f'loaded interfaces from file: {self.dhcp_server.intf_settings}')

    # this is providing the first portion of creating a socket. this will allow the system to create the socket
    # store the file descriptor id, and then bind when ready per normal registration logic.
    def _create_socket(self, intf: str) -> None:
        l_sock = socket(AF_INET, SOCK_DGRAM)

        # used for converting interface identity to socket object file descriptor number
        self.dhcp_server.intf_settings[intf].update({
            'l_sock': l_sock,
            'fileno': l_sock.fileno()
        })

        Log.debug(f'[{l_sock.fileno()}][{intf}] socket created')


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
        with ConfigurationManager('dhcp_server', ext='.lease') as dnx:
            dhcp_settings: ConfigChain = dnx.load_configuration()

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

        stored_leases: dict[str, list] = load_configuration('dhcp_server', ext='.lease').get_dict()

        self.update({ip: DHCP_RECORD(*lease_info) for ip, lease_info in stored_leases.items()})
