#!/usr/bin/env python3

from __future__ import annotations

import threading

from collections import namedtuple
from socket import socket,  AF_INET, SOCK_DGRAM
from ipaddress import IPv4Address, IPv4Interface

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_namedtuples import RECORD_CONTAINER, Item
from dnx_gentools.def_enums import DHCP
from dnx_gentools.file_operations import load_configuration, cfg_read_poller, ConfigurationManager
from dnx_gentools.standard_tools import looper, dnx_queue, Initialize

from dnx_iptools.cprotocol_tools import iptoi

from dnx_routines.logging.log_client import LogHandler as Log

# required when using configuration manager.
ConfigurationManager.set_log_reference(Log)

_NULL_LEASE: DHCP_RECORD = DHCP_RECORD(DHCP.AVAILABLE, 0, '', '')


class Configuration:
    _setup: ClassVar[bool] = False

    __slots__ = (
        'initialize', 'dhcp_server',
    )

    def __init__(self, name: str):
        self.initialize = Initialize(Log, name)

    @classmethod
    def setup(cls, server: Type[DHCPServer]) -> None:
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(server.__name__)
        self.dhcp_server = server

        self._load_interfaces()

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_server_options).start()
        threading.Thread(target=self._get_reservations).start()
        self.initialize.wait_for_threads(count=3)

    @cfg_read_poller('dhcp_server')
    def _get_settings(self, cfg_file: str) -> None:
        dhcp_settings: ConfigChain = load_configuration(cfg_file)

        # updating user configuration items per interface in memory.
        for settings in dhcp_settings.get_values('interfaces'):

            # NOTE ex. ident: eth0, lo, enp0s3
            intf_identity = settings['ident']
            enabled = settings['enabled']

            # TODO: compare interface status in memory with what is loaded in. if it is different then the setting was
            #  just changed and needs to be acted on. implement register/unregister methods available to external
            #  callers and use them to act on the disable of an interfaces dhcp service. this should also be the most
            #  efficient in that if all listeners are disabled only the automate class will be actively processing on
            #  file changes.
            # NOTE: .get is to cover server startup. do not change. test functionality.
            sock_fd = self.dhcp_server.intf_settings[intf_identity]['fileno']
            if (enabled and not self.dhcp_server.intf_settings[intf_identity].get('enabled', False)):
                self.dhcp_server.enable(sock_fd, intf_identity)

            elif (not enabled and self.dhcp_server.intf_settings[intf_identity].get('enabled', True)):
                self.dhcp_server.disable(sock_fd, intf_identity)

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
            configured_options = {int(k): v for k, v in settings['options']}

            active_interface = self.dhcp_server.intf_settings[settings['ident']]

            # if active interface options have not changed we can pass
            if (configured_options == active_interface['options']):
                continue

            active_interface['options'] = configured_options

        self.initialize.done()

    # loading user configured dhcp reservations from json config file into memory.
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

        # FIXME: make lease table automatically check if ip is reserved since it now controls the reserved data set
        # adding dhcp reservations to lease table to prevent them from being selected during an offer
        # self.dhcp_server.leases.update({
        #     info['ip_address']: DHCP_RECORD(DHCP.RESERVATION, 0, mac, '')
        #     for mac, info in self.dhcp_server.reservations.items()
        # })

        self.initialize.done()

    def _load_interfaces(self) -> None:
        fw_intf: dict = load_configuration('system').get_dict('interfaces->builtins')

        dhcp_intfs: list[Item] = load_configuration('dhcp_server').get_items('interfaces->builtins')

        # interface friendly name e.g. wan
        for intf_name, settings in dhcp_intfs:

            intf_ident = settings['ident']

            # creating ipv4 interface object which will be associated with the ident in the config.
            # this can then be used by the server to identify itself as well as generate its effective
            # subnet based on netmask for ip handouts or membership tests.
            intf_ip = iptoi(fw_intf[intf_name]['ip'])
            intf_netmask = iptoi(fw_intf[intf_name]['netmask'])

            # updating general network information for interfaces on server class object. these will never change
            # while the server is running. for interfaces changes, the server must be restarted.
            # initializing fileno key in the intf dict to make assignments easier in later calls.
            self.dhcp_server.intf_settings[intf_ident] = {
                'ip': intf_ip,
                'netmask': intf_netmask
            }

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

    # if missing will return an available record
    def __missing__(self, key: Any) -> DHCP_RECORD:
        return _NULL_LEASE

    def modify(self, ip: int, record: DHCP_RECORD = _NULL_LEASE, clean_up: bool = False) -> None:
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
        '''return copy of reservered ip addresses as a set.'''

        return set(self.reservations.values())

    @dnx_queue(Log, name='Leases')
    # store lease table changes to disk. if record is not present, it indicates the record needs to be removed.
    def _storage_queue(self, dhcp_lease: RECORD_CONTAINER):
        with ConfigurationManager('dhcp_server') as dnx:
            dhcp_settings = dnx.load_configuration()

            dhcp_usr_settings = dhcp_settings.expanded_user_data
            if (dhcp_lease.record is _NULL_LEASE):
                dhcp_usr_settings['leases'].pop(dhcp_lease.ip, None)

            else:
                dhcp_usr_settings['leases'][dhcp_lease.ip] = dhcp_lease.record

            dnx.write_configuration(dhcp_usr_settings)

    @looper(ONE_MIN)
    # TODO: TEST RESERVATIONS GET CLEANED UP
    def _lease_table_cleanup(self) -> None:

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

        dhcp_settings = load_configuration('dhcp_server')

        stored_leases = dhcp_settings.get_items('leases')
        self.update({ip: lease_info for ip, lease_info in stored_leases})
