#!/usr/bin/env python3

from __future__ import annotations

import threading

from collections import namedtuple
from socket import socket,  AF_INET, SOCK_DGRAM
from ipaddress import IPv4Address, IPv4Interface

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import DHCP
from dnx_gentools.file_operations import load_configuration, cfg_read_poller, ConfigurationManager
from dnx_gentools.standard_tools import looper, dnx_queue, Initialize

from dnx_iptools.interface_ops import get_netmask, get_ipaddress

from dnx_routines.logging.log_client import LogHandler as Log

# required when using configuration manager.
ConfigurationManager.set_log_reference(Log)

DHCP_Lease = tuple[DHCP, Union[int, float], str, str]
_NULL_LEASE: DHCP_Lease = (DHCP.AVAILABLE, 0, '', '')


class Configuration:
    _setup: ClassVar[bool] = False

    __slots__ = (
        'initialize', 'dhcp_server',
    )

    def __init__(self, name: str, DHCPServer: Type[DHCPServer]):
        self.initialize = Initialize(Log, name)

        self.dhcp_server = DHCPServer

    @classmethod
    def setup(cls, DHCPServer: Type[DHCPServer]) -> None:
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(DHCPServer.__name__, DHCPServer)

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
        dhcp_settings: ConfigChain = load_configuration(cfg_file)
        server_options = dhcp_settings.get_items('options')
        # interfaces = dhcp_settings['interfaces']

        # if server options have not changed, the function can return
        if (server_options == self.dhcp_server.options): return

        # will wait for 2 threads to check in before running code. this will allow the necessary settings
        # to be initialized on startup before this thread continues.
        self.initialize.wait_in_line(wait_for=2)

        with self.dhcp_server.options_lock:

            # iterating over server interfaces and populating server option data sets
            for intf, settings in self.dhcp_server.intf_settings.items():

                # converting keys to integers (json keys are string only), then packing any
                # option value that is in ip address form to raw bytes.
                for o_id, values in server_options:

                    # standard fields
                    if (o_id in ['26', '28', '51', '58', '59']):
                        self.dhcp_server.options[intf][int(o_id)] = values

                    elif (o_id == '1'):
                        ip_value = get_netmask(interface=intf)

                    elif (o_id in ['3', '6', '54']):
                        ip_value = get_ipaddress(interface=intf)

                    self.dhcp_server.options[intf][int(o_id)] = (
                        values[0], ip_value.packed
                    )

        self.initialize.done()

    # loading user configured dhcp reservations from json config file into memory.
    @cfg_read_poller('dhcp_server')
    def _get_reservations(self, cfg_file: str) -> None:
        dhcp_settings: ConfigChain = load_configuration(cfg_file)

        # dict comp that retains all infos of stored json data, but converts ip address into objects
        self.dhcp_server.reservations = {
            mac: {
                'ip_address': IPv4Address(info['ip_address']),
                'description': info['description']
            }
            for mac, info in dhcp_settings.get_items('reservations')
        }

        # loading all reserved ip addresses into a set to be referenced below
        reserved_ips = set([IPv4Address(info['ip_address']) for info in self.dhcp_server.reservations.values()])

        # sets reserved ip address lease records to available if they are no longer configured
        dhcp_leases = self.dhcp_server.leases
        for ip, record in dhcp_leases.items():

            # record[0] is record type. cross-referencing ip reservation list with current lease table
            # to reset any leased record placeholders for the reserved ip.
            if (record[0] is DHCP.RESERVATION and IPv4Address(ip) not in reserved_ips):
                dhcp_leases[ip] = _NULL_LEASE

        # adding dhcp reservations to lease table to prevent them from being selected during an offer
        self.dhcp_server.leases.update({
            IPv4Address(info['ip_address']): (DHCP.RESERVATION, 0, mac) for mac, info in self.dhcp_server.reservations.items()
        })

        self.initialize.done()

    # accessing class object via local instance to change overall DHCP server enabled ints tuple
    def _load_interfaces(self) -> None:
        fw_intf: ConfigChain = load_configuration('system')['interfaces']['builtins']
        dhcp_intfs: ConfigChain = load_configuration('dhcp_server')['interfaces']

        # interface ident eg. eth0
        for *_, intf in self.dhcp_server._intfs:

            # interface friendly name e.g. wan
            for _intf, settings in dhcp_intfs.items():

                # ensuring the interfaces match since we cannot guarantee order
                if (intf != settings['ident']): continue

                # creating ipv4 interface object which will be associated with the ident in the config.
                # this can then be used by the server to identify itself as well as generate its effective
                # subnet based on netmask for ip handouts or membership tests.
                intf_ip = IPv4Interface(str(fw_intf[_intf]['ip']) + '/' + str(fw_intf[_intf]['netmask']))

                # initializing server options so the autoloader doesn't have to worry about it.
                self.dhcp_server.options[intf] = {}

                # updating general network information for interfaces on server class object. these will never change
                # while the server is running. for interfaces changes, the server must be restarted.
                # initializing fileno key in the intf dict to make assignments easier in later calls.
                self.dhcp_server.intf_settings[intf] = {'ip': intf_ip}

                self._create_socket(intf)

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


# short-lived container for queue/writing dhcp record to disk
class _RECORD_CONTAINER(NamedTuple):
    ip: str
    record: DHCP_Lease


class Leases(dict):
    _setup = False

    __slots__ = (
        '_ip_reservations', '_lease_table_lock'
    )

    def __init__(self, ip_reservations: dict[str, Any]):
        self._ip_reservations = ip_reservations

        self._lease_table_lock: Lock = threading.Lock()

        self._load_leases()
        threading.Thread(target=self._lease_table_cleanup).start()
        threading.Thread(target=self._storage).start()

    # if missing will return an expired result
    def __missing__(self, key: Any) -> DHCP_Lease:
        return _NULL_LEASE

    def modify(self, ip: IPv4Address, record: DHCP_Lease = _NULL_LEASE, clean_up: bool = False) -> None:
        '''modifies a record in the lease table. this will automatically ensure changes get written to disk. if no record
        is provided, a dhcp release is assumed.

        clean_up=True should only be used by callers in an automated system that handle mutating the lease dict themselves.
        '''

        # added change to storage queue for lease persistence across device/process shutdowns.
        # will only store active leases. offers will be treated as volatile and not persist restarts
        if (record[0] is not DHCP.OFFERED):
            self._storage.add(_RECORD_CONTAINER(f'{ip}', record))

        if (not clean_up):
            self[ip] = record

    @dnx_queue(Log, name='Leases')
    # store lease table changes to disk. if record is not present, it indicates the record needs to be removed.
    def _storage(self, dhcp_lease):
        with ConfigurationManager('dhcp_server') as dnx:
            dhcp_settings = dnx.load_configuration()
            leases = dhcp_settings['leases']

            if (dhcp_lease.record is _NULL_LEASE):
                leases.pop(dhcp_lease.ip, None)

            else:
                leases[dhcp_lease.ip] = dhcp_lease.record

            dnx.write_configuration(dhcp_settings)

    # loading dhcp leases from json file. will be called on startup only for lease persistence.
    def _load_leases(self) -> None:

        dhcp_settings = load_configuration('dhcp_server')

        stored_leases = dhcp_settings['leases']
        self.update({
            IPv4Address(ip): lease_info for ip, lease_info in stored_leases.items()
        })

    @looper(ONE_MIN)
    # TODO: TEST RESERVATIONS GET CLEANED UP
    def _lease_table_cleanup(self) -> NoReturn:

        # filtering list down to only active leases. list comp is more efficient and this also removes the need
        # to check if lease is active in business logic.
        active_leases = [
            (ip_addr, lease) for ip_addr, lease in self.items() if lease[0] != DHCP.AVAILABLE
        ]

        for ip_address, lease in active_leases:

            lease_type, lease_time, lease_mac, _ = lease

            # current time - lease time = time elapsed since lease was handed out
            time_elapsed = fast_time() - lease_time

            # ip reservation has been removed from the system
            if (lease_type == DHCP.RESERVATION and lease_mac not in self._ip_reservations):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # the client did not accept our ip offer
            elif (lease_type == DHCP.OFFERED and time_elapsed > ONE_MIN):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # ip lease expired normally # NOTE: consider moving this value to a global constant/ make configurable
            elif (time_elapsed >= 86800):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # unknown condition? maybe log?
            else: continue

            # adding to queue for removal from stored leases on disk. no record notifies job handler to remove vs add.
            # this is only needed to adjust the disk since the iterator handles mutating the lease dict in memory.
            self.modify(ip_address, clean_up=True)
