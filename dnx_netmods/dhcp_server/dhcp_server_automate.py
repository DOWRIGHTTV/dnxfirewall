#!/usr/bin/env python3

import os, sys
import threading

from collections import namedtuple
from socket import socket,  AF_INET, SOCK_DGRAM
from ipaddress import IPv4Address, IPv4Interface

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.interface_ops import get_netmask
from dnx_sysmods.logging.log_main import LogHandler as Log
from dnx_sysmods.configure.file_operations import load_configuration, cfg_read_poller, ConfigurationManager
from dnx_gentools.standard_tools import looper, dnx_queue, Initialize

_NULL_LEASE = (DHCP.AVAILABLE, None, None, None)

# required when using configuration manager.
ConfigurationManager.set_log_reference(Log)


class Configuration:
    _setup = False

    def __init__(self, name):
        self.initialize = Initialize(Log, name)

    @classmethod
    def setup(cls, DHCPServer):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(DHCPServer.__name__)
        self.DHCPServer = DHCPServer

        self._load_interfaces()

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_server_options).start()
        threading.Thread(target=self._get_reservations).start()
        self.initialize.wait_for_threads(count=3)

    @cfg_read_poller('dhcp_server')
    def _get_settings(self, cfg_file):
        dhcp_settings = load_configuration(cfg_file)

        # updating user configuration items per interface in memory.
        for settings in dhcp_settings['interfaces'].values():

            # NOTE ex. ident: eth0, lo, enp0s3
            intf_identity = settings['ident']

            enabled  = True if settings['enabled'] else False

            # TODO: compare interface status in memory with what is loaded in. if it is different then the setting was just
            # changed and needs to be acted on. implement register/unregister methods available to external callers and use
            # them to act on the disable of an interfaces dhcp service. this should also be the most efficient in that if
            # all listeners are disabled only the automate class will be actively processing on file changes.
            # NOTE: .get is to cover server startup. do not change. test functionality.
            sock_fd = self.DHCPServer.intf_settings[intf_identity]['fileno']
            if (enabled and not self.DHCPServer.intf_settings[intf_identity].get('enabled', False)):
                self.DHCPServer.enable(sock_fd, intf_identity)

            elif (not enabled and self.DHCPServer.intf_settings[intf_identity].get('enabled', True)):
                self.DHCPServer.disable(sock_fd, intf_identity)

            # identity will be kept in settings just in case, though they key is the identity also.
            self.DHCPServer.intf_settings[intf_identity].update(settings)

        self.initialize.done()

    @cfg_read_poller('dhcp_server')
    def _get_server_options(self, cfg_file):
        dhcp_settings = load_configuration(cfg_file)
        server_options = dhcp_settings['options']
        interfaces = dhcp_settings['interfaces']

        # if server options have not changed, the function can return
        if (server_options == self.DHCPServer.options): return

        # will wait for 2 threads to check in before running code. this will allow the necessary settings
        # to be initialized on startup before this thread continues.
        self.initialize.wait_in_line(wait_for=2)

        with self.DHCPServer.options_lock:

            # iterating over server interfaces and populated server option data sets NOTE: consider merging server
            # options with the interface settings since they are technically bound.
            for intf, settings in self.DHCPServer.intf_settings.items():

                for _intf in interfaces.values():

                    # ensuring the interfaces match since we cannot guarantee order
                    if (intf != _intf['ident']): continue

                    # converting keys to integers (json keys are string only), then packing any
                    # option value that is in ip address form to raw bytes.
                    for o_id, values in server_options.items():

                        opt_len, opt_val = values
                        if (not isinstance(opt_val, str)):
                            self.DHCPServer.options[intf][int(o_id)] = (opt_len, opt_val)

                        else:
                            # NOTE: this is temporary to allow interface netmask to be populated correction while migrating
                            # to new system backend functions.
                            if (o_id == '1'):
                                ip_value = get_netmask(interface=intf)
                            else:
                                ip_value = list(settings['ip'].network)[int(opt_val)]

                            # using digit as ipv4 network object index to grab correct ip object, then pack.
                            self.DHCPServer.options[intf][int(o_id)] = (
                                opt_len, ip_value.packed
                            )

        self.initialize.done()

    # loading user configured dhcp reservations from json config file into memory.
    @cfg_read_poller('dhcp_server')
    def _get_reservations(self, cfg_file):
        dhcp_settings = load_configuration(cfg_file)

        # dict comp that retains all info of stored json data, but converts ip address into objects
        self.DHCPServer.reservations = {
            mac: {
                'ip_address': IPv4Address(info['ip_address']),
                'description': info['description']
            }
            for mac, info in dhcp_settings['reservations'].items()
        }

        # creating local reference for iteration performance
        reservations = self.DHCPServer.reservations

        # loaded all reserved ip addressing into a set to be referenced below
        reserved_ips = set([IPv4Address(info['ip_address']) for info in reservations.values()])

        # sets reserved ip addresses lease records to available is there are no longer configured
        dhcp_leases = self.DHCPServer.leases
        for ip, record in dhcp_leases.items():

            # record[0] is record type. cross referencing ip reservation list with current lease table
            # to reset any leased record placeholders for the reserved ip.
            if (record[0] is DHCP.RESERVATION and IPv4Address(ip) not in reserved_ips):
                dhcp_leases[ip] = _NULL_LEASE

        # adding dhcp reservations to lease table to prevent them from being selected during an offer
        self.DHCPServer.leases.update({
            IPv4Address(info['ip_address']): (DHCP.RESERVATION, 0, mac) for mac, info in reservations.items()
        })

        self.initialize.done()

    # accessing class object via local instance to change overall DHCP server enabled ints tuple
    def _load_interfaces(self):
        fw_intf = load_configuration('config')['interfaces']['builtins']
        dhcp_intfs = load_configuration('dhcp_server')['interfaces']

        # interface ident eg. eth0
        for intf in self.DHCPServer._intfs:

            # interface friendly name eg. wan
            for _intf, settings in dhcp_intfs.items():

                # ensuring the iterfaces match since we cannot guarantee order
                if (intf != settings['ident']): continue

                # creating ipv4 interface object which will be associated with the ident in the config.
                # this can then be used by the server to identify itself as well as generate its effective
                # subnet based on netmask for ip handouts or membership tests.
                intf_ip = IPv4Interface(str(fw_intf[_intf]['ip']) + '/' + str(fw_intf[_intf]['netmask']))

                # initializing server options so the auto loader doesnt have to worry about it.
                self.DHCPServer.options[intf] = {}

                # updating general network information for interfaces on server class object. these will never change
                # while the server is running. for interfaces changes, the server must be restarted.
                # initializing fileno key in the intf dict to make assignments easier in later calls.
                self.DHCPServer.intf_settings[intf] = {'ip': intf_ip}

                self._create_socket(intf)

        Log.debug(f'loaded interfaces from file: {self.DHCPServer.intf_settings}')

    # this is providing the first portion of creating a socket. this will allow the system to create the socket
    # store the file descriptor id, and then bind when ready per normal registration logic.
    def _create_socket(self, intf):
        l_sock = socket(AF_INET, SOCK_DGRAM)

        # used for converting interface identity to socket object file descriptor number
        self.DHCPServer.intf_settings[intf].update({
            'l_sock': l_sock,
            'fileno': l_sock.fileno()
        })

        Log.debug(f'[{l_sock.fileno()}][{intf}] socket created')

# short lived container for queue/writing dhcp record to disk
_RECORD_CONTAINER = namedtuple('record_container', 'ip record')


class Leases(dict):
    _setup = False

    __slots__ = (
        '_ip_reservations', '_lease_table_lock'
    )

    def __init__(self, ip_reservations):
        self._ip_reservations = ip_reservations

        self._lease_table_lock = threading.Lock()

        self._load_leases()
        threading.Thread(target=self._lease_table_cleanup).start()
        threading.Thread(target=self._storage).start()

    # if missing will return an expired result
    def __missing__(self, key):
        return _NULL_LEASE

    def modify(self, ip, record=_NULL_LEASE, clean_up=False):
        '''modifies a record in the lease table. this will automatically ensure changes get written to disk. if no record
        is provided, a dhcp release is assumed.

        clean_up=True should only be used by callers in an automated system that handle mutating the lease dict themselves.
        '''

        # added change to storage queue for lease persistence across device/process shutdowns.
        # will only store active leases. offers will be treated as volitile and not persist restarts
        if (record[0] is not DHCP.OFFERED):
            self._storage.add(_RECORD_CONTAINER(f'{ip}', record)) # pylint: disable=no-member

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
    def _load_leases(self):

        dhcp_settings = load_configuration('dhcp_server')

        stored_leases = dhcp_settings['leases']
        self.update({
            IPv4Address(ip): lease_info for ip, lease_info in stored_leases.items()
        })

    @looper(ONE_MIN)
    # TODO: TEST RESERVATIONS GET CLEANED UP
    def _lease_table_cleanup(self):

        # filtering list down to only active leases. list comp is more efficient and this also removes the need
        # to check if lease is active in business logic.
        active_leases = [
            (ip_addr, lease) for ip_addr, lease in self.items() if lease[0] != DHCP.AVAILABLE
        ]

        for ip_address, lease in active_leases:

            lease_type, lease_time, lease_mac, _ = lease

            # current time - lease time = time elapsed since lease was handed out
            time_elapsed = fast_time() - lease_time

            # ip reservation has been removed from system
            if (lease_type == DHCP.RESERVATION and lease_mac not in self._ip_reservations):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # client did not accept our ip offer
            elif (lease_type == DHCP.OFFERED and time_elapsed > ONE_MIN):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # ip lease expired normally # NOTE: consider moving this value to a global constant/ make configurable
            elif (time_elapsed >= 86800):
                self[ip_address] = (DHCP.AVAILABLE, 0, 0, 0)

            # unknown condition? maybe log?
            else: continue

            # adding to queue for removal from stored leases on disk. no record notifies job handler to remove vs add.
            # this is only needed to adjust the disk since the iterator handles mutating the lease dict in memory.
            self.modify(ip_address, clean_up=True) # pylint: disable=no-member
