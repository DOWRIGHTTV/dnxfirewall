#!/usr/bin/env python3

import os, sys
import json
import time
import threading

from ipaddress import IPv4Address

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_system_info import Interface
from dnx_iptools.dnx_standard_tools import looper, dynamic_looper, Initialize
from dnx_configure.dnx_file_operations import load_configuration, cfg_read_poller
from dnx_configure.dnx_iptables import IPTablesManager
from dnx_ips.dnx_ips_log import Log


class Configuration:
    _setup = False

    def __init__(self, name):
        self.initialize  = Initialize(Log, name)
        self._cfg_change = threading.Event()

    @classmethod
    def setup(cls, IPS):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')
        cls._setup = True

        self = cls(IPS.__name__)
        self.IPS = IPS

        self._load_interfaces()
        self._manage_ip_tables()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_open_ports).start()
        threading.Thread(target=self._update_system_vars).start()

        self.initialize.wait_for_threads(count=3)

        threading.Thread(target=self._clear_ip_tables).start()

    def _manage_ip_tables(self):
        IPTablesManager.purge_proxy_rules(table='mangle', chain='IPS')

    def _load_interfaces(self):
        dnx_settings = load_configuration('config')

        wan_ident = dnx_settings['interfaces']['wan']['ident']

        self.IPS.broadcast = Interface.broadcast_address(wan_ident)

    @cfg_read_poller('ips')
    def _get_settings(self, cfg_file):
        ips = load_configuration(cfg_file)

        self.IPS.ids_mode = ips['ids_mode']

        self.IPS.ddos_prevention = ips['ddos']['enabled']
        # ddos CPS configured thresholds
        self.IPS.connection_limits = {
            PROTO.ICMP: ips['ddos']['limits']['source']['icmp'],
            PROTO.TCP:  ips['ddos']['limits']['source']['tcp'],
            PROTO.UDP:  ips['ddos']['limits']['source']['udp']
        }

        self.IPS.portscan_prevention = ips['port_scan']['enabled']
        self.IPS.portscan_reject = ips['port_scan']['reject']

        if (self.IPS.ddos_prevention and not self.IPS.ids_mode):

            # checking length(hours) to leave IP table rules in place for hosts part of ddos attacks
            self.IPS.block_length = ips['passive_block_ttl'] * ONE_HOUR

            # NOTE: this will provide a simple way to ensure very recently blocked hosts do not get their
            # rule removed if passive blocking is disabled.
            if (not self.IPS.block_length):
                self.IPS.block_length = FIVE_MIN

        # if ddos engine is disabled
        else:
            self.IPS.block_length = 0

        # src ips that will not trigger ips
        self.IPS.ip_whitelist = set([IPv4Address(ip) for ip in ips['whitelist']['ip_whitelist']])

        self._cfg_change.set()
        self.initialize.done()

    # NOTE: determine whether default sleep timer is acceptible for this method. if not, figure out how to override
    # the setting set in the decorator or remove the decorator entirely.
    # TODO: this doesnt seem to be working. a portscan that should have been reported as a miss was labeled as blocked.
    #     see if these are getting cross referenced correctly by the portscan module and that the object types line up.
    @cfg_read_poller('ips')
    def _get_open_ports(self, cfg_file):
        ips = load_configuration(cfg_file)

        self.IPS.open_ports = {
            PROTO.TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips['open_protocols']['tcp'].items()
            },
            PROTO.UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips['open_protocols']['udp'].items()
            }
        }

        self._cfg_change.set()
        self.initialize.done()

    @looper(NO_DELAY)
    def _update_system_vars(self):
        # waiting for any thread to report a change in configuration.
        self._cfg_change.wait()

        #resetting the config change event.
        self._cfg_change.clear()

        open_ports = self.IPS.open_ports[PROTO.TCP] or self.IPS.open_ports[PROTO.UDP]
        if (self.IPS.ddos_prevention or (self.IPS.portscan_prevention and open_ports)):
            self.IPS.ins_engine_enabled = True
        else:
            self.IPS.ins_engine_enabled = False

        if (self.IPS.portscan_prevention and open_ports):
            self.IPS.ps_engine_enabled = True
        else:
            self.IPS.ps_engine_enabled = False

        if (self.IPS.ddos_prevention):
            self.IPS.ddos_engine_enabled = True
        else:
            self.IPS.ddos_engine_enabled = False

        self.initialize.done()

    @looper(THIRTY_MIN)
    # TODO: consider making this work off of a thread event. then we can convert the dynamic looper
    # to a standard looper and method will block until an actual host has been blocked.
    def _clear_ip_tables(self):
        # quick check to see if any firewall rules exist
        firewall_rules = self.IPS.fw_rules
        if (not firewall_rules): return

        block_length, now = self.IPS.block_length, fast_time()

        # TODO: look into a method that isnt linearly complext to clear firewall rules. its expected to be
        # somewhat small so its not terrible as is.
        with IPTablesManager() as iptables:
            for tracked_ip, insertion_time in list(firewall_rules.items()):
                if (now - insertion_time > block_length) and firewall_rules.pop(tracked_ip, None):
                    iptables.proxy_del_rule(tracked_ip, table='mangle', chain='IPS')
