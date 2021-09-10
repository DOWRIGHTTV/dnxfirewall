#!/usr/bin/env python3

import os, sys
import threading

from ipaddress import IPv4Address

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import *  # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.system_info import System
from dnx_gentools.standard_tools import looper, Initialize
from dnx_sysmods.configure.file_operations import load_configuration, cfg_read_poller
from dnx_sysmods.configure.iptables import IPTablesManager
from dnx_secmods.ips_ids.ips_ids_log import Log


class Configuration:
    _setup = False

    __slots__ = (
        'initialize', 'IPS', '_cfg_change',
    )

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

        self._load_passive_blocking()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_open_ports).start()
        threading.Thread(target=self._update_system_vars).start()

        self.initialize.wait_for_threads(count=3)

        threading.Thread(target=self._clear_ip_tables).start()

    # this resets any passively blocked hosts in the system on startup. persisting this
    # data through service or system restarts is not really worth the energy.
    def _load_passive_blocking(self):
        self.IPS.fw_rules = dict(System.ips_passively_blocked())

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
            self.IPS.block_length = NO_DELAY

        # src ips that will not trigger ips
        self.IPS.ip_whitelist = set([IPv4Address(ip) for ip in ips['whitelist']['ip_whitelist']])

        self._cfg_change.set()
        self.initialize.done()

    # NOTE: determine whether default sleep timer is acceptable for this method. if not, figure out how to override
    # the setting set in the decorator or remove the decorator entirely.
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

        # resetting the config change event.
        self._cfg_change.clear()

        open_ports = self.IPS.open_ports[PROTO.TCP] or self.IPS.open_ports[PROTO.UDP]

        self.IPS.ps_engine_enabled = True if self.IPS.portscan_prevention and open_ports else False

        self.IPS.ddos_engine_enabled = True if self.IPS.ddos_prevention else False

        self.initialize.done()

    @looper(FIVE_MIN)
    # NOTE: refactored function utilizing iptables + timestamp comment to identify rules to be expired.
    # this should inherently make the passive blocking system persist service or system reboots.
    # TODO: consider using the fw_rule dict check before continuing to call System.
    def _clear_ip_tables(self):
        expired_hosts = System.ips_passively_blocked(block_length=self.IPS.block_length)
        if (not expired_hosts):
            return

        with IPTablesManager() as iptables:
            for host, timestamp in expired_hosts:
                iptables.proxy_del_rule(host, timestamp, table='raw', chain='IPS')

                # removing host from ips tracker/ suppression dictionary
                self.IPS.fw_rules.pop(IPv4Address(host), None)  # should never return None
