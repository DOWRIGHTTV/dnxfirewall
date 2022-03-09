#!/usr/bin/env python3

from __future__ import annotations

import threading

from ipaddress import IPv4Address

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO
from dnx_routines.configure.system_info import System
from dnx_gentools.standard_tools import looper, Initialize
from dnx_gentools.file_operations import load_configuration, cfg_read_poller
from dnx_routines.configure.iptables import IPTablesManager
from dnx_secmods.ips_ids.ips_ids_log import Log


class Configuration:
    _setup = False

    __slots__ = (
        'initialize', 'ips_ids', '_cfg_change',
    )

    def __init__(self, name):
        self.initialize  = Initialize(Log, name)
        self._cfg_change = threading.Event()

        self.ips_ids: IPS_IDS_T

    @classmethod
    def setup(cls, ips_ids: IPS_IDS_T):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(ips_ids.__name__)
        self.ips_ids = ips_ids

        self._load_passive_blocking()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_open_ports).start()
        threading.Thread(target=self._update_system_vars).start()

        self.initialize.wait_for_threads(count=3)

        threading.Thread(target=self._clear_ip_tables).start()

    # this resets any passively blocked hosts in the system on startup.
    # persisting the data through service or system restarts is not really worth the energy.
    def _load_passive_blocking(self):
        self.ips_ids.fw_rules = dict(System.ips_passively_blocked())

    @cfg_read_poller('ips_ids')
    def _get_settings(self, cfg_file: str) -> None:
        proxy_settings: ConfigChain = load_configuration(cfg_file)

        self.ips_ids.ids_mode = proxy_settings['ids_mode']

        self.ips_ids.ddos_prevention = proxy_settings['ddos->enabled']
        # ddos CPS configured thresholds
        self.ips_ids.connection_limits = {
            PROTO.ICMP: proxy_settings['ddos->limits->source->icmp'],
            PROTO.TCP:  proxy_settings['ddos->limits->source->tcp'],
            PROTO.UDP:  proxy_settings['ddos->limits->source->udp']
        }

        self.ips_ids.portscan_prevention = proxy_settings['port_scan->enabled']
        self.ips_ids.portscan_reject = proxy_settings['port_scan->reject']

        if (self.ips_ids.ddos_prevention and not self.ips_ids.ids_mode):

            # checking length(hours) to leave IP table rules in place for hosts part of ddos attacks
            self.ips_ids.block_length = proxy_settings['passive_block_ttl'] * ONE_HOUR

            # NOTE: this will provide a simple way to ensure very recently blocked hosts do not get their
            # rule removed if passive blocking is disabled.
            if (not self.ips_ids.block_length):
                self.ips_ids.block_length = FIVE_MIN

        # if ddos engine is disabled
        else:
            self.ips_ids.block_length = NO_DELAY

        # src ips that will not trigger ips # FIXME: does this even work? we use integer for ip addr now.
        self.ips_ids.ip_whitelist = set([IPv4Address(ip) for ip in proxy_settings['whitelist->ip_whitelist']])

        self._cfg_change.set()
        self.initialize.done()

    # NOTE: determine whether the default sleep timer is acceptable for this method. if not, figure out how to override
    # the setting set in the decorator or remove the decorator entirely.
    @cfg_read_poller('ips_ids')
    def _get_open_ports(self, cfg_file: str) -> None:
        proxy_settings: ConfigChain = load_configuration(cfg_file)

        self.ips_ids.open_ports = {
            PROTO.TCP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->tcp')
            },
            PROTO.UDP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->udp')
            }
        }

        self._cfg_change.set()
        self.initialize.done()

    @looper(NO_DELAY)
    def _update_system_vars(self) -> None:
        # waiting for any thread to report a change in configuration.
        self._cfg_change.wait()

        # resetting the config change event.
        self._cfg_change.clear()

        open_ports = self.ips_ids.open_ports[PROTO.TCP] or self.ips_ids.open_ports[PROTO.UDP]

        self.ips_ids.ps_engine_enabled = True if self.ips_ids.portscan_prevention and open_ports else False

        self.ips_ids.ddos_engine_enabled = True if self.ips_ids.ddos_prevention else False

        # makes some conditions easier when determining what to do with the packet.
        self.ips_ids.all_engines_enabled = self.ips_ids.ps_engine_enabled and self.ips_ids.ddos_engine_enabled

        self.initialize.done()

    @looper(FIVE_MIN)
    # NOTE: refactored function utilizing iptables + timestamp comment to identify rules to be expired.
    # this should inherently make the passive blocking system persist service or system reboots.
    # TODO: consider using the fw_rule dict check before continuing to call System.
    def _clear_ip_tables(self) -> None:
        expired_hosts = System.ips_passively_blocked(block_length=self.ips_ids.block_length)
        if (not expired_hosts):
            return

        with IPTablesManager() as iptables:
            for host, timestamp in expired_hosts:
                iptables.proxy_del_rule(host, timestamp, table='raw', chain='IPS')

                # removing host from ips tracker/ suppression dictionary
                self.ips_ids.fw_rules.pop(IPv4Address(host), None)  # should never return None
