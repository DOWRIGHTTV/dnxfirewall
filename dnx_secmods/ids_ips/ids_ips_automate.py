#!/usr/bin/env python3

from __future__ import annotations

from ipaddress import IPv4Address

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO
from dnx_gentools.system_info import System
from dnx_gentools.standard_tools import looper, ConfigurationMixinBase
from dnx_gentools.file_operations import cfg_read_poller

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.iptables import IPTablesManager

from dnx_secmods.ids_ips.ids_ips_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


class IPSConfiguration(ConfigurationMixinBase):
    fw_rules:     ClassVar[dict] = {}
    ip_whitelist: ClassVar[dict] = {}

    open_ports: ClassVar[dict[PROTO, dict]] = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }

    ddos_limits: ClassVar[dict[PROTO, int]] = {
        PROTO.TCP: -1,
        PROTO.UDP: -1,
        PROTO.ICMP: -1
    }

    ids_mode: ClassVar[int] = 0  # TODO: implement this throughout
    ddos_enabled:  ClassVar[int] = 0
    pscan_enabled: ClassVar[int] = 0
    pscan_reject:  ClassVar[int] = 0
    all_enabled:   ClassVar[int] = 0
    block_length:  ClassVar[int] = 0

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''tasks required by the IDS/IPS.

        return thread information to be run.
        '''
        self.__class__.fw_rules = dict(System.ips_passively_blocked())

        threads = (
            (self._get_settings, ()),
            (self._get_open_ports, ()),
            (self._clear_ip_tables, ())
        )

        return Log, threads, 2

    @cfg_read_poller('profiles/profile_1', cfg_type='security/ids_ips')
    def _get_settings(self, proxy_settings: ConfigChain) -> None:

        self.__class__.ids_mode = proxy_settings['ids_mode']

        self.__class__.ddos_enabled = proxy_settings['ddos->enabled']
        # ddos CPS configured thresholds
        self.__class__.ddos_limits = {
            PROTO.ICMP: proxy_settings['ddos->limits->source->icmp'],
            PROTO.TCP:  proxy_settings['ddos->limits->source->tcp'],
            PROTO.UDP:  proxy_settings['ddos->limits->source->udp']
        }

        self.__class__.pscan_enabled = proxy_settings['port_scan->enabled']
        self.__class__.pscan_reject  = proxy_settings['port_scan->reject']

        self.__class__.all_enabled = proxy_settings['ddos->enabled'] and proxy_settings['port_scan->enabled']

        if (self.__class__.ddos_enabled and not self.__class__.ids_mode):

            # checking length(hours) to leave IP table rules in place for hosts part of ddos attacks
            self.__class__.block_length = proxy_settings['passive_block_ttl'] * ONE_HOUR

            # NOTE: this will provide a simple way to ensure very recently blocked hosts do not get their
            # rule removed if passive blocking is disabled.
            if (not self.__class__.block_length):
                self.__class__.block_length = FIVE_MIN

        # if ddos engine is disabled
        else:
            self.__class__.block_length = NO_DELAY

        # src ips that will not trigger ips
        self.__class__.ip_whitelist = set([iptoi(ip) for ip in proxy_settings['whitelist->ip_whitelist']])

        self._initialize.done()

    # NOTE: determine whether the default sleep timer is acceptable for this method. if not, figure out how to override
    # the setting set in the decorator or remove the decorator entirely.
    @cfg_read_poller('global', cfg_type='security/ids_ips')
    def _get_open_ports(self, proxy_settings: ConfigChain) -> None:

        self.__class__.open_ports = {
            PROTO.TCP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->tcp')
            },
            PROTO.UDP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->udp')
            },
            PROTO.ICMP: {}
        }

        self._initialize.done()

    @looper(FIVE_MIN)
    # NOTE: refactored function utilizing iptables + timestamp comment to identify rules to be expired.
    # this should inherently make the passive blocking system persist service or system reboots.
    # TODO: consider using the fw_rule dict check before continuing to call System.
    def _clear_ip_tables(self) -> None:
        expired_hosts = System.ips_passively_blocked(block_length=self.__class__.block_length)
        if (not expired_hosts):
            return

        with IPTablesManager() as iptables:
            for host, timestamp in expired_hosts:
                iptables.proxy_del_rule(host, timestamp, table='raw', chain='IPS')

                # removing host from ips tracker/ suppression dictionary
                self.__class__.fw_rules.pop(IPv4Address(host), None)  # should never return None
