#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO
from dnx_gentools.system_info import System
from dnx_gentools.standard_tools import looper, ConfigurationMixinBase
from dnx_gentools.file_operations import cfg_read_poller, ConfigurationManager

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

    ids_mode: ClassVar[int] = 0  # TODO: this should be removed or re implemented as a packet action of LOG/ACCEPT per cat
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

    # NOTE: determine whether the default sleep timer is acceptable for this open port updates. if not, figure out how
    # to override the setting set in the decorator or remove the decorator entirely.
    @cfg_read_poller('global', cfg_type='security/ids_ips')
    def _get_open_ports(self, proxy_settings: ConfigChain) -> None:

        self.__class__.open_ports = {
            PROTO.TCP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->tcp')
            },
            PROTO.UDP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->udp')
            },
            PROTO.ICMP: {}  # todo: what is this here for? is it to prevent issue on packet inspection?
        }

        # NOTE: this is needed to remove from memory who were manually removed by user via webui
        if hosts_to_remove := proxy_settings.get_items('pbl_remove'):
            with ConfigurationManager('global', cfg_type='security/ids_ips') as dnx:
                ips_global_settings: ConfigChain = dnx.load_configuration()

                for host, timestamp in hosts_to_remove:

                    # removing host from ips tracker/ suppression dictionary
                    # notify list could desync from in memory tracker under service/system shutdown conditions, so we
                    # will remove entry from the notify list regardless.
                    self.__class__.fw_rules.pop(host, None)

                    del ips_global_settings[f'pbl_remove->{host}']

                dnx.write_configuration(ips_global_settings.expanded_user_data)

        self._initialize.done()

    @looper(FIVE_MIN)
    # refactored function utilizing iptables + timestamp comment to identify rules to be expired.
    # this should inherently make the passive blocking system persist service or system reboots.
    def _clear_ip_tables(self) -> None:
        expired_hosts = System.ips_passively_blocked(block_length=self.__class__.block_length)
        if (not expired_hosts):
            return

        with IPTablesManager() as iptables:
            for host, timestamp in expired_hosts:
                iptables.remove_passive_block(host, timestamp)

                # removing host from ips tracker/ suppression dictionary
                self.__class__.fw_rules.pop(host, None)  # should never return None
