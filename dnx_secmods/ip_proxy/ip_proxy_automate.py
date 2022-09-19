#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RFC1918
from dnx_gentools.def_namedtuples import Item
from dnx_gentools.def_enums import PROTO, DIR, REP, GEO
from dnx_gentools.standard_tools import ConfigurationMixinBase
from dnx_gentools.file_operations import load_configuration, cfg_read_poller

from dnx_iptools.iptables import IPTablesManager

from ip_proxy_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


class ProxyConfiguration(ConfigurationMixinBase):
    ids_mode: ClassVar[bool] = False

    reputation_enabled:   ClassVar[list[int]] = []
    reputation_settings:  ClassVar[dict[REP, DIR]] = {}
    # geolocation_enabled:  ClassVar[bool] = True
    geolocation_settings: ClassVar[dict[GEO, DIR]] = {}

    ip_whitelist:  ClassVar[dict] = {}
    tor_whitelist: ClassVar[dict] = {}

    open_ports: ClassVar[dict[PROTO, dict[int, int]]] = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''tasks required by the DNS proxy.

        return thread information to be run.
        '''
        self._manage_ip_tables()

        threads = (
            (self._get_settings, ()),
            (self._get_ip_whitelist, ()),
            (self._get_open_ports, ())
        )

        return Log, threads, 3

    @cfg_read_poller('profiles/profile_1', cfg_type='security/ip')
    def _get_settings(self, proxy_settings: ConfigChain) -> None:

        self.__class__.ids_mode = proxy_settings['ids_mode']

        # converting list[items] > dict
        rep_settings = proxy_settings.get_items('reputation')
        geo_settings = proxy_settings.get_items('geolocation')

        # used for categorizing private ip addresses
        geo_settings.append(Item(*RFC1918))

        reputation_enabled: bool = False
        for reputation, direction in rep_settings:

            if (direction):
                reputation_enabled = True

            self.__class__.reputation_settings[REP[reputation.upper()]] = DIR(direction)

        for country, direction in geo_settings:
            
            # using enum for category key and direction value
            try:
                self.__class__.geolocation_settings[GEO[country.upper()]] = DIR(direction)
            except KeyError:
                continue  # not all enums/countries are populated

        # using a list to maintain initial reference with inplace ops
        if (reputation_enabled):
            self.__class__.reputation_enabled.append(1)

        else:
            self.__class__.reputation_enabled.clear()

        self._initialize.done()

    @cfg_read_poller('whitelist')
    def _get_ip_whitelist(self, cfg_file: str) -> None:
        whitelist: ConfigChain = load_configuration(cfg_file)

        self.__class__.ip_whitelist = {
            ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'ip'
        }

        self.__class__.tor_whitelist = {
            ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'tor'
        }

        self._initialize.done()

    @cfg_read_poller('ids_ips', cfg_type='security/ids_ips')
    def _get_open_ports(self, ips: ConfigChain) -> None:

        self.__class__.open_ports = {
            PROTO.TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->tcp')
            },
            PROTO.UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->udp')
            }
        }

        self._initialize.done()

    @staticmethod
    def _manage_ip_tables():
        IPTablesManager.clear_dns_over_https()
        IPTablesManager.update_dns_over_https()
