#!/usr/bin/env python3

from __future__ import annotations

import threading

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RFC1918
from dnx_gentools.def_enums import PROTO, DIR, REP, GEO
from dnx_gentools.standard_tools import Initialize
from dnx_gentools.file_operations import load_configuration, cfg_read_poller

from dnx_routines.configure.iptables import IPTablesManager

from ip_proxy_log import Log


class Configuration:
    _setup: bool = False

    __slots__ = (
        'ip_proxy', 'initialize',
    )

    def __init__(self, name: str):
        self.initialize = Initialize(Log, name)

    @classmethod
    def setup(cls, ip_proxy: Type[IPProxy]) -> None:
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self: Configuration = cls(ip_proxy.__name__)
        self.ip_proxy = ip_proxy

        self._manage_ip_tables()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_ip_whitelist).start()
        threading.Thread(target=self._get_open_ports).start()

        self.initialize.wait_for_threads(count=3)

    @cfg_read_poller('ip_proxy')
    def _get_settings(self, cfg_file: str) -> None:
        ip_proxy = load_configuration(cfg_file)

        self.ip_proxy.ids_mode = ip_proxy['ids_mode']

        # converting list[items] > dict
        rep_settings = dict(ip_proxy.get_items('reputation'))
        geo_settings = dict(ip_proxy.get_items('geolocation'))

        # used for categorizing private ip addresses
        geo_settings.update(RFC1918)

        reputation_enabled = []
        for cat, setting in rep_settings.items():
            if (setting): reputation_enabled.append(1)

            self.ip_proxy.reputation_settings[REP[cat.upper()]] = DIR(setting)

        for country, direction in geo_settings.items():
            
            # using enum for category key and direction value
            try:
                self.ip_proxy.geolocation_settings[GEO[country.upper()]] = DIR(direction)
            except KeyError:
                continue # not all enums/countries are populated

        self.ip_proxy.reputation_enabled = bool(reputation_enabled)

        self.initialize.done()

    @cfg_read_poller('whitelist')
    def _get_ip_whitelist(self, cfg_file: str) -> None:
        whitelist = load_configuration(cfg_file)

        self.ip_proxy.ip_whitelist = {
            ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'ip'
        }

        self.ip_proxy.tor_whitelist = {
            ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'tor'
        }

        self.initialize.done()

    @cfg_read_poller('ips')
    def _get_open_ports(self, cfg_file: str) -> None:
        ips = load_configuration(cfg_file)

        self.ip_proxy.open_ports = {
            PROTO.TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->tcp')
            },
            PROTO.UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->udp')
            }
        }

        self.initialize.done()

    @staticmethod
    def _manage_ip_tables():
        IPTablesManager.clear_dns_over_https()
        IPTablesManager.update_dns_over_https()
