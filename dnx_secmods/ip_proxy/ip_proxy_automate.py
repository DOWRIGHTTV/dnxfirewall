#!/usr/bin/env python3

import threading

import dnx_gentools.signature_operations as signature_operations

from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import Initialize

from dnx_gentools.file_operations import load_configuration, cfg_read_poller
from dnx_routines.configure.iptables import IPTablesManager

from dnx_secmods.ip_proxy.ip_proxy_log import Log


class Configuration:
    _setup = False

    __slots__ = (
        'IPProxy', 'initialize',
    )

    def __init__(self, name):
        self.initialize = Initialize(Log, name)

    @classmethod
    def setup(cls, IPProxy):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(IPProxy.__name__)
        self.IPProxy = IPProxy

        self._manage_ip_tables()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_ip_whitelist).start()
        threading.Thread(target=self._get_open_ports).start()

        self.initialize.wait_for_threads(count=3)

    @cfg_read_poller('ip_proxy')
    def _get_settings(self, cfg_file):
        ip_proxy = load_configuration(cfg_file)

        self.IPProxy.ids_mode = ip_proxy['ids_mode']

        rep_settings = ip_proxy['reputation']
        geo_settings = ip_proxy['geolocation']

        # used for categorizing private ip addresses
        geo_settings.update(RFC1918)

        reputation_enabled = []
        for cat, setting in rep_settings.items():
            if (setting): reputation_enabled.append(1)

            self.IPProxy.reputation_settings[REP[cat.upper()]] = DIR(setting)

        for country, direction in geo_settings.items():
            
            # using enum for category key and direction value
            try:
                self.IPProxy.geolocation_settings[GEO[country.upper()]] = DIR(direction)
            except KeyError:
                continue # not all enums/countries are populated

        self.IPProxy.reputation_enabled = bool(reputation_enabled)

        self.initialize.done()

    @cfg_read_poller('whitelist')
    def _get_ip_whitelist(self, cfg_file):
        whitelist = load_configuration(cfg_file)

        whitelist = whitelist['ip_bypass']
        self.IPProxy.ip_whitelist = {
            ip for ip, wl_info in whitelist.items() if wl_info['type'] == 'ip'
        }

        self.IPProxy.tor_whitelist = {
            ip for ip, wl_info in whitelist.items() if wl_info['type'] == 'tor'
        }

        self.initialize.done()

    @cfg_read_poller('ips')
    def _get_open_ports(self, cfg_file):
        ips = load_configuration(cfg_file)

        self.IPProxy.open_ports = {
            PROTO.TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips['open_protocols']['tcp'].items()
            },
            PROTO.UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips['open_protocols']['udp'].items()
            }
        }

        self.initialize.done()

    @staticmethod
    def _manage_ip_tables():
        IPTablesManager.clear_dns_over_https()
        IPTablesManager.update_dns_over_https()
