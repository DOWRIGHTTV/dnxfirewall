#!/usr/bin/env python3

import os, sys
import time
import json
import threading

from ipaddress import IPv4Network

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_file_operations import load_configuration, cfg_read_poller, load_geo_bitmap, load_ip_bitmap
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_iptables import IPTableManager
from dnx_iptools.dnx_standard_tools import Initialize

from ip_proxy.ip_proxy_log import Log


class Configuration:
    _setup = False

    def __init__(self, name):
        self.initialize = Initialize(Log, name)

    @classmethod
    def setup(cls, IPProxy):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')

        cls._setup = True

        self = cls(IPProxy.__name__)
        self.IPProxy = IPProxy

        self._load_interfaces()
        self._manage_ip_tables()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_ip_whitelist).start()
        threading.Thread(target=self._get_open_ports).start()

        self.initialize.wait_for_threads(count=3)

    def _load_interfaces(self):
        dnx_settings = load_configuration('config')['settings']

        lan_net = dnx_settings['interfaces']['lan']['subnet']
        self.IPProxy.lan_net = IPv4Network(lan_net)

    @cfg_read_poller('ip_proxy')
    def _get_settings(self, cfg_file):
        ip_proxy = load_configuration(cfg_file)['ip_proxy']

        cat_settings = ip_proxy['categories']
        geo_settings = ip_proxy['geolocation']

        cat_enabled = []
        for cat, setting in cat_settings.items():
            if (setting): cat_enabled.append(1)

            self.IPProxy.cat_settings[IPP_CAT[cat.upper()]] = DIR(setting)

        geo_enabled = []
        for cat, setting in geo_settings.items():
            if (setting): geo_enabled.append(1)

            # using enum for category key and direction value
            try:
                self.IPProxy.geo_settings[GEO[cat.upper()]] = DIR(setting)
            except KeyError:
                continue # NOTE: temporary while not all enums/countries are populated

        self.IPProxy.inspect_on  = bool(cat_enabled or geo_enabled)
        self.IPProxy.cat_enabled = bool(cat_enabled)
        self.IPProxy.geo_enabled = bool(geo_enabled)
        self.IPProxy.ids_mode = ip_proxy['ids_mode']

        self.initialize.done()

    @cfg_read_poller('whitelist')
    def _get_ip_whitelist(self, cfg_file):
        whitelist = load_configuration(cfg_file)['whitelist']

        whitelist = whitelist['ip_whitelist']
        self.IPProxy.ip_whitelist = {
            ip for ip, wl_info in whitelist.items() if wl_info['type'] == 'ip'
        }

        self.IPProxy.tor_whitelist = {
            ip for ip, wl_info in whitelist.items() if wl_info['type'] == 'tor'
        }

        self.initialize.done()

    @cfg_read_poller('ips')
    def _get_open_ports(self, cfg_file):
        ips = load_configuration(cfg_file)['ips']

        open_tcp_ports = ips['open_protocols']['tcp']
        open_udp_ports = ips['open_protocols']['udp']
        self.IPProxy.open_ports = {
            PROTO.TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in open_tcp_ports.items()
            },
            PROTO.UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in open_udp_ports.items()
            }
        }

        self.initialize.done()

    def _manage_ip_tables(self):
        IPTableManager.clear_dns_over_https()
        IPTableManager.update_dns_over_https()

    @staticmethod
    # Loading lists of interesting traffic into dictionaries and creating ip table rules for dns over https blocking
    def load_ip_signature_bitmaps():
        list_files = ListFiles(Log=Log)
        list_files.combine_ips()
        list_files.combine_geolocation()

        ip_category_signatures = load_ip_bitmap(Log)
        geolocation_signatures = load_geo_bitmap(Log)

        return ip_category_signatures, geolocation_signatures
