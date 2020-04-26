#!/usr/bin/env python3

import os, sys
import json

from subprocess import run

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import load_configuration

__all__ = (
    'ListFiles'
)


class ListFiles:
    def __init__(self, *, Log):
        self.Log = Log
        self.combine_dom_files  = ['dns-over-https']
        self.combine_ip_files   = []
        self.dom_signatures     = []
        self.ip_cat_signatures  = []
        self.ip_geo_signatures  = []
        self.keyword_categories = set()

    def combine_domains(self):
        dns_proxy_categories = load_configuration('dns_proxy')

        categories   = dns_proxy_categories['dns_proxy']['categories']
        default_cats = categories['default']
        ud_cats      = categories['user_defined']

        for cat, settings in default_cats.items():
            # NOTE: this will prevent loading disabled configs to memory. maybe make it a user configurable option later?
#            if (not settings['enabled']): continue

            self.combine_dom_files.append(cat)

        for file in self.combine_dom_files:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/{file}.domains', 'r') as file:
                    self.dom_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {file}.domains file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/blocked.domains', 'w+') as blocked:
            blocked.write('\n'.join(self.dom_signatures))

            # TODO: user defined categories will break the enum load on proxy / FIX
            # looping over all user defined categories
            for cat, settings in ud_cats:
                if (not settings['enabled']): continue

                # writing signatures to block file
                for signature in settings[1:]:
                    blocked.write(f'{signature} {cat}\n'.lower())

        # NOTE: nulling out signatures in memory so we dont have to wait for GC.
        self.dom_signatures = None

    def combine_ips(self):
        ip_proxy_categories = load_configuration('ip_proxy')

        ip_cats = ip_proxy_categories['ip_proxy']['categories']
        for sig in ip_cats:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{sig}.ips', 'r') as file:
                    self.ip_cat_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {file}.ips file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'w+') as blocked:
            blocked.write('\n'.join(self.ip_cat_signatures))

        self.ip_cat_signatures = None

    def combine_geolocation(self):
        ip_proxy_categories = load_configuration('ip_proxy')

        ip_geo = ip_proxy_categories['ip_proxy']['geolocation']
        for country in ip_geo:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/{country}.geo', 'r') as file:
                    self.ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {country} geolocation file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/blocked.geo', 'w+') as blocked:
            blocked.write('\n'.join(self.ip_geo_signatures))

        self.ip_geo_signatures = None
