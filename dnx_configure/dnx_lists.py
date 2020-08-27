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

    def combine_domains(self):
        dns_proxy = load_configuration('dns_proxy')['dns_proxy']

        default_cats = dns_proxy['categories']['default']
        ud_cats      = dns_proxy['categories']['user_defined']

        domain_signatures = []
        # iterating over list of categories + DoH to load signaure sets.
        for cat in [*default_cats, 'dns-over-https']:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/{cat}.domains', 'r') as file:
                    domain_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {cat}.domains file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/blocked.domains', 'w+') as blocked:
            blocked.write('\n'.join(domain_signatures))

            # TODO: user defined categories will break the enum load on proxy / FIX
            # looping over all user defined categories. ALSO. i think this will require a proxy restart if sigs change
            for cat, settings in ud_cats:
                if (not settings['enabled']): continue

                # writing signatures to block file
                for signature in settings[1:]:
                    blocked.write(f'{signature} {cat}\n'.lower())

        # NOTE: nulling out signatures in memory so we dont have to wait for GC.
        self.dom_signatures = None

    def combine_ips(self):
        ip_proxy = load_configuration('ip_proxy')['ip_proxy']

        ip_cat_signatures = []
        for sig in ip_proxy['categories']:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{sig}.ips', 'r') as file:
                    ip_cat_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {file}.ips file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'w+') as blocked:
            blocked.write('\n'.join(ip_cat_signatures))

        # overriding list to not wait for gc
        ip_cat_signatures = None

    def combine_geolocation(self):
        ip_proxy = load_configuration('ip_proxy')['ip_proxy']

        ip_geo_signatures = []
        for country in ip_proxy['geolocation']:
            try:
                with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/{country}.geo', 'r') as file:
                    ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
            except FileNotFoundError:
                self.Log.alert(f'Unable to locate {country} geolocation file. Contact Support.')

        with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/blocked.geo', 'w+') as blocked:
            blocked.write('\n'.join(ip_geo_signatures))

        # overriding list to not wait for gc
        ip_geo_signatures = None
