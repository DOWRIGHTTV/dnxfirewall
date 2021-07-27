#!/usr/bin/env python3

import os, sys
import json

from subprocess import run
from socket import inet_aton
from struct import Struct

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import GEO
from dnx_configure.dnx_file_operations import load_configuration

__all__ = (
    'combine_domains', 'combine_ips', 'combine_geolocation',
    'generate_geolocation'
)

ip_unpack = Struct('>L').unpack

cidr_to_host_count = {
    '1': 4294967296,
    '2': 2147483648,
    '3': 1073741824,
    '4': 536870912,
    '5': 268435456,
    '6': 134217728,
    '7': 67108864,
    '8': 33554432,
    '9': 16777216,
    '10': 8388608,
    '11': 4194304,
    '12': 2097152,
    '13': 1048576,
    '14': 524288,
    '15': 262144,
    '16': 131072,
    '17': 65536,
    '18': 32768,
    '19': 16384,
    '20': 8192,
    '21': 4096,
    '22': 2048,
    '23': 1024,
    '24': 512,
    '25': 256,
    '26': 128,
    '27': 64,
    '28': 32,
    '29': 16,
    '30': 4,
    '31': 2,
    '32': 1
}

def combine_domains(Log):
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
            Log.alert('signature file missing: {cat} domains.')

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
    domain_signatures = []

def combine_ips(Log):
    ip_proxy = load_configuration('ip_proxy')['ip_proxy']

    ip_cat_signatures = []
    for cat in ip_proxy['categories']:
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_cat_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            Log.alert(f'signature file missing: {sig} ips.'')

    with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'w+') as blocked:
        blocked.write('\n'.join(ip_cat_signatures))

    # NOTE: nulling out signatures in memory so we dont have to wait for GC.
    ip_cat_signatures = []

def _combine_geolocation(Log):
    ip_proxy = load_configuration('ip_proxy')['ip_proxy']

    ip_geo_signatures = []
    for country in ip_proxy['geolocation']:
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/{country}.geo', 'r') as file:
                ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            Log.alert(f'signature file missing: {country} geolocation.')

    return ip_geo_signatures

# NOTE: new method to convert standard signatures into a compressed integer format. This will completely replace file operations function since we are
# no longer generating a combined file and will do the merge and convert in memory before returning compressed structure.
def generate_geolocation(Log):

    # getting all enabled signatures
    ip_geo_signatures = _combine_geolocation(Log)

    converted_list = []
    cvl_append = converted_list.append

    ## conversion logic
    for line in ip_geo_signatures:

        try:
            subnet, country = line.split()

            subnet = subnet.split('/')
            net_id = ip_unpack(inet_aton(subnet[0]))[0]
            host_count = cidr_to_host_count[subnet[1]]

            country = GEO[country.upper()]
        except Exception as E:
            Log.warning(f'invalid signature: {line}, {E}')

        else:
            cvl_append(f'{net_id} {host_count} {country}')

    # NOTE: nulling out signatures in memory so we dont have to wait for GC.
    ip_geo_signatures = []

    # compression logic (currently not compressing contiguous networks)
    dict_nets = {}
    for signature in converted_list:

        net_id, ip_count, country = [int(x) for x in signature.split()]

        # assigning vars for bin id, host ranges, and ip count
        ip_list = range(net_id, net_id + ip_count)
        if (ip_count < LSB):
            bin_id = net_id & MSB
            host_id_start = net_id & LSB

            host_container = [host_id_start, host_id_start+ip_count, country]
            # initializing key/ empty list as a defaultdict replacement
            if (bin_id not in dict_nets):
                initial_list = [host_container]
                dict_nets[bin_id] = initial_list

                continue

            dict_nets[bin_id].append(host_container)

        else:
            offset = 0
            while True:
                current_ip_index = ip_list[offset]
                bin_id = current_ip_index & MSB

                # initializing key/ empty list as a defaultdict replacement
                if (bin_id not in dict_nets):
                    bin_id_list = []
                    dict_nets[bin_id] = bin_id_list

                else:
                    bin_id_list = dict_nets[bin_id]

                remaining_ips = ip_count - offset
                if (remaining_ips <= LSB):
                    host_container = [current_ip_index, current_ip_index+remaining_ips, country]
                    bin_id_list.append(host_container)

                    break

                else:
                    host_container = [current_ip_index, LSB, country]
                    bin_id_list.append(host_container)

                    offset += LSB

    nets = [(bin_id, tuple(tuple(host_container) for host_container in sorted(bin_container))) for bin_id, bin_container in dict_nets.items()]
    nets.sort()

    dict_nets, converted_list = {}, []

    return tuple(nets)
