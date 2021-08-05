#!/usr/bin/env python3

import os, sys
import json

from subprocess import run
from socket import inet_aton
from struct import Struct
from array import array
from collections import defaultdict

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import GEO, MSB, LSB
from dnx_configure.dnx_file_operations import load_configuration

__all__ = (
    'combine_domains', 'combine_ips', 'generate_geolocation'
)

cidr_to_host_count = {f'{i}': 2**x for i, x in enumerate(reversed(range(31)), 2)}
ip_unpack = Struct('>L').unpack

def combine_domains(Log):
    dns_proxy = load_configuration('dns_proxy')

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
    ip_proxy = load_configuration('ip_proxy')

    ip_cat_signatures = []
    for cat in ip_proxy['categories']:
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_cat_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            Log.alert(f'signature file missing: {cat} ips.')

    with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'w+') as blocked:
        blocked.write('\n'.join(ip_cat_signatures))

    # NOTE: nulling out signatures in memory so we dont have to wait for GC.
    ip_cat_signatures = []

def _combine_geolocation(Log):
    ip_proxy = load_configuration('ip_proxy')

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
            host_count = int(cidr_to_host_count[subnet[1]])

            country = GEO[country.upper()]
        except Exception as E:
            Log.warning(f'invalid signature: {line}, {E}')

        else:
            # NOTE: subtracting 1 to account for 0th value.
            cvl_append(f'{net_id} {host_count-1} {country}')

    # NOTE: nulling out signatures in memory so we dont have to wait for GC.
    ip_geo_signatures = []

    # compression logic
    dict_nets = defaultdict(list)
    for signature in converted_list:

        net_id, ip_count, country = [int(x) for x in signature.split()]

        # assigning vars for bin id, host ranges, and ip count
        bin_id = net_id & MSB
        host_id_start = net_id & LSB

        host_container = [host_id_start, host_id_start+ip_count, country]

        dict_nets[bin_id].append(host_container)

    # merging contiguous ranges if within same country
    for bin_id, containers in dict_nets.items():
        dict_nets[bin_id] = _merge_geo_ranges(sorted(containers))

    nets = [
        (bin_id, tuple(array('l', host_container) for host_container in containers)) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    dict_nets = {}

    return tuple(nets)

def _merge_geo_ranges(ls):
    merged_item, merged_container = [], []
    for l in ls:

        cur_net_id, cur_broadcast, cur_country = l

        # applying current item to temp item since it didnt exist
        if (not merged_item):
            merged_item = l

        # currently have ongoing contiguous range.
        else:
            _, last_broadcast, last_country = merged_item

            # the networks are contiguous so we will merge them and update the temp item unless the countries are different
            # which treat the current container as non contiguous
            if (cur_net_id == last_broadcast+1 and cur_country == last_country):
                merged_item[1] = cur_broadcast

            # once a discontiguous range or new country is detected, the merged_item will get added to the merged list. this
            # finalized the container by incrementing the broadcast by 1 to accomodate range() non inclusivity, then
            # replaces the value of the ongoing merged_item with the current iteration list.
            else:
                merged_container.append(merged_item)

                merged_item = l

    # adding odd one out to merged container
    if (not merged_item or merged_item[-1] != l):
        merged_container.append(merged_item)

    return merged_container
