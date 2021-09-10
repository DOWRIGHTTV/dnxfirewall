#!/usr/bin/env python3

import os, sys
import json

from subprocess import run
from socket import inet_aton
from struct import Struct
from array import array
from collections import defaultdict

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import GEO, REP, MSB, LSB
from dnx_sysmods.configure.file_operations import load_configuration

__all__ = (
    'combine_domains', 'generate_reputation', 'generate_geolocation',
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
            Log.alert(f'signature file missing: {cat} domains.')

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

def _combine_reputation(Log):
    ip_proxy = load_configuration('ip_proxy')

    ip_rep_signatures = []
    for cat in ip_proxy['reputation']:
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_rep_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            Log.alert(f'signature file missing: {cat} ips.')

    return ip_rep_signatures

def generate_reputation(Log):

    # getting all enabled signatures
    ip_rep_signatures = _combine_reputation(Log)

    dict_nets = defaultdict(list)

    for signature in ip_rep_signatures:

        sig = signature.split()
        try:
            ip_addr = ip_unpack(inet_aton(sig[0]))[0]

            cat = REP[sig[1].upper()]
        except Exception as E:
            Log.warning(f'invalid signature: {signature}, {E}')
            continue

        bin_id  = ip_addr & MSB
        host_id = ip_addr & LSB

        dict_nets[bin_id].append((host_id, cat))

    # in place sort of all containers prior to building the structure
    for containers in dict_nets.values():
        containers.sort()

    # converting to nested tuple and sorting, outermost list converted on return
    nets = [
        (bin_id, tuple(containers)) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    dict_nets, ip_rep_signatures = {}, []

    return tuple(nets)

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

    # conversion logic
    for signature in ip_geo_signatures:

        try:
            subnet, country = signature.split()

            subnet = subnet.split('/')
            net_id = ip_unpack(inet_aton(subnet[0]))[0]
            host_count = int(cidr_to_host_count[subnet[1]])

            country = GEO[country.upper()]
        except Exception as E:
            Log.warning(f'invalid signature: {signature}, {E}')

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

        dict_nets[bin_id].append([host_id_start, host_id_start+ip_count, country])

    # merging contiguous ranges if within same country
    for bin_id, containers in dict_nets.items():
        dict_nets[bin_id] = _merge_geo_ranges(sorted(containers))

    # NOTE: reduced list comprehension now that extra compression is re implemented, which converts to
    # tuple once it is completed with host containers, then again on the bin itself.
    nets = [
        (bin_id, containers) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    dict_nets = {}

    return tuple(nets)

def _merge_geo_ranges(ls):
    merged_item, merged_containers = [], []
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

            # once a discontiguous range or new country is detected, the merged_item will get added to the merged list. convert
            # host container to a tuple while we have it here now, which should reduce the list comprehension complexity.
            # after, replace the value of the ongoing merged_item with the current iteration list to continue process.
            # NOTE/TODO: this is where we can implement the array, instead of convering after returned.
            else:
                merged_containers.append(tuple(merged_item))

                merged_item = l

    # adding odd one out to merged container
    if (not merged_item or merged_item[-1] != l):
        merged_containers.append(tuple(merged_item))

    # converting bin to tuple here. this should reduce list comprehension complexity on return.
    return tuple(merged_containers)
