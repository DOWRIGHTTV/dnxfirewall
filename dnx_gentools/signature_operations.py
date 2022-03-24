#!/usr/bin/env python3

from __future__ import annotations

from ctypes import c_uint16, c_uint32
from socket import inet_aton
from struct import Struct
from collections import defaultdict

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, MSB, LSB, DNS_BIN_OFFSET, RFC1918
from dnx_gentools.def_enums import GEO, REP, DNS_CAT
from dnx_gentools.file_operations import load_configuration

from dnx_iptools.protocol_tools import mhash

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain

__all__ = (
    'generate_domain', 'generate_reputation', 'generate_geolocation',
)

cidr_to_host_count: dict[str, int] = {f'{i}': 2**x for i, x in enumerate(reversed(range(31)), 2)}
ip_unpack: Callable[[bytes], tuple] = Struct('>L').unpack

def _combine_domain(log: LogHandler_T) -> list[str]:
    proxy_settings: ConfigChain = load_configuration('dns_proxy')

    domain_signatures: list = []

    default_cats: list = proxy_settings.get_list('categories->default')
    # iterating over the list of categories + DoH to load signature sets.
    for cat in [*default_cats, 'dns-over-https']:
        try:
            file = open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/{cat}.domains')
        except FileNotFoundError:
            log.alert(f'[missing] signature file: {cat} domains.')
        else:
            domain_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            file.close()

    ud_cats: list = proxy_settings.get_list('categories->user_defined')
    # TODO: user defined categories will break the enum load on proxy / FIX
    # NOTE: i think this will require a proxy restart if sigs change
    # looping over all user defined categories.
    for cat, settings in ud_cats:

        if (settings['enabled']):

            for signature in settings[1:]:
                domain_signatures.append(f'{signature} {cat}'.lower())

    return domain_signatures

def generate_domain(log: LogHandler_T) -> list[list[c_uint32, list[c_uint32, c_uint16]]]:
    # getting all enabled signatures
    domain_signatures: list = _combine_domain(log)

    wl_exceptions: list = load_configuration('whitelist').get_list('pre_proxy')
    bl_exceptions: list = load_configuration('blacklist').get_list('pre_proxy')

    dict_nets = defaultdict(list)

    # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    domain_signatures.extend([f'{domain} blacklist' for domain in bl_exceptions])

    for signature in domain_signatures:

        sig: list = signature.strip().split(maxsplit=1)
        try:
            hhash = mhash(sig[0]) >> 1
            host_hash: str = f'{hhash}'

            cat = int(DNS_CAT[sig[1]])
        except Exception as E:
            log.warning(f'bad signature detected | {E} | {sig}')

        else:
            # pre proxy override check before adding
            if (sig[0] not in wl_exceptions):
                bin_id  = int(host_hash[:DNS_BIN_OFFSET])
                host_id = c_uint32(int(host_hash[DNS_BIN_OFFSET:]))

                try:
                    dict_nets[bin_id].append([host_id, cat])
                except Exception as E:
                    log.warning(f'bad signature detected | {E} | {sig}')

    # in place sort of all containers prior to building the structure
    for containers in dict_nets.values():
        containers.sort()

        # ctypes dont have comparison operators
        for container in containers:
            container[0] = c_uint32(container[0])

    # converting to nested tuple and sorting with the outermost list converted on return
    nets = [[bin_id, containers] for bin_id, containers in dict_nets.items()]
    nets.sort()

    for li in nets:
        li[0] = c_uint32(li[0])

    # no longer needed so ensuring memory gets freed
    del dict_nets

    return nets

def _combine_reputation(log: LogHandler_T) -> list[str]:
    proxy_settings: ConfigChain = load_configuration('ip_proxy')

    ip_rep_signatures: list = []
    for cat in proxy_settings.get_list('reputation'):
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_rep_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[reputation] signature file missing: {cat}')

    return ip_rep_signatures

def generate_reputation(log: LogHandler_T) -> list[list[c_uint32, list[c_uint32, c_uint16]]]:

    # getting all enabled signatures
    ip_rep_signatures: list = _combine_reputation(log)

    dict_nets = defaultdict(list)

    for signature in ip_rep_signatures:

        sig = signature.split()
        try:
            ip_addr = ip_unpack(inet_aton(sig[0]))[0]

            cat = int(REP[sig[1].upper()])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')
            continue

        bin_id  = ip_addr & MSB
        host_id = ip_addr & LSB

        dict_nets[bin_id].append([host_id, cat])

    # in place sort of all containers prior to building the structure
    for containers in dict_nets.values():
        containers.sort()

        # ctypes dont have comparison operators
        for container in containers:
            container[0] = c_uint32(container[0])

    # converting to nested tuple and sorting.
    # outermost list converted on return
    nets = [[bin_id, containers] for bin_id, containers in dict_nets.items()]
    nets.sort()

    for li in nets:
        li[0] = c_uint32(li[0])

    del dict_nets, ip_rep_signatures

    return nets

def _combine_geolocation(log: LogHandler_T) -> list[str]:
    geo_settings: list = load_configuration('ip_proxy').get_list('geolocation')

    # adding private ip space signatures because they are currently excluded from webui. (by design... for now)
    geo_settings.extend(RFC1918.keys())

    ip_geo_signatures: list = []
    # restricting iteration to explicitly defined rules in the configuration file instead of assuming all files in the
    # signature folder are good to load in.
    for country in geo_settings:
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/{country}.geo', 'r') as file:
                ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[geolocation] signature file missing: {country}')

    return ip_geo_signatures

def generate_geolocation(log: LogHandler_T) -> list[list[c_uint32, list[c_uint32, c_uint32, c_uint16]]]:
    '''
    Convert standard signatures into a compressed integer format. This will completely replace file operations function
    since we are no longer generating a combined file and will do the merge and convert in memory before returning
    compressed structure.
    '''
    # getting all enabled signatures
    ip_geo_signatures: list = _combine_geolocation(log)

    converted_list: list = []
    cvl_append = converted_list.append

    # conversion logic
    for signature in ip_geo_signatures:

        try:
            net, cat = signature.split()

            snet: list = net.split('/')
            nid: int = ip_unpack(inet_aton(snet[0]))[0]
            hcount = int(cidr_to_host_count[snet[1]])

            cat = int(GEO[cat.upper()])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            # needed to account for MSB/bin_id overflows
            while hcount > LSB+1:
                cvl_append(f'{nid} {LSB} {cat}')

                hcount -= (LSB+1)
                nid += (LSB+1)

            # NOTE: -1 to step down to bcast value
            cvl_append(f'{nid} {hcount-1} {cat}')

    del ip_geo_signatures

    # compression logic
    dict_nets = defaultdict(list)
    for signature in converted_list:

        sig = [int(x) for x in signature.split()]

        net_id:   int = sig[0]
        ip_count: int = sig[1]
        country:  int = sig[2]

        # assigning vars for bin id, host ranges, and ip count
        bin_id = net_id & MSB
        host_id_r1 = net_id & LSB
        host_id_r2 = (net_id & LSB) + ip_count
        cty = c_uint16(country)

        dict_nets[bin_id].append([host_id_r1, host_id_r2, cty])

    # merging contiguous ranges if within the same country
    for bin_id, containers in dict_nets.items():
        dict_nets[bin_id] = _merge_geo_ranges(sorted(containers))

        # ctypes dont have comparison operators
        for container in dict_nets[bin_id]:
            container[0] = c_uint32(container[0])
            container[1] = c_uint32(container[1])

    # NOTE: reduced list comprehension now that extra compression is re implemented, which converts to
    # tuple once it is completed with host containers, then again on the bin itself.
    nets = [[bin_id, containers] for bin_id, containers in dict_nets.items()]
    nets.sort()

    # ctypes do not have comparison operations
    for li in nets:
        li[0] = c_uint32(li[0])

    del dict_nets

    return nets

def _merge_geo_ranges(ls: list, /) -> list[list]:
    merged_item, merged_containers, l = [], [], object()
    for l in ls:

        cur_net_id, cur_broadcast, cur_country = l

        # applying current item to temp item since it didn't exist
        if (not merged_item):
            merged_item = l

        # ongoing contiguous range.
        else:
            _, last_broadcast, last_country = merged_item

            # the networks are contiguous, so we will merge them and update the temp item.
            # if the countries are different, well treat the current container as not contiguous
            if (cur_net_id == last_broadcast+1 and cur_country == last_country):
                merged_item[1] = cur_broadcast

            # once a discontiguous range or new country is detected, the merged_item will get added to the merged list.
            # convert host container to a tuple while we have it here now, which should reduce the list comprehension
            # complexity. after, replace the value of the ongoing merged_item with the current iteration list to
            # continue process.
            else:
                merged_containers.append(merged_item)

                merged_item = l

    # adding odd one out to the merged container
    if (not merged_item or merged_item[-1] != l):
        merged_containers.append(merged_item)

    # converting bin to tuple here. this should reduce the list comprehension complexity on return.
    return merged_containers
