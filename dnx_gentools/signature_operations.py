#!/usr/bin/env python3

from __future__ import annotations

from socket import inet_aton
from struct import Struct
from collections import defaultdict

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, MSB, LSB, UINT32_MAX, RFC1918
from dnx_gentools.def_enums import GEO, REP, DNS_CAT
from dnx_gentools.file_operations import load_configuration

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T

__all__ = (
    'generate_domain', 'generate_reputation', 'generate_geolocation',
)

cidr_to_host_count: dict[str, int] = {f'{i}': 2**x for i, x in enumerate(reversed(range(31)), 2)}
ip_unpack: Callable[[bytes], tuple] = Struct('>L').unpack

def _combine_domain(log: LogHandler_T) -> list[str]:
    proxy_settings: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    domain_signatures: list = []

    default_cats: list = proxy_settings.get_list('categories->built-in')
    # iterating over the list of categories + DoH to load signature sets.
    for cat in [*default_cats, 'dns-over-https']:
        try:
            file = open(f'{HOME_DIR}/dnx_profile/signatures/domain_lists/{cat}.domains')
        except FileNotFoundError:
            log.alert(f'[missing] signature file: {cat} domains.')
        else:
            domain_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            file.close()

    ud_cats: list = proxy_settings.get_list('categories->custom')
    # TODO: user defined categories will break the enum load on proxy / FIX
    # NOTE: i think this will require a proxy restart if sigs change
    # looping over all user defined categories.
    for cat, settings in ud_cats:

        if (settings['enabled']):

            for signature in settings[1:]:
                domain_signatures.append(f'{signature} {cat}'.lower())

    return domain_signatures

def generate_domain(log: LogHandler_T) -> list[list[int, int]]:
    # getting all enabled signatures
    domain_signatures: list = _combine_domain(log)

    wl_exceptions: list = load_configuration('whitelist', cfg_type='global').get_list('pre_proxy')
    bl_exceptions: list = load_configuration('blacklist', cfg_type='global').get_list('pre_proxy')

    # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    domain_signatures.extend([f'{domain} blacklist' for domain in bl_exceptions])

    doms = []
    doms_append = doms.append
    for signature in domain_signatures:

        sig: list = signature.strip().split(maxsplit=1)
        try:
            # converting the hash to an unsigned 32 bit int to normalize for dnx tries
            hhash = hash(sig[0]) & UINT32_MAX
            cat = int(DNS_CAT[sig[1]])
        except Exception as E:
            log.warning(f'bad signature detected | {E} | {sig}')

        else:
            # pre proxy override check before adding
            if (sig[0] not in wl_exceptions):
                doms_append([hhash, cat])

    return doms

def _combine_reputation(log: LogHandler_T) -> list[str]:
    proxy_settings: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/ip')

    ip_rep_signatures: list = []
    for cat in proxy_settings.get_list('reputation'):
        try:
            with open(f'{HOME_DIR}/dnx_profile/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_rep_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[reputation] signature file missing: {cat}')

    return ip_rep_signatures

def generate_reputation(log: LogHandler_T) -> list[list[int, int]]:

    # getting all enabled signatures
    ip_rep_signatures: list = _combine_reputation(log)

    hosts = []
    hosts_append = hosts.append
    for signature in ip_rep_signatures:

        sig = signature.split()
        try:
            ip_addr = ip_unpack(inet_aton(sig[0]))[0]
            cat = int(REP[sig[1].upper()])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            hosts_append([ip_addr, cat])

    del ip_rep_signatures

    return hosts

def _combine_geolocation(log: LogHandler_T) -> list[str]:
    geo_settings: list = load_configuration('profiles/profile_1', cfg_type='security/ip').get_list('geolocation')

    # adding private ip space signatures because they are currently excluded from webui. (by design... for now)
    geo_settings.append(RFC1918[0])

    ip_geo_signatures: list = []
    # restricting iteration to explicitly defined rules in the configuration file instead of assuming all files in the
    # signature folder are good to load in.
    for country in geo_settings:
        try:
            with open(f'{HOME_DIR}/dnx_profile/signatures/geo_lists/{country}.geo', 'r') as file:
                ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[geolocation] signature file missing: {country}')

    return ip_geo_signatures

def generate_geolocation(log: LogHandler_T) -> list[list[int, list[int, int, int]]]:
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

            subnet: list = net.split('/')
            net_id:  int = ip_unpack(inet_aton(subnet[0]))[0]
            h_count: int = cidr_to_host_count[subnet[1]]

            country = int(GEO[cat.upper()])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            # needed to account for MSB/bin_id overflows
            while h_count > LSB+1:
                cvl_append(f'{net_id} {LSB} {country}')

                h_count -= LSB + 1
                net_id  += LSB + 1

            # NOTE: -1 to step down to bcast value
            cvl_append(f'{net_id} {h_count-1} {country}')

    del ip_geo_signatures

    # compression logic
    dict_nets = defaultdict(list)
    for signature in converted_list:

        net_id, ip_count, country = [int(x) for x in signature.split()]

        # assigning vars for bin id, host ranges, and ip count
        bin_id  = net_id & MSB
        host_id = net_id & LSB

        dict_nets[bin_id].append([host_id, host_id + ip_count, country])

    # merging contiguous ranges if within the same country
    for bin_id, containers in dict_nets.items():
        dict_nets[bin_id] = _merge_geo_ranges(sorted(containers))

    nets = [[bin_id, containers] for bin_id, containers in dict_nets.items()]
    nets.sort()

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
            # if countries are different, we will treat the current container as not contiguous
            if (cur_net_id == last_broadcast+1 and cur_country == last_country):
                merged_item[1] = cur_broadcast

            # once a discontiguous range or new country is detected, the merged_item will get added to the merged list.
            # swaps the value of the ongoing merged_item with the current iteration list.
            else:
                merged_containers.append(merged_item)

                merged_item = l

    # adding odd one out to the merged container
    if (not merged_item or merged_item[-1] != l):
        merged_containers.append(merged_item)

    return merged_containers
