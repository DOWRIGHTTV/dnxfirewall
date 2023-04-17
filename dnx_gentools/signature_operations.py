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

# cidr_to_host_count: dict[str, int] = {f'{i}': 2**x for i, x in enumerate(reversed(range(31)), 2)}
ip_unpack: Callable[[bytes], tuple] = Struct('>L').unpack

def _combine_domain(log: LogHandler_T) -> list[str]:
    '''returns an aggregated list of all plain text domain based signatures.
    '''
    proxy_settings: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    domain_category_labels = proxy_settings.get_list('categories->built-in')

    domain_categories = ['dns_https']
    for label in domain_category_labels:

        domain_categories.extend(proxy_settings.get_list(f'categories->built-in->{label}'))

    domain_signatures = []
    # iterating over the list of categories + DoH to load signature sets.
    for category in domain_categories:
        try:
            file = open(f'{HOME_DIR}/dnx_profile/signatures/domain_lists/{category}.domains')
        except FileNotFoundError:
            log.alert(f'[missing] signature file: {category} domains.')
        else:
            domain_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            file.close()

    # NOTE: currently not available while this system is being reworked for profiles + webui
    # ud_cats: list = proxy_settings.get_list('categories->custom')
    # # TODO: user defined categories will break the enum load on proxy / FIX
    # # NOTE: i think this will require a proxy restart if sigs change
    # # looping over all user defined categories.
    # for cat, settings in ud_cats:
    #
    #     if (settings['enabled']):
    #
    #         for signature in settings[1:]:
    #             domain_signatures.append(f'{signature} {cat}'.lower())

    return domain_signatures

def generate_domain(log: LogHandler_T) -> list[list[int, int]]:
    '''returns a list containing the aggregated domain based signatures.

        each signature is a key/value pair (as list) -> [hash of the domain, category id]
    '''
    domain_signatures: list[str] = _combine_domain(log)

    # NOTE: currently not available while this system is being reworked for profiles + webui
    # wl_exceptions: list = load_configuration('whitelist', cfg_type='global').get_list('pre_proxy')
    # bl_exceptions: list = load_configuration('blacklist', cfg_type='global').get_list('pre_proxy')
    #
    # # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    # domain_signatures.extend([f'{domain} blacklist' for domain in bl_exceptions])

    doms = []
    doms_append = doms.append
    for signature in domain_signatures:

        sig = signature.strip().split(maxsplit=1)
        try:
            # converting the hash to an unsigned 32 bit int to normalize for dnx tries
            hhash = hash(sig[0]) & UINT32_MAX
            cat_id = int(DNS_CAT[sig[1]])
        except Exception as E:
            log.warning(f'bad signature detected | {E} | {sig}')

        else:
            # NOTE: same as above
            # pre proxy override check before adding
            # if (sig[0] not in wl_exceptions):
            doms_append([hhash, cat_id])

    return doms

def _combine_reputation(log: LogHandler_T) -> tuple[list[str], dict[str, int]]:
    '''returns an aggregated list of all plain text reputation based signatures.
    '''
    proxy_settings: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/ip')
    reputation_categories = proxy_settings.get_list('reputation->built-in')

    reputation_priority = proxy_settings.get_dict('reputation->priority')

    ip_rep_signatures = []
    for category in reputation_categories:
        try:
            with open(f'{HOME_DIR}/dnx_profile/signatures/ip_lists/{category}.ips', 'r') as file:
                ip_rep_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[reputation] signature file missing: {category}')

    return ip_rep_signatures, reputation_priority

def generate_reputation(log: LogHandler_T) -> list[list[int, int]]:
    '''returns a list containing the aggregated reputation based signatures.

    each signature is a key/value pair -> {ip_addr (as int): (rep priority, category id)}
    '''
    ip_rep_signatures, reputation_priority = _combine_reputation(log)

    hosts_with_dup = defaultdict(list)
    for signature in ip_rep_signatures:

        sig = signature.split()
        try:
            ip_addr = ip_unpack(inet_aton(sig[0]))[0]
            cat_id = int(REP[sig[1].upper()])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            hosts_with_dup[ip_addr].append((reputation_priority[sig[1]], cat_id))

    # removing temporary structure from memory
    del ip_rep_signatures

    # this routine ensures the highest priority category is used for a host with multiple memberships
    hosts_final = []
    for host, cats in hosts_with_dup.items():

        # sorting to bring the lowest number (highest priority) to the front, then grabbing the cat id from the tuple.
        hosts_final.append([host, sorted(cats)[0][1]])

    return hosts_final

def _combine_geolocation(log: LogHandler_T) -> list[str]:
    '''returns an aggregated list of all plain text geolocation based signatures.
    '''
    # geo_settings: list = load_configuration('profiles/profile_1', cfg_type='security/ip').get_list('geolocation')
    #
    # # adding private ip space signatures because they are currently excluded from webui. (by design... for now)
    # geo_settings.append(RFC1918[0])
    #
    # ip_geo_signatures: list = []
    # # restricting iteration to explicitly defined rules in the configuration file instead of assuming all files in the
    # # signature folder are good to load in.
    # for country in geo_settings:
    #     try:
    #         with open(f'{HOME_DIR}/dnx_profile/signatures/geo_lists/{country}.geo', 'r') as file:
    #             ip_geo_signatures.extend([x for x in file.read().splitlines() if x and '#' not in x])
    #     except FileNotFoundError:
    #         log.alert(f'[geolocation] signature file missing: {country}')
    #
    # return ip_geo_signatures

    # filtering out ranges with an undefined country
    # TODO: make sure rfc1918 is being added to the list
    try:
        with open(f'{HOME_DIR}/dnx_profile/signatures/geo_lists/collection.geo', 'r') as collection:
            return [x for x in collection.read().splitlines() if not x.endswith('-')]
    except FileNotFoundError:
        log.alert('[geolocation] signature file missing.')

        return []

def generate_geolocation(log: LogHandler_T) -> list[list[int, list[int, int, int]]]:
    '''
    Convert standard signatures into a compressed integer format. This will completely replace file operations function
    since we are no longer generating a combined file and will do the merge and convert in memory before returning
    compressed structure.
    '''
    ip_geo_signatures = _combine_geolocation(log)
    # =================================
    # CONVERSION LOGIC
    # =================================
    converted_list = []
    cvl_append = converted_list.append

    for signature in ip_geo_signatures:

        try:
            sig = signature.split(',', 2)

            network_id = int(sig[0])
            host_count = int(sig[1])

            country = sig[2].upper()

            cat_id = int(GEO[country])
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            # needed to account for MSB/bin_id overflows
            while host_count > LSB+1:
                cvl_append(f'{network_id} {LSB} {cat_id}')

                host_count -= LSB + 1
                network_id += LSB + 1

            # NOTE: -1 to step down to bcast value  // not needed with new ip2l format
            # cvl_append(f'{net_id} {h_count-1} {country}')

            cvl_append(f'{network_id} {host_count} {cat_id}')

    # removing temporary structure from memory
    del ip_geo_signatures
    # =================================
    # COMPRESSION LOGIC
    # =================================
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

    # removing temporary structure from memory
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
