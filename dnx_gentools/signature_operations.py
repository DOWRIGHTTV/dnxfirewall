#!/usr/bin/env python3

from __future__ import annotations

from socket import inet_aton
from struct import Struct
from collections import defaultdict

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, MSB, LSB, DNS_BIN_OFFSET, RFC1918
from dnx_gentools.def_enums import GEO, REP, DNS_CAT
from dnx_gentools.file_operations import load_configuration

__all__ = (
    'generate_domain', 'generate_reputation', 'generate_geolocation',
)

cidr_to_host_count: dict[str, int] = {f'{i}': 2**x for i, x in enumerate(reversed(range(31)), 2)}
ip_unpack: Callable[[bytes], tuple] = Struct('>L').unpack

def _combine_domain(log: LogHandler_T) -> list[str]:
    dns_proxy: ConfigChain = load_configuration('dns_proxy')

    domain_signatures: list = []

    default_cats: list = dns_proxy.get_list('categories->default')
    # iterating over list of categories + DoH to load signature sets.
    for cat in [*default_cats, 'dns-over-https']:
        try:
            file = open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/{cat}.domains')
        except FileNotFoundError:
            log.alert(f'[missing] signature file: {cat} domains.')
        else:
            domain_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
            file.close()

    ud_cats: list = dns_proxy.get_list('categories->user_defined')
    # TODO: user defined categories will break the enum load on proxy / FIX
    # NOTE: i think this will require a proxy restart if sigs change
    # looping over all user defined categories.
    for cat, settings in ud_cats:

        if (settings['enabled']):

            for signature in settings[1:]:
                domain_signatures.append(f'{signature} {cat}'.lower())

    return domain_signatures

def generate_domain(log: LogHandler_T) -> tuple[tuple[int, tuple[int, int]]]:
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
            host_hash: str = f'{hash(sig[0])}'
            cat: int = int(DNS_CAT[sig[1]])
        except Exception as E:
            log.warning(f'bad signature detected | {E} | {sig}')

        else:
            # pre proxy override check before adding
            if (sig[0] not in wl_exceptions):
                dict_nets[int(host_hash[:DNS_BIN_OFFSET])].append((int(host_hash[DNS_BIN_OFFSET:]), cat))

    # in place sort of all containers prior to building the structure
    for containers in dict_nets.values():
        containers.sort()

    # converting to nested tuple and sorting with the outermost list converted on return
    nets: list[tuple[int, tuple[int, int]]] = [
        (bin_id, tuple(containers)) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    # no longer needed so ensuring memory gets freed
    del dict_nets

    return tuple(nets)

def _combine_reputation(log: LogHandler_T) -> list[str]:
    ip_proxy: ConfigChain = load_configuration('ip_proxy')

    ip_rep_signatures: list = []
    for cat in ip_proxy.get_list('reputation'):
        try:
            with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/{cat}.ips', 'r') as file:
                ip_rep_signatures.extend([x.lower() for x in file.read().splitlines() if x and '#' not in x])
        except FileNotFoundError:
            log.alert(f'[reputation] signature file missing: {cat}')

    return ip_rep_signatures

def generate_reputation(log: LogHandler_T) -> tuple[tuple[int, tuple[int, REP]]]:

    # getting all enabled signatures
    ip_rep_signatures: list = _combine_reputation(log)

    dict_nets: defaultdict[int, Union[list[tuple[int, REP]], tuple[tuple[int, REP]]]] = defaultdict(list)

    for signature in ip_rep_signatures:

        sig = signature.split()
        try:
            ip_addr = ip_unpack(inet_aton(sig[0]))[0]

            cat = REP[sig[1].upper()]
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')
            continue

        bin_id:  int = ip_addr & MSB
        host_id: int = ip_addr & LSB

        dict_nets[bin_id].append((host_id, cat))

    # in place sort of all containers prior to building the structure
    for containers in dict_nets.values():
        containers.sort()

    # converting to nested tuple and sorting, outermost list converted on return
    nets: list[tuple[int, tuple[int, REP]]] = [
        (bin_id, tuple(containers)) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    del dict_nets, ip_rep_signatures

    return tuple(nets)

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

def generate_geolocation(log: LogHandler_T) -> tuple[tuple[int, tuple[int, int, int]]]:
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
            net, country = signature.split()

            subnet: list = net.split('/')
            net_id: int = ip_unpack(inet_aton(subnet[0]))[0]
            host_count: int = int(cidr_to_host_count[subnet[1]])

            country: GEO = GEO[country.upper()]
        except Exception as E:
            log.warning(f'invalid signature: {signature}, {E}')

        else:
            # needed to account for MSB/bin_id overflows
            while host_count > LSB+1:
                cvl_append(f'{net_id} {LSB} {country}')

                host_count -= (LSB+1)
                net_id += (LSB+1)

            # NOTE: -1 to step down to bcast value
            cvl_append(f'{net_id} {host_count-1} {country}')

    del ip_geo_signatures

    # compression logic
    dict_nets: defaultdict[int, Union[list, tuple]] = defaultdict(list)
    for signature in converted_list:

        net_id, ip_count, country = [int(x) for x in signature.split()]

        # assigning vars for bin id, host ranges, and ip count
        bin_id: int = net_id & MSB
        host_id_start: int = net_id & LSB

        dict_nets[bin_id].append([host_id_start, host_id_start+ip_count, country])

    # merging contiguous ranges if within the same country
    for bin_id, containers in dict_nets.items():
        dict_nets[bin_id] = _merge_geo_ranges(sorted(containers))

    # NOTE: reduced list comprehension now that extra compression is re implemented, which converts to
    # tuple once it is completed with host containers, then again on the bin itself.
    nets: list[tuple[int, tuple[int, int, int]]] = [
        (bin_id, containers) for bin_id, containers in dict_nets.items()
    ]
    nets.sort()

    del dict_nets

    return tuple(nets)

def _merge_geo_ranges(ls: list, /) -> tuple[tuple]:
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
            # NOTE/TODO: this is where we can implement the array, instead of converting after returned.
            else:
                merged_containers.append(tuple(merged_item))

                merged_item = l

    # adding odd one out to the merged container
    if (not merged_item or merged_item[-1] != l):
        merged_containers.append(tuple(merged_item))

    # converting bin to tuple here. this should reduce the list comprehension complexity on return.
    return tuple(merged_containers)
