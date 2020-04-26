#!/usr/bin/env python3

import os, sys
import json
import time
import fcntl
import shutil
import hashlib
import subprocess

from secrets import token_urlsafe
from ipaddress import IPv4Address, IPv4Network

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import USER, GROUP, LOG, FILE_POLL_TIMER
from dnx_configure.dnx_constants import DNS_BIN_OFFSET, DNS_CAT, IPP_CAT, GEO
from dnx_configure.dnx_exceptions import ValidationError

# used to load ip and domain signatures. if whitelist exceptions are specified then they will not
# get loaded into the proxy. the try/except block is used to ensure bad rules dont prevent proxy
# from starting though the bad rule will be ommited from the proxy.
def load_signatures(Log, *, mod, exc=[]):
    signatures = {}
    with open(f'{HOME_DIR}/dnx_system/signatures/{mod}_lists/blocked.{mod}s', 'r') as blocked_sigs:
        for signature in blocked_sigs:
            try:
                host_signature = signature.strip().split(maxsplit=1)
                host, category = host_signature
            except:
                Log.warning(f'bad signature detected in {mod}.')
            else:
                if (host not in exc):
                    signatures[host] = category

        return signatures

def load_dns_bitmap(Log, bl_exc=[], wl_exc=[]):
    dict_nets = {}
    # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    blacklist = [f'{domain} blacklist' for domain in bl_exc]

    with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/blocked.domains', 'r') as sigs:
        for sig_set in [sigs, blacklist]:
            for sig in sig_set:
                try:
                    si = sig.strip().split(maxsplit=1)

                    host = si[0]
                    host_hash = f'{hash(si[0])}'
                    cat = int(DNS_CAT[si[1]])

                    b_id = int(host_hash[:DNS_BIN_OFFSET])
                    h_id = int(host_hash[DNS_BIN_OFFSET:])
                except Exception as E:
                    print(f'bad signature detected in domain. | {E} | {sig}')
                else:
                    if (host in wl_exc): continue # overriding signature pre proxy
                    try:
                        dict_nets[b_id].append((h_id, cat))
                    except Exception as E:
                        dict_nets[b_id] = [(h_id, cat)]
                    else:
                        dict_nets[b_id].sort()

    # converting to nested tuple and sorting, list > tuple done on return
    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets = None

    return tuple(nets)

def load_ip_bitmap(Log):
    '''returns a bitmap trie for ip host filtering loaded from the consolodated blocked.ips file.'''
    dict_nets, bin_offset = {}, 5
    with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'r') as ip_sigs:
        for sig in ip_sigs:
            try:
                si = sig.strip().split(maxsplit=1)
                ip = int(IPv4Address(si[0]))
                cat = int(IPP_CAT[si[1].upper()])
            except Exception as E:
                Log.warning(f'bad signature detected in ip. | {E} | {sig}')
                continue

            ip = f'{int(IPv4Address(ip))}'

            b_id = int(ip[:-bin_offset])
            host = int(ip[-bin_offset:])
            try:
                dict_nets[b_id].append((host, cat))
            except KeyError:
                dict_nets[b_id] = [(host, cat)]
            else:
                # sorted the items in bin/bucket #
                dict_nets[b_id].sort()

    # converting to nested tuple and sorting, list > tuple done on return
    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets = None

    return tuple(nets)

def load_geo_bitmap(Log):
    '''returns a bitmap trie for geolocation filtering loaded from the consolodated blocked.geo file.'''
    # temporary dict to generate dataset easier and local var for easier bin size adjustments
    dict_nets, bin_offset = {}, 5
    with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/blocked.geo', 'r') as geo_sigs:
        for net in geo_sigs:
            if '#' in net: continue
            try:
                geo_signature = net.strip().split(maxsplit=1)
                net = IPv4Network(geo_signature[0])
                country = int(GEO[geo_signature[1].title()])
            except Exception as E:
                Log.warning(f'bad signature detected in geo. | {E} | {net}')
                continue

            # assigning vars for bin id, host ranges, and ip count
            net_id = str(int(net.network_address))
            ip_count = int(net.num_addresses) - 1

            rollover_max = int('9'*bin_offset)
            bis_id = int(net_id[:-bin_offset])
            host = int(net_id[-bin_offset:])
            try:
                bin_range = dict_nets[bis_id]
            except KeyError:
                bin_range = dict_nets[bis_id] = []

            while ip_count > 0:
                diff = rollover_max - host
                if diff > ip_count:
                    bin_range.append((host,host+ip_count, country))
                    break

                # NOTE: if max host id is reached, will roll over to next bin id integer
                else:
                    bin_range.append((host,rollover_max, country))
                    bis_id += 1
                    ip_count -= diff
                    host = 0

                    try:
                        bin_range = dict_nets[bis_id]
                    except KeyError:
                        bin_range = dict_nets[bis_id] = []

                bin_range.sort()
            dict_nets[bis_id] = _merge_geo_ranges(bin_range)

    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets = None

    return tuple(nets)

# TODO: when merging DO NOT let different country ranges merge!!!!!
def _merge_geo_ranges(ls):
    temp_item, temp_list = [], []
    for t in ls:
        l = list(t)
        # if we have a temp item, it means we have an ongoing contigous range. if the first element in the current list
        # is equal to the last element in the temp list(+1), the networks are still contigous so we will merge them and
        # update the temp item.
        if (temp_item and l[0] == temp_item[1] + 1
                and l[2] == temp_item[2]):
            temp_item[1] = l[1]
        # applying current item to temp item since it didnt exist
        elif (not temp_item):
            temp_item = l
        # once a discontigious range is detected. the temp item for previous range will get appended to the list to be
        # returned as well as the current list.
        else:
            temp_list.append(tuple(temp_item))
            temp_item = l

    if ls and (not temp_list or temp_list[-1] not in [t, l]):
        temp_list.append(tuple(temp_item))

    return temp_list

def load_tlds():
    dns_proxy = load_configuration('dns_proxy')['dns_proxy']

    for tld, setting in dns_proxy['tlds'].items():
        yield (tld.strip('.'), setting)

# function to load in all keywords corresponding to enabled domain categories. the try/except
# is used to ensure bad keywords do not prevent the proxy from starting, though the bad keyword
# will be ommited from the proxy.
def load_keywords(Log):
    '''returns keyword set for enabled domain categories'''
    keywords = []
    try:
        with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/domain.keywords', 'r') as blocked_keywords:
            all_keywords = [
                x.strip() for x in blocked_keywords.readlines() if x.strip() and '#' not in x
            ]
    except FileNotFoundError:
        Log.critical('domain keywords file not found. contact support immediately.')
        return keywords
    else:
        for keyword_info in all_keywords:
            try:
                keyword, category = keyword_info.split(maxsplit=1)
            except:
                continue
            else:
                keywords.append((keyword, DNS_CAT[category]))

    return tuple(keywords)

def load_top_domains_filter():
    with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/valid_top.domains', 'r') as tdf:
        return [s.strip() for s in tdf.readlines() if s.strip() and '#' not in s]

def calculate_file_hash(file_to_hash, *, path=f'{HOME_DIR}/', folder='data'):
    '''returns the sha256 secure hash of the file sent in'''
    with open(f'{path}{folder}/{file_to_hash}', 'rb') as f2h:
        file_hash = hashlib.sha256(f2h.read()).digest()

    return file_hash

def cfg_read_poller(watch_file, class_method=False):
    '''Automate Class configuration file poll decorator. apply this decorator to all functions
    that will update configurations loaded in memory from json files. config file must be sent
    in via decorator argument. set class_method argument to true if being used with a class method.'''

    if not isinstance(watch_file, str):
        raise TypeError('watch file must be a string.')

    if (not watch_file.endswith('.json')):
        watch_file += '.json'

    def decorator(function_to_wrap):
        if (not class_method):
            def wrapper(*args):
                watcher = Watcher(watch_file, callback=function_to_wrap)
                watcher.watch(*args)

        else:
            @classmethod
            def wrapper(*args):
                watcher = Watcher(watch_file, callback=function_to_wrap)
                watcher.watch(*args)

        return wrapper
    return decorator

def cfg_write_poller(list_function):
    '''Automate class configuration file poll decorator. this decorator is only compatible with
    the dns proxy module whitelist/blacklist read/write operations'''
    def wrapper(*args):
        print(f'[+] Starting user defined {args[1]} timer')
        last_modified_time, new_args = 0, (*args, f'{args[1]}.json')
        # main loop calling the primary function for read/write change detection/polling
        # the recycle the saved hash file which is returned regardless of if it was changed or not
        while True:
            last_modified_time = list_function(*new_args, last_modified_time)

            time.sleep(FILE_POLL_TIMER)
    return wrapper


class Watcher:
    '''this class is used to detect file changes, primarily configuration files.'''
    __slots__ = (
        '_watch_file', '_callback', '_full_path',
        '_last_modified_time'
    )

    def __init__(self, watch_file, callback):
        self._watch_file = watch_file
        self._callback   = callback
        self._full_path  = f'{HOME_DIR}/data/{watch_file}'

        self._last_modified_time = 0

    # will check file for change in set intervals, currently using global constant for config file polling
    def watch(self, *args):
        args = [*args, self._watch_file]
        while True:
            if (self.is_modified):
                self._callback(*args)
            else:
                time.sleep(FILE_POLL_TIMER)

    @property
    # if watch file has been modified will update modified time and return True, else return False
    def is_modified(self):
        modified_time = os.stat(self._full_path).st_mtime
        if (modified_time != self._last_modified_time):
            self._last_modified_time = modified_time
            return True

        return False
