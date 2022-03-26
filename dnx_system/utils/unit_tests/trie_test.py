#!usr/bin/env python3

import os
import time

from ctypes import c_uint32
from dataclasses import dataclass
from ipaddress import IPv4Address

from dnx_gentools.def_constants import INITIALIZE_MODULE, hardout
from dnx_gentools import signature_operations

from dnx_iptools.protocol_tools import mhash
from dnx_iptools.dnx_trie_search import HashTrie_Range, HashTrie_Value, RecurveTrie, RangeTrie

from dnx_routines.logging.log_client import LogHandler as Log

line = '='*32

f_time = time.perf_counter_ns

MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111
DNS_BIN_OFFSET = 6

_host_list = [
    '14.204.211.122',  # malware
    '69.69.69.69',  # not found
    '193.164.216.238',  # compromised host
    '1.1.1.1',  # DoH
    '8.8.8.8',  # google/ USA
    '104.244.75.143',  # tor entry
    '192.168.69.69',  # rfc1918 (private)
    '34.107.220.220',  # USA
]
host_list = [int(IPv4Address(ip)) for ip in _host_list]

domain_list = [
    'www.google.com',
    'www.dnxfirewall.com',
    'www.worldofwarcraft.com',  # video games
    'www.amd.com',
    'www.poker.com',  # gambling
    'www.intel.com',
]

# this is to get every ip to be searched twice, which will guarantee LRU cache hits if applicable
hosts_to_test = [*host_list, *host_list]
domains_to_test = [*domain_list, *domain_list]

def _test_search(name, cat, search_func):
    results = []

    for ip in hosts_to_test:

        host = (ip & MSB, ip & LSB)

        start = f_time()

        # =========================
        # FUNCTION BEING TIMED
        # =========================
        result = search_func(host)
        # =========================

        total_time = f_time() - start

        results.append(
            (total_time, f'[{ip}] {cat}={result}', f'MSB->{ip & MSB}', f'LSB->{ip & LSB}')
        )

    _process_results(results, f'{name} TRIE RESULTS')

def _test_search2(name, cat, search_func):

    results = []

    for domain in domains_to_test:

        hhash = c_uint32(mhash(domain)).value

        host_hash = f'{hhash}'

        h1 = host_hash[:DNS_BIN_OFFSET]
        h2 = host_hash[DNS_BIN_OFFSET:]

        host = (int(h1), int(h2))

        start = f_time()

        # =========================
        # FUNCTION BEING TIMED
        # =========================
        result = search_func(host)
        # =========================

        total_time = f_time() - start

        results.append(
            (total_time, f'[{domain}] {cat}={result}', f'BINID->{h1}', f'HOSTID->{h2}')
        )

    _process_results(results, f'{name} TRIE RESULTS')

def _process_results(results, descriptor):
    no_cache = sorted(results[:len(host_list)])
    cache = sorted(results[len(host_list):len(hosts_to_test)])

    normalize_no_cache = no_cache[:-1]
    normalize_cache = cache[:-1]

    no_cache_average = sum([x[0] for x in normalize_no_cache])/(len(results)/2)-1
    cached_average = sum([x[0] for x in normalize_cache])/(len(results)/2)-1

    # print(f'{sum([x[0] for x in normalize_no_cache])}/{(len(results)/2)-1}')

    print(f'{line}\n{descriptor}\n{line}')

    for i, res in enumerate(results):
        print(hosts_to_test[i], f'> time={res[0]}, {res[1]}')

    print(f'\nno cache avg: {no_cache_average} ns, excluded: {no_cache[-1]}')
    print(f'cached avg: {cached_average} ns, excluded: {cache[-1]}')


if INITIALIZE_MODULE('trie-test'):
    args = None

    @dataclass
    class Args:
        h:    int = 0
        help: int = 0

        gh: int = 0
        gr: int = 0
        rr: int = 0
        dr: int = 0

        @property
        def show_help(self):
            return self.h or self.help

    try:
        args = Args(**{a: 1 for a in os.environ['PASSTHROUGH_ARGS'].split(',') if a})
    except Exception as E:
        hardout(f'DNXFIREWALL arg parse failure => {E}')

    if (args.show_help):
        vargs = [
            ('gh', 'v3 GEO (HASH)'), ('gr', 'v2 GEO (RANGE)'),
            ('rr', 'v2 REP (RECURVE)'), ('dr', 'v2 DNS (RECURVE)')
        ]

        print('available args')
        print('-'*32)
        for a, desc in vargs:
            print(f'{a}->{desc}')

        hardout()

    elif not any(args.__dict__.values()):
        hardout('args required. use help for more info.')

    Log.run(name='_tests')


def run():

    if (args.gh or args.gr):
        geo_sigs = signature_operations.generate_geolocation(Log)

        if (args.gh):
            geo_hash_trie = HashTrie_Range()
            geo_hash_trie.generate_structure(geo_sigs, len(geo_sigs))

        if (args.gr):
            geo_range_trie = RangeTrie()
            geo_range_trie.generate_structure(geo_sigs)

    if (args.rr):
        rep_sigs = signature_operations.generate_reputation(Log)
        rep_recurve_trie = RecurveTrie()
        rep_recurve_trie.generate_structure(rep_sigs)

    if (args.dr):
        dns_sigs = signature_operations.generate_domain(Log)
        dns_hash_trie = HashTrie_Value()
        dns_hash_trie.generate_structure(dns_sigs, len(dns_sigs))

    for x in range(2):

        print(f'{line}\nITERATION {x}\n{line}')

        if (args.gh):
            _test_search('v3 GEO (HASH)', 'geo', geo_hash_trie.py_search)

        if (args.gr):
            _test_search('v2 GEO (RANGE)', 'geo', geo_range_trie.search)

        if (args.rr):
            _test_search('v2 REP (RECURVE)', 'rep', rep_recurve_trie.search)

        if (args.dr):
            _test_search2('v4 DNS (HASH)', 'dns', dns_hash_trie.search)

    os._exit(1)
