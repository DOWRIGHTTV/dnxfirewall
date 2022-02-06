#!usr/bin/env python3

import __init__

import os
import sys
import time
import argparse

from ipaddress import IPv4Address

from dnx_gentools import signature_operations
from dnx_iptools.dnx_trie_search import HashTrie, RecurveTrie, RangeTrie
from dnx_iptools.dnx_trie_search import generate_recursive_binary_search, generate_linear_binary_search
from dnx_routines.logging.log_client import LogHandler as Log

line = '='*32

f_time = time.perf_counter_ns

MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111

_host_list = [
    '14.204.211.122',  # malware
    '69.69.69.69',  # not found
    '193.164.216.238',  # compromised host
    '1.1.1.1',  # DoH
    '104.244.75.143',  # tor entry
    '192.168.69.69',  # rfc1918 (private)
    '34.107.220.220',  # USA
]
host_list = [int(IPv4Address(ip)) for ip in _host_list]

# this is to get every ip to be searched twice which guarantee LRU cache hits if active in specific trie.
hosts_to_test = [*host_list, *host_list]

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
            (total_time, f'[{ip}] {cat}={result}', f'MSB={ip & MSB}', f'LSB={ip & LSB}')
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


if (__name__ == '__main__'):
    parser = argparse.ArgumentParser(description='DNX TRIE unit test utility')

    parser.add_argument('--rep', help='run through rep signatures', action='store_true')
    parser.add_argument('-ha', help='trie map(hash trie) test', action='store_true')
    parser.add_argument('-r', help='range of recurve trie test', action='store_true')
    parser.add_argument('-o', help='old range or recurve trie test', action='store_true')

    args = parser.parse_args(sys.argv[1:])

    import pyximport; pyximport.install()

    Log.run(name='_test')

    rep_sigs = signature_operations.generate_reputation(Log)
    geo_sigs = signature_operations.generate_geolocation(Log)

    recurve_trie = RecurveTrie()
    recurve_trie.generate_structure(rep_sigs)

    range_trie = RangeTrie()
    range_trie.generate_structure(geo_sigs)

    hash_trie = HashTrie()
    hash_trie.generate_structure(geo_sigs)

    _recursive_binary_search = generate_recursive_binary_search(rep_sigs, (0, len(rep_sigs)-1))
    _linear_binary_search = generate_linear_binary_search(geo_sigs, (0, len(geo_sigs)-1))

    for x in range(2):

        print(f'{line}\nITERATION {x}\n{line}')

        # TODO: figure out how general test can call this.
        if (args.ha):
            _test_search('v3 GEO (HASH)', 'geo', hash_trie._search)

        if (args.r):
            _test_search('v2 GEO (RANGE)', 'geo', range_trie.search)

            if (args.rep):
                _test_search('v2 REP (RECURVE)', 'rep', recurve_trie.search)

        if (args.o):
            _test_search('v1 GEO (typed)', 'geo', _linear_binary_search)

            if (args.rep):
                _test_search('v1 REP (typed)', 'rep', _recursive_binary_search)

    os._exit(1)
