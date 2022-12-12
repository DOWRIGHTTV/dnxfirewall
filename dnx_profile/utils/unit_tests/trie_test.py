#!usr/bin/env python3

# LABEL: DEVELOPMENT_ONLY_CODE

import os
import time

from dataclasses import dataclass
from ipaddress import IPv4Address

from dnx_gentools.def_constants import INITIALIZE_MODULE, UINT32_MAX, hardout
from dnx_gentools import signature_operations

from dnx_iptools.hash_trie import HashTrie_Range, HashTrie_Value

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
    '8.8.8.8',  # google/ USA
    '104.244.75.143',  # tor entry
    '192.168.69.69',  # rfc1918 (private)
    '34.107.220.220',  # USA
]
hosts_to_test = [int(IPv4Address(ip)) for ip in _host_list]

_domain_list = [
    'google.com',
    'dnxfirewall.com',
    'worldofwarcraft.com',  # video games
    'amd.com',
    'uspoker.com',  # gambling
    'logmein.com',  # remote login
]
domains_to_test = [hash(domain) & UINT32_MAX for domain in _domain_list]

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

    test_list = []
    if (cat == 'rep'):
        test_list.extend(hosts_to_test)

    elif (cat == 'dns'):
        test_list.extend(domains_to_test)

    results = []

    for entry in test_list:

        start = f_time()

        # =========================
        # FUNCTION BEING TIMED
        # =========================
        result = search_func(entry)
        # =========================

        total_time = f_time() - start

        results.append(
            (total_time, f'[{entry}] {cat}->{result}')
        )

    _process_results(results, f'{name} TRIE RESULTS')

def _process_results(results, descriptor):
    normalized_results = sorted(results)[:-1]

    average = sum([x[0] for x in normalized_results]) / (len(results) / 2) - 1

    print(f'{line}\n{descriptor}\n{line}')

    for i, res in enumerate(results):
        print(f'[{i}] time->{res[0]}, {res[1]}')

    print(f'\nsearch time: avg->{average}ns, excluded->{sorted(results)[-1]}')


if INITIALIZE_MODULE('trie-test'):
    args = None

    @dataclass
    class Args:
        h:    int = 0
        help: int = 0

        gh: int = 0
        rh: int = 0
        dh: int = 0

        @property
        def show_help(self):
            return self.h or self.help

    try:
        args = Args(**{a: 1 for a in os.environ['PASSTHROUGH_ARGS'].split(',') if a})
    except Exception as E:
        hardout(f'DNXFIREWALL arg parse failure => {E}')

    if (args.show_help):
        vargs = [
            ('gh', 'v3 GEO (HASH)'),
            ('rh', 'v4 REP (HASH)'),
            ('dh', 'v4 DNS (HASH)')
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

    if (args.gh):
        geo_sigs = signature_operations.generate_geolocation(Log)
        geo_hash_trie = HashTrie_Range()
        geo_hash_trie.generate_structure(geo_sigs, len(geo_sigs))

    if (args.rh):
        rep_sigs = signature_operations.generate_reputation(Log)
        rep_hash_trie = HashTrie_Value()
        rep_hash_trie.generate_structure(rep_sigs, len(rep_sigs))

    if (args.dh):
        dns_sigs = signature_operations.generate_domain(Log)
        dns_hash_trie = HashTrie_Value()
        dns_hash_trie.generate_structure(dns_sigs, len(dns_sigs))

    for x in range(2):

        print(f'{line}\nITERATION {x}\n{line}')

        if (args.gh):
            _test_search('v3 GEO (HASH)', 'geo', geo_hash_trie.py_search)

        if (args.rh):
            _test_search2('v4 REP (HASH)', 'rep', rep_hash_trie.py_search)

        if (args.dh):
            _test_search2('v4 DNS (HASH)', 'dns', dns_hash_trie.py_search)

    os._exit(1)
