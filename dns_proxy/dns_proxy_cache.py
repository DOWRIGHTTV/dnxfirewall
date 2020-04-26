#!/usr/bin/env python3

import os, sys
import threading

from time import sleep
from collections import Counter

# NOTE: this is an alternate implementation of the DNSCache class inhereting from dict.

import dnx_configure.dnx_file_operations as fo

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_namedtuples import DNS_CACHE, CACHED_RECORD
from dnx_iptools.dnx_standard_tools import looper
from dns_proxy.dns_proxy_log import Log

# NOTE: normal_cache boolean is not working correctly. top domains are showing up as True
# fix or remove. might not be needed anymore as it was initial implemented to assist with
# ensuring the top domains system was actually working as intended.
class DNSCache(dict):
    '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

    containers handled by class:
        general dict - standard cache storage
        private dict - top domains cache storage
        private Counter - tracking number of times domains are queried

    initialization is the same as a dict, with the addition of two required method calls for callback references
    to the dns server.

        set_query_generator(*reference to packet class*)
        set_query_handler(*reference to dns server request handler function*)

    if the above callbacks are not set the top domains caching system will actively update records, though the counts
    will still be accurate/usable.
    '''
    clear_dns_cache   = False
    clear_top_domains = False

    __slots__ = (
        # protected vars
        '_dns_packet', '_request_handler',

        # private vars
        '_dom_counter', '_top_domains',
        '_cnter_lock', '_top_dom_filter'
    )

    def __init__(self, *, packet=None, request_handler=None):
        self._dns_packet = packet
        self._request_handler = request_handler

        self._dom_counter = Counter()
        self._top_domains = {}
        self._top_dom_filter = []
        self._cnter_lock  = threading.Lock()

        self._load_top_domains()
        threading.Thread(target=self._auto_clear_cache).start()
        if (self._dns_packet and self._request_handler):
            threading.Thread(target=self._auto_top_domains).start()

    def __str__(self):
        return ' '.join([
            f'TOP DOMAIN COUNT: {len(self._top_domains)} | TOP DOMAINS: {self._top_domains}',
            f'CACHE SIZE: {sys.getsizeof(self)} | NUMBER OF RECORDS: {len(self)} | CACHE: {super().__str__()}'
        ])

    # searching key directly will return calculated ttl and associated records
    def __getitem__(self, key):
        # filtering root lookups from checking cache
        if (not key):
            return DNS_CACHE(NOT_VALID, None)

        record = dict.__getitem__(self, key)
        # not present
        if (record == NOT_VALID):
            return DNS_CACHE(NOT_VALID, None)

        calcd_ttl = record.expire - int(fast_time())
        if (calcd_ttl > DEFAULT_TTL):
            return DNS_CACHE(DEFAULT_TTL, record.records)

        elif (calcd_ttl > 0):
            return DNS_CACHE(calcd_ttl, record.records)
        # expired
        else:
            return DNS_CACHE(NOT_VALID, None)

    # if missing will return an expired result
    def __missing__(self, key):
        return NOT_VALID

    def add(self, request, data_to_cache):
        '''add query to cache after calculating expiration time.'''
        self[request] = data_to_cache

        Log.dprint(f'CACHE ADD | NAME: {request} TTL: {data_to_cache.ttl}')

    def search(self, query_name):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None. top domain count will get automatically
        incremented if it passes filter.'''
        if (query_name):
            self._increment_if_valid_top(query_name)

        return self[query_name]

    def _increment_if_valid_top(self, domain):
        for fltr in self._top_dom_filter:
            if (fltr in domain): break
        else:
            with self._cnter_lock:
                self._dom_counter[domain] += 1

    @looper(FIVE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def _auto_clear_cache(self):
        cache, now = self.items, fast_time()
        if (self.clear_dns_cache):
            self.clear()
            self._reset_flag('dns_cache')

        expired = [dom for dom, record in cache() if now > record.expire]

        for domain in expired:
            del self[domain]

        # should print __str__ of self. if debug level will log to file.
#        Log.debug(self)

    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    @looper(THREE_MIN)
    def _auto_top_domains(self):
        if (self.clear_top_domains):
            self._dom_counter = Counter()
            self._reset_flag('top_domains')

        most_common_doms = self._dom_counter.most_common
        self._top_domains = {dom[0]:cnt for cnt, dom
            in enumerate(most_common_doms(TOP_DOMAIN_COUNT), 1)}

        request_handler, dns_packet = self._request_handler, self._dns_packet
        for domain in self._top_domains:
            request_handler(dns_packet(domain))
            sleep(.1)

        fo.write_configuration(self._top_domains, 'dns_cache')

    # method called to reset dictionary cache for sent in value (standard or top domains) and then reset the flag in the
    # json file back to false.
    def _reset_flag(self, cache_type):
        setattr(self, f'clear_{cache_type}', False)
        with fo.ConfigurationManager('dns_server') as dnx:
            dns_settings = dnx.load_configuration()

            dns_settings['dns_server']['cache'][cache_type] = False

            dnx.write_configuration(dns_settings)

        Log.notice(f'{cache_type.replace("_", " ")} has been cleared.')

    # loads top domains from file for persistence between restarts/shutdowns and top domains filter
    def _load_top_domains(self):
        self._top_domains = fo.load_configuration('dns_cache')

        dom_list = reversed(list(self._top_domains))
        self._dom_counter = Counter({dom: cnt for cnt, dom in enumerate(dom_list)})

        self._top_dom_filter = set(fo.load_top_domains_filter())
