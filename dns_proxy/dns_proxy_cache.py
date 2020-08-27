#!/usr/bin/env python3

import os, sys
import threading

from collections import Counter, OrderedDict

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
            fast_sleep(.1)

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


class RequestTracker(OrderedDict):
    ''' Tracks DNS Server requests and allows for either DNS Proxy or Server to add initial client address key
    on a first come basis and the second one will update the corresponding value index with info directly.

        RequestTracker([client_address: [client_query, decision]])
    '''

    __slots__ = (
        'insert_lock', 'counter_lock',

        'ready_count',

        'request_wait', 'request_set', 'request_clear'
    )

    def __init__(self):
        self.insert_lock = threading.Lock()
        self.counter_lock = threading.Lock()

        self.ready_count = 0

        request_ready = threading.Event()
        self.request_wait  = request_ready.wait
        self.request_set   = request_ready.set
        self.request_clear = request_ready.clear

    # blocks until the request ready flag has been set, then iterates over dict and appends any client adress with
    # both values present. (client_query class instance object and decision)
    def return_ready(self):
        self.request_wait()

        ready_requests = []
        tracker = list(self.items())
        for client_address, (client_query, decision) in tracker:

            # using inverse because it has potential to be more efficient if both are not present. decision is more
            # likely to be input first, so it will be evaled only if client_query is present.
            if not client_query or not decision:
                continue

            ready_requests.append((client_query, decision))

            # lock protects count, which is also accessed by server and proxy via insert method.
            with self.counter_lock:
                self.ready_count -= 1

            # removes entry from tracker if request is ready for forwarding.
            del self[client_address]

        if not self.ready_count:
            self.request_clear()

        # here temporarily for testing implementation
        elif self.ready_count < 0:
            raise RuntimeError('Request Tracker ready count dropped below 0. probably fatal. yay me.')

        return ready_requests

    # this is a thread safe method to add entries to the request tracker dictionary. this will ensure the key
    # exists before updatin the value. a default dict cannot be used (from what i can tell) because an empty
    # list would raise an index error if it was trying to set decision before request.
    def insert(self, client_address, info, *, module_index):

        with self.insert_lock:

            # if client address is not already present, it will be added before updating the module index value
            if client_address not in self:

                # default entry for requests. 1. client request instance 2. proxy decision
                self[client_address] = [None, None]
                self[client_address][module_index] = info

            else:
                with self.counter_lock:
                    self.ready_count += 1

                self[client_address][module_index] = info

                self.request_set()
