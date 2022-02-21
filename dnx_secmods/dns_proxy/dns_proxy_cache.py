#!/usr/bin/env python3

from __future__ import annotations

import threading

from collections import Counter, deque, namedtuple

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_namedtuples import DNS_CACHE
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper

from dns_proxy_log import Log

NOT_VALID = -1
request_info = namedtuple('request_info', 'server proxy')

def dns_cache(*, dns_packet: Callable, request_handler: Callable) -> DNSCache:
    _top_domains = load_configuration('dns_cache')['top_domains']

    domain_counter = Counter({dom: cnt for cnt, dom in enumerate(reversed(_top_domains))})
    counter_lock = threading.Lock()

    top_domain_filter = set(load_top_domains_filter())

    # not needed once loaded into Counter
    del _top_domains

    dict_get = dict.__getitem__

    @cfg_read_poller('dns_cache')
    def manual_clear(cache: DNSCache, cfg_file: str):
        cache_settings = load_configuration(cfg_file)

        clear_dns_cache   = cache_settings['clear->standard']
        clear_top_domains = cache_settings['clear->top_domains']

        # when new top domains or standard cache (future) are written to disk, the poller will trigger whether the
        # flags are set or not. this will ensure we only run through the code if needed.
        if not (clear_dns_cache or clear_top_domains):
            return

        # if clearing cache, we do not need to check for expired records since they will have been cleared already
        if (clear_dns_cache):
            cache.clear()
            clear_dns_cache = False

            Log.notice('dns cache has been cleared.')

        # if clearing top domains, we do not need to check for expired records since they will have been cleared already
        if (clear_top_domains):
            domain_counter.clear()
            clear_top_domains = False

            Log.notice('top domains cache has been cleared.')

        with ConfigurationManager('dns_cache') as dnx:
            cache_settings = dnx.load_configuration()

            cache_settings['clear->standard'] = clear_dns_cache
            cache_settings['clear->top_domains'] = clear_top_domains

            dnx.write_configuration(cache_settings.expanded_user_data)

    @looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def auto_clear(cache: DNSCache):

        # =============
        # STANDARD
        # =============
        # locking in starting time since per loop accuracy is not necessary
        now = fast_time()
        expired = [dom for dom, record in list(cache.items()) if now > record.expire]

        for domain in expired:
            del cache[domain]

        # =============
        # TOP 20
        # =============
        # keep top XX queried domains permanently in cache. uses current cached packet to generate a new request and
        # forward to handler. response will be identified by "None" as client address in session tracker.
        top_domains = [
            dom[0] for dom in domain_counter.most_common(TOP_DOMAIN_COUNT)
        ]

        # updating persistent file first then sending requests
        with ConfigurationManager('dns_cache') as dnx:
            cache_storage = dnx.load_configuration()

            cache_storage['top_domains'] = top_domains

        write_configuration(cache_storage.expanded_user_data, 'dns_cache')

        for domain in top_domains:
            request_handler(dns_packet(domain), top_domain=True)
            fast_sleep(.1)

        Log.debug('top domains refreshed')

    class DNSCache(dict):
        '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

        containers handled by class:
            general dict - standard cache storage
            private dict - top domains cache storage
            private Counter - tracking number of times domains are queried

        initialization is the same as a dict, with the addition of two required arguments for callback references
        to the dns server.

            packet (*reference to packet class*)
            request_handler (*reference to dns server request handler function*)

        if the above callbacks are not set the top domains caching system will NOT actively update records, though the
        counts will still be accurate/usable.
        '''

        __slots__ = ()

        # searching key directly will return calculated ttl and associated records
        def __getitem__(self, key: str) -> DNS_CACHE:
            record = dict_get(self, key)
            # not present or root lookup
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
        def __missing__(self, key: str) -> int:
            return NOT_VALID

        def add(self, request: str, data_to_cache: CACHED_RECORD):
            '''add query to cache after calculating expiration time.'''

            self[request] = data_to_cache

            Log.debug(f'[{request}:{data_to_cache.ttl}] Added to standard cache. ')

        def search(self, query_name: str) -> DNS_CACHE:
            '''if client requested domain is present in cache, will return namedtuple of time left on ttl
            and the dns records, otherwise will return None. top domain count will get automatically
            incremented if it passes filter.'''

            if (query_name):
                # list comp to built in any test for match. match will not increment top domain counter.
                if not any([fltr in query_name for fltr in top_domain_filter]):

                    with counter_lock:
                        domain_counter[query_name] += 1

            return self[query_name]

    _cache = DNSCache()

    threading.Thread(target=auto_clear, args=(_cache,)).start()
    threading.Thread(target=manual_clear, args=(_cache,)).start()

    return _cache


def request_tracker() -> RequestTracker:
    '''Basic queueing mechanism for DNS requests received by the server. The main feature of the queue is to provide
    efficient thread blocking via Thread Events over a busy loop. This is a very lightweight version of the standard lib
    Queue and uses a deque as its primary data structure.
    '''

    request_ready = threading.Event()
    wait_for_request = request_ready.wait
    notify_ready = request_ready.set
    clear_ready = request_ready.clear

    _list = list

    req_tracker = deque()
    request_tracker_append = req_tracker.append
    request_tracker_get = req_tracker.popleft

    class RequestTracker:

        @staticmethod
        # blocks until the request ready flag has been set, then iterates over dict and appends any client address with
        # both values present. (client_query class instance object and decision)
        def return_ready() -> ClientQuery:

            # blocking until an at least one request has been received
            wait_for_request()

            # immediately clearing event, so we don't have to worry about it after loop. this prevents having to deal
            # with scenarios where a request was received in just after while loop, but just before reset. in this case
            # the request would be stuck until another was received.
            clear_ready()

            while request_tracker:
                yield request_tracker_get()

        def insert(self, client_query: ClientQuery):

            request_tracker_append(client_query)

            # notifying return_ready there is a query ready to forward
            notify_ready()

    return RequestTracker()
