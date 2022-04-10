#!/usr/bin/env python3

from __future__ import annotations

import threading

from collections import Counter, deque

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import QNAME_RECORD, QNAME_RECORD_UPDATE
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper

from dns_proxy_log import Log

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_secmods.dns_proxy import DNSCache, RequestTracker

    from dns_proxy_packets import ClientQuery

__all__ = (
    'dns_cache', 'request_tracker',
    
    'NO_QNAME_RECORD', 'QNAME_NOT_FOUND'
)

NO_QNAME_RECORD = QNAME_RECORD(-1, -1, [])
QNAME_NOT_FOUND = QNAME_RECORD_UPDATE(-1, [])

def dns_cache(*, dns_packet: Callable[[str], ClientQuery], request_handler: Callable[[int, ClientQuery],None]) -> DNSCache:

    _top_domains: list = load_configuration('dns_server', ext='cache').get('top_domains')

    domain_counter: Counter[str, int] = Counter({dom: cnt for cnt, dom in enumerate(reversed(_top_domains))})
    counter_lock: Lock = threading.Lock()

    top_domain_filter = tuple(load_top_domains_filter())

    # not needed once loaded into Counter
    del _top_domains

    dict_get = dict.__getitem__

    @cfg_read_poller('dns_server.cache')
    def manual_clear(cache: DNSCache, cfg_file: str) -> None:
        cache_settings: ConfigChain = load_configuration(cfg_file, ext='')

        clear_dns_cache:   bool = cache_settings['clear->standard']
        clear_top_domains: bool = cache_settings['clear->top_domains']

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

        with ConfigurationManager('dns_server', ext='cache') as dnx:
            cache_settings = dnx.load_configuration()

            cache_settings['clear->standard'] = clear_dns_cache
            cache_settings['clear->top_domains'] = clear_top_domains

            dnx.write_configuration(cache_settings.expanded_user_data)

    @looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def auto_clear(cache: DNSCache) -> None:

        Log.debug('record cache clear or renew started.')

        # =============
        # STANDARD
        # =============
        # locking in starting time since per loop accuracy is not necessary
        now: int = fast_time()
        expired: list[str] = [dom for dom, record in list(cache.items()) if now > record.expire]

        for domain in expired:
            del cache[domain]

        # =============
        # TOP 20
        # =============
        # keep the top XX queried domains permanently in cache.
        top_domains: list[str] = [
            domain[0] for domain in domain_counter.most_common(TOP_DOMAIN_COUNT)
        ]

        # updating persistent file first then sending requests
        with ConfigurationManager('dns_server', ext='cache') as dnx:
            cache_storage: ConfigChain = dnx.load_configuration()

            cache_storage['top_domains'] = top_domains

            dnx.write_configuration(cache_storage.expanded_user_data)

        # response will be identified by "None" for client address
        for domain in top_domains:
            request_handler(1, dns_packet(domain))
            fast_sleep(.1)

        Log.debug('expired records cleared from cache and top domains refreshed')

    class _DNSCache(dict):
        '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

        containers handled by class:
            general dict - standard cache storage
            private dict - top domains cache storage
            private Counter - tracking number of times a domain is queried

        initialization is the same as a dict, with the addition of two required arguments for callback references
        to the dns server.

            packet (*reference to packet class*)
            request_handler (*reference to dns server request handler function*)

        if the above callbacks are not set, the top domain's caching system will NOT actively update records, but the
        counts will still be accurate/usable.
        '''
        __slots__ = ()

        # searching key directly will return calculated ttl and associated records
        def __getitem__(self, key: str) -> QNAME_RECORD_UPDATE:
            record: QNAME_RECORD = dict_get(self, key)
            # not present or root lookup
            if (record is NO_QNAME_RECORD):
                return QNAME_NOT_FOUND

            calcd_ttl = record.expire - int(fast_time())
            if (calcd_ttl > DEFAULT_TTL):
                return QNAME_RECORD_UPDATE(DEFAULT_TTL, record.records)

            elif (calcd_ttl > 0):
                return QNAME_RECORD_UPDATE(calcd_ttl, record.records)

            # expired
            else:
                return QNAME_NOT_FOUND

        def __missing__(self, key: str) -> QNAME_RECORD:
            return NO_QNAME_RECORD

        def add(self, request: str, data_to_cache: QNAME_RECORD):
            '''add query to cache after calculating expiration time.
            '''
            self[request] = data_to_cache

            Log.debug(f'[{request}:{data_to_cache.ttl}] Added to standard cache. ')

        def search(self, query_name: str) -> QNAME_RECORD_UPDATE:
            '''return namedtuple of time left on ttl and the dns record if the client requested domain is cached.

            the top domain count will be incremented automatically if it passes the filter.
            '''
            if (query_name):

                filter_matches: list[str] = [fltr for fltr in top_domain_filter if fltr in query_name]
                if (not filter_matches):

                    with counter_lock:
                        domain_counter[query_name] += 1

            return self[query_name]

        def start_pollers(self):

            threading.Thread(target=auto_clear, args=(self,)).start()
            threading.Thread(target=manual_clear, args=(self,)).start()

    if (TYPE_CHECKING):
        return _DNSCache

    return _DNSCache()


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

    request_queue = deque()
    request_queue_append = request_queue.append
    request_queue_get = request_queue.popleft

    class _RequestTracker:

        @staticmethod
        # blocks until the request ready flag has been set, then iterates over dict and appends any client address with
        # both values present. (client_query class instance object and decision)
        def return_ready() -> ClientQuery:

            # blocking until at least one request has been received
            wait_for_request()

            # immediately clearing event, so we don't have to worry about it after loop. this prevents having to deal
            # with scenarios where a request was received in just after while loop, but just before reset. in this case
            # the request would be stuck until another was received.
            clear_ready()

            while request_queue:
                yield request_queue_get()

        @staticmethod
        # NOTE: first arg is because this gets reference/called via an instance.
        def insert(_, client_query: ClientQuery) -> None:

            request_queue_append(client_query)

            # notifying return_ready that there is a query ready to forward
            notify_ready()

    if (TYPE_CHECKING):
        return _RequestTracker

    return _RequestTracker()
