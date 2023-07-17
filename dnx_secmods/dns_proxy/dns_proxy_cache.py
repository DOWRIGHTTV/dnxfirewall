#!/usr/bin/env python3

from __future__ import annotations

import threading

from collections import Counter

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import QNAME_RECORD, QNAME_RECORD_UPDATE
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper

from dns_proxy_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dns_proxy_packets import ClientQuery

__all__ = (
    'dns_cache',
    
    'NO_QNAME_RECORD', 'QNAME_NOT_FOUND'
)

NO_QNAME_RECORD = QNAME_RECORD(-1, -1, [])
QNAME_NOT_FOUND = QNAME_RECORD_UPDATE(-1, [])

# TODO: it might be worth making dns_packet callback set via set_* method since we doing for the request_queue already
def dns_cache(*, dns_packet: Callable[[str], ClientQuery]) -> DNSCache_T:
    '''factory function providing subclass of dict as custom data structure for dealing with the local caching of dns
    records and poller operations for refresh and cleanup.

    containers handled by class:
        general dict - standard cache storage
        private dict - top domains cache storage
        private Counter - tracking number of times a domain is queried

    required callbacks via arguments

        packet (*reference to packet class*)

    required callbacks via set_* method

        request_queue (*reference to dns server request queue*)
    '''
    # will be set through class as nonlocal
    request_handler_add: Callable[[ClientQuery], None]

    _top_domains: list = load_configuration('dns_server', ext='cache', cfg_type='global').get('top_domains')

    domain_counter: Counter[str, int] = Counter({dom: cnt for cnt, dom in enumerate(reversed(_top_domains))})
    counter_lock: Lock_T = threading.Lock()

    top_domain_filter = tuple(load_top_domains_filter())

    # not needed once loaded into Counter
    del _top_domains

    dict_get = dict.__getitem__

    @cfg_read_poller('dns_server', ext='cache', cfg_type='global')
    def manual_clear(cache: DNSCache_T, cache_settings: ConfigChain) -> None:

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

        with ConfigurationManager('dns_server', ext='cache', cfg_type='global') as dns:
            dns.config_data['clear->standard'] = clear_dns_cache
            dns.config_data['clear->top_domains'] = clear_top_domains

    @looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def auto_clear(cache: DNSCache_T) -> None:

        Log.debug('record cache clear or renew started.')

        # =============
        # STANDARD
        # =============
        # locking in starting time since per loop accuracy is not necessary
        now: int = fast_time()
        expired: list[str] = [domain for domain, record in cache.items() if now > record.expire]

        for domain in expired:
            del cache[domain]

        # =============
        # TOP 20
        # =============
        # keep the top XX queried domains permanently in cache.
        top_domains: list[str] = [
            domain for domain, ct in domain_counter.most_common(TOP_DOMAIN_COUNT)
        ]

        # updating persistent file first then sending requests
        with ConfigurationManager('dns_server', ext='cache', cfg_type='global') as dns:
            dns.config_data['top_domains'] = top_domains

        # response will be identified by "None" for client address
        for domain in top_domains:

            request_handler_add(dns_packet(domain))
            fast_sleep(.1)

        Log.debug('expired records cleared from cache and top domains refreshed')

    class _DNSCache(dict):
        __slots__ = ()

        # searching key directly will return calculated ttl and associated records
        def __getitem__(self, key: str) -> QNAME_RECORD_UPDATE:
            record: QNAME_RECORD = dict_get(self, key)
            # not present or root lookup
            if (record is NO_QNAME_RECORD):
                return QNAME_NOT_FOUND

            calcd_ttl = record.expire - int(fast_time())
            if (calcd_ttl >= DEFAULT_TTL):
                return QNAME_RECORD_UPDATE(DEFAULT_TTL, record.records)

            elif (calcd_ttl > 0):
                return QNAME_RECORD_UPDATE(calcd_ttl, record.records)

            # expired
            else:
                return QNAME_NOT_FOUND

        def __missing__(self, key: str) -> QNAME_RECORD:
            return NO_QNAME_RECORD

        def add(self, request: str, data_to_cache: QNAME_RECORD):
            '''add the query to cache after calculating expiration time.
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

        def set_request_queue(self, request_handler) -> None:
            nonlocal request_handler_add

            request_handler_add = request_handler.add

        def start_pollers(self):

            threading.Thread(target=auto_clear, args=(self,)).start()
            threading.Thread(target=manual_clear, args=(self,)).start()

    if (TYPE_CHECKING):
        return _DNSCache

    return _DNSCache()


# basic helpers
def load_top_domains_filter() -> list[str]:
    with open(f'{SIGNATURES_DIR}/domain_lists/valid_top.domains', 'r') as tdf:
        return [s.strip() for s in tdf.readlines() if s.strip() and '#' not in s]


# TYPE EXPORTS
if (TYPE_CHECKING):
    DNSCache_T: TypeAlias = dns_cache(dns_packet=Callable[[str], ClientQuery])

    __all__.append('DNSCache_T')
