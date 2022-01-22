#!/usr/bin/env python3

import threading

from collections import Counter, OrderedDict, namedtuple

from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_CACHE
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper

from dnx_secmods.dns_proxy.dns_proxy_log import Log

NOT_VALID = -1
request_info = namedtuple('request_info', 'server proxy')

def DNSCache(*, dns_packet, request_handler):
    _top_domains = load_configuration('dns_cache')

    domain_counter = Counter({dom: cnt for cnt, dom in enumerate(reversed(_top_domains))})
    counter_lock = threading.Lock()

    top_domain_filter = set(load_top_domains_filter())

    # not needed once loaded into Counter
    del _top_domains

    dict_get = dict.__getitem__

    @cfg_read_poller('dns_cache')
    def manual_clear(cache, cfg_file):
        dns_cache = load_configuration(cfg_file)

        clear_dns_cache   = dns_cache['clear']['standard']
        clear_top_domains = dns_cache['clear']['top_domains']

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

        with ConfigurationManager('dns_server') as dnx:
            dns_settings = dnx.load_configuration()

            dns_settings['clear']['standard'] = clear_dns_cache
            dns_settings['clear']['top_domains'] = clear_top_domains

            dnx.write_configuration(dns_settings)

    @looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def auto_clear(cache):

        # =============
        # STANDARD
        # =============
        # locking in starting time since per loop accuracy is not necessary
        now = fast_time()
        expired = [dom for dom, record in list(cache.items) if now > record.expire]

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
        with ConfigurationManager('dns_server') as dnx:
            dns_settings = dnx.load_configuration()

            dns_settings['top_domains'] = top_domains

        write_configuration(dns_settings, 'dns_cache')

        for domain in top_domains:
            request_handler(dns_packet(domain), top_domain=True)
            fast_sleep(.1)

        Log.debug('top domains refreshed')

    class _DNSCache(dict):
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
        def __getitem__(self, key):
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
        def __missing__(self, key):
            return NOT_VALID

        def add(self, request, data_to_cache):
            '''add query to cache after calculating expiration time.'''
            self[request] = data_to_cache

            Log.debug(f'[{request}:{data_to_cache.ttl}] Added to standard cache. ')

        def search(self, query_name):
            '''if client requested domain is present in cache, will return namedtuple of time left on ttl
            and the dns records, otherwise will return None. top domain count will get automatically
            incremented if it passes filter.'''
            if (query_name):
                # list comp to built in any test for match. match will not increment top domain counter.
                if not any([fltr in query_name for fltr in top_domain_filter]):

                    with counter_lock:
                        domain_counter[query_name] += 1

            return self[query_name]

    _cache = _DNSCache()

    threading.Thread(target=auto_clear, args=(_cache,)).start()
    threading.Thread(target=manual_clear, args=(_cache,)).start()


# TODO: refactor name to be lowercase maybe.
def RequestTracker():
    ''' Tracks DNS Server requests and allows for either DNS Proxy or Server to add initial client address key
    on a first come basis and the second one will update the corresponding value index with info directly.

        RequestTracker([request_identifier: [client_query, decision, timestamp]])
    '''

    # storing as closure for lookup performance.
    # NOTE: only one request tracker will be active at a time so shared reference isn't a concern
    insert_lock = threading.Lock()
    counter_lock = threading.Lock()

    request_ready = threading.Event()
    request_wait = request_ready.wait
    request_set = request_ready.set
    request_clear = request_ready.clear

    _list = list

    # modified by class
    ready_count = 0
    request_tracker = OrderedDict()

    ready_requests = []
    ready_requests_append = ready_requests.append
    ready_requests_clear  = ready_requests.clear

    class _RequestTracker:

        @staticmethod
        # blocks until the request ready flag has been set, then iterates over dict and appends any client address with
        # both values present. (client_query class instance object and decision)
        def return_ready():
            nonlocal ready_count, ready_requests

            # blocking until an at least one request has been received
            request_wait()

            # clearing list from previously processed requests. this is new and replaced making a new list ever call
            # to return ready + direct ref to append
            ready_requests_clear()

            # iterating over a copy by passing dict into list
            for request_identifier, (client_query, decision, timestamp) in _list(request_tracker.items()):

                # using inverse because it has potential to be more efficient if both are not present. decision is more
                # likely to be input first, so it will be eval'd only if client_query is present.
                if (not client_query or not decision):

                    # removes entry from tracker if not finalized within 1 second
                    if (fast_time() - timestamp >= ONE_SEC):
                        del request_tracker[request_identifier]

                    continue

                ready_requests_append((client_query, decision))

                # lock protects count, which is also accessed by server and proxy via insert method.
                with counter_lock:
                    ready_count -= 1

                # removes entry from tracker if request is ready for forwarding.
                del request_tracker[request_identifier]

            if (not ready_count):
                request_clear()

            # NOTE: here temporarily for testing implementation
            elif (ready_count < 0):
                raise RuntimeError('Request Tracker ready count dropped below 0. probably fatal. yay me.')

            return ready_requests

        @staticmethod
        # this is a thread safe method to add entries to the request tracker dictionary. this will ensure the key
        # exists before updating the value. a default dict cannot be used (from what i can tell) because an empty
        # list would raise an index error if it was trying to set decision before request.
        def insert(request_identifier, data, *, module_index):
            nonlocal ready_count

            with insert_lock:

                tracked_request = request_tracker.get(request_identifier, None)
                # if client address is not already present, it will be added before updating the module index value
                if (not tracked_request):
                    # default entry: 1. client request instance 2. proxy decision, 3. timestamp
                    request_tracker[request_identifier] = [None, None, fast_time()]
                    request_tracker[request_identifier][module_index] = data

                # if present 1/2 entries exist so after this condition 2/2 will be present and request will be ready
                # for forwarding. setting thread event to allow return ready to unblock and start processing. checking
                # for None to prevent duplicate from triggering request ready.
                elif (tracked_request[module_index] is None):
                    with counter_lock:
                        ready_count += 1

                    request_tracker[request_identifier][module_index] = data

                    # notifying return_ready there is a query ready to forward
                    request_set()

    return _RequestTracker()
