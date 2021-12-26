#!/usr/bin/env python3

import threading

from collections import Counter, OrderedDict, namedtuple

from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_CACHE
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, write_configuration, load_top_domains_filter

from dnx_secmods.dns_proxy.dns_proxy_log import Log

from dnx_gentools.standard_tools import looper

request_info = namedtuple('request_info', 'server proxy')

# NOTE: normal_cache boolean is not working correctly. top domains are showing up as True
# fix or remove. might not be needed anymore as it was initial implemented to assist with
# ensuring the top domains system was actually working as intended.
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

    if the above callbacks are not set the top domains caching system will NOT actively update records, though the counts
    will still be accurate/usable.
    '''
    clear_dns_cache   = False
    clear_top_domains = False

    __slots__ = (
        '_dns_packet', '_request_handler',

        '_dom_counter', '_top_domains',
        '_counter_lock', '_top_dom_filter'
    )

    def __init__(self, *, packet, request_handler):
        self._dns_packet = packet
        self._request_handler = request_handler

        self._dom_counter = Counter()
        self._top_domains = {}
        self._top_dom_filter = []
        self._counter_lock  = threading.Lock()

        self._load_top_domains()
        threading.Thread(target=self._auto_clear_cache).start()
        threading.Thread(target=self._auto_top_domains).start()

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

        Log.debug(f'[{request}:{data_to_cache.ttl}] Added to standard cache. ')

    def search(self, query_name):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None. top domain count will get automatically
        incremented if it passes filter.'''
        if (query_name):
            self._increment_if_valid_top(query_name)

        return self[query_name]

    def _increment_if_valid_top(self, domain):
        # list comp to built in any test for match. match will not increment top domain counter.
        if any([fltr in domain for fltr in self._top_dom_filter]): return

        with self._counter_lock:
            self._dom_counter[domain] += 1

    @looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def _auto_clear_cache(self):
        cache, now = self.items, fast_time()
        if (self.clear_dns_cache):
            self.clear()
            self._reset_flag('dns_cache')

        expired = [dom for dom, record in cache() if now > record.expire]

        for domain in expired:
            del self[domain]

    @looper(THREE_MIN)
    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to
    # generate a new packet and add to the standard tls queue. the receiving end will know how to handle this by
    # settings the client address to none in the session tracker.
    def _auto_top_domains(self):
        if (self.clear_top_domains):
            self._dom_counter = Counter()
            self._reset_flag('top_domains')

        most_common_doms = self._dom_counter.most_common
        self._top_domains = {
            dom[0]: cnt for cnt, dom in enumerate(most_common_doms(TOP_DOMAIN_COUNT), 1)
        }

        request_handler, dns_packet = self._request_handler, self._dns_packet
        for domain in self._top_domains:
            request_handler(dns_packet(domain))
            fast_sleep(.1)

        Log.debug('top domains refreshed')

        write_configuration(self._top_domains, 'dns_cache')

    @classmethod
    # method called to reset dictionary cache for sent in value (standard or top domains) and then reset the flag in the
    # json file back to false. needed class method since the structures are stored within the class scope.
    def _reset_flag(cls, cache_type):
        setattr(cls, f'clear_{cache_type}', False)
        with ConfigurationManager('dns_server') as dnx:
            dns_settings = dnx.load_configuration()

            dns_settings['cache'][cache_type] = False

            dnx.write_configuration(dns_settings)

        Log.notice(f'{cache_type.replace("_", " ")} has been cleared.')

    # loads top domains from file for persistence between restarts/shutdowns and top domains filter
    def _load_top_domains(self):
        self._top_domains = load_configuration('dns_cache')

        dom_list = reversed(list(self._top_domains))
        self._dom_counter = Counter({dom: cnt for cnt, dom in enumerate(dom_list)})

        self._top_dom_filter = set(load_top_domains_filter())


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

    class _RequestTracker(OrderedDict):

        # blocks until the request ready flag has been set, then iterates over dict and appends any client address with
        # both values present. (client_query class instance object and decision)
        def return_ready(self):
            nonlocal ready_count

            request_wait()

            ready_requests = []
            ready_requests_append = ready_requests.append
            # iterating over a copy by passing dict into list
            for request_identifier, (client_query, decision, timestamp) in _list(self.items()):

                # using inverse because it has potential to be more efficient if both are not present. decision is more
                # likely to be input first, so it will be evaled only if client_query is present.
                if (not client_query or not decision):

                    # removes entry from tracker if not finalized within 1 second
                    if (fast_time() - timestamp >= ONE_SEC):
                        del self[request_identifier]

                    continue

                ready_requests_append((client_query, decision))

                # lock protects count, which is also accessed by server and proxy via insert method.
                with counter_lock:
                    ready_count -= 1

                # removes entry from tracker if request is ready for forwarding.
                del self[request_identifier]

            if (not ready_count):
                request_clear()

            # NOTE: here temporarily for testing implementation
            elif (ready_count < 0):
                raise RuntimeError('Request Tracker ready count dropped below 0. probably fatal. yay me.')

            return ready_requests

        # this is a thread safe method to add entries to the request tracker dictionary. this will ensure the key
        # exists before updating the value. a default dict cannot be used (from what i can tell) because an empty
        # list would raise an index error if it was trying to set decision before request.
        def insert(self, request_identifier, data, *, module_index):
            nonlocal ready_count

            with insert_lock:

                tracked_request = self.get(request_identifier, None)
                # if client address is not already present, it will be added before updating the module index value
                if (not tracked_request):
                    # default entry: 1. client request instance 2. proxy decision, 3. timestamp
                    self[request_identifier] = [None, None, fast_time()]
                    self[request_identifier][module_index] = data

                # if present 1/2 entries exist so after this condition 2/2 will be present and request will be ready
                # for forwarding. setting thread event to allow return ready to unblock and start processing. checking
                # for None to prevent duplicate from triggering request ready.
                elif (tracked_request[module_index] is None):
                    with counter_lock:
                        ready_count += 1

                    self[request_identifier][module_index] = data

                    # notifying return_ready there is a query ready to forwarding
                    request_set()

    return _RequestTracker()
