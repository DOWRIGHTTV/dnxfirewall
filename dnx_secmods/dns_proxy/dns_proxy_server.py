#!/usr/bin/env python3

import threading
import socket

from random import randint

from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_SERVERS
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.protocol_tools import btoia
from dnx_iptools.packet_classes import Listener

from dnx_secmods.dns_proxy.dns_proxy_automate import Configuration, Reachability
from dnx_secmods.dns_proxy.dns_proxy_cache import DNSCache, RequestTracker
from dnx_secmods.dns_proxy.dns_proxy_protocols import UDPRelay, TLSRelay
from dnx_secmods.dns_proxy.dns_proxy_packets import ClientRequest, ttl_rewrite
from dnx_secmods.dns_proxy.dns_proxy_log import Log

INVALID_RESPONSE = (None, None)


class DNSServer(Listener):
    protocol = PROTO.NOT_SET
    tls_down = True
    keepalive_interval = 8

    REQ_TRACKER = RequestTracker()

    # NOTE: setting values to None to denote initialization has not been completed.
    dns_records = {}
    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None},
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None}
    )

    _request_map = {}
    _records_cache = None
    _id_lock = threading.Lock()

    # dynamic inheritance reference... ??? wtf is this comment
    _packet_parser = ClientRequest

    __slots__ = (
        '_request_map_pop', '_dns_records_get', '_records_cache_add',
        '_records_cache_search', 'request_tracker_insert'
    )

    @classmethod
    def _setup(cls):
        Configuration.server_setup(cls)

        # setting parent class callback to allow custom actions on subclasses
        cls.set_proxy_callback(func=cls.receive_request)

        Reachability.run(cls)
        TLSRelay.run(cls, fallback_relay=UDPRelay.relay)
        UDPRelay.run(cls)

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            dns_packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query
        )

    # extending parent method because we need to passthrough threaded and always on attrs.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        threading.Thread(target=self.responder).start()
        threading.Thread(target=self._request_queue).start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop
        self._dns_records_get = self.dns_records.get
        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search

        self.request_tracker_insert = self.REQ_TRACKER.insert

    # NOTE: this is the callback assigned on start and is called by the listener parent class after parsing.
    def receive_request(self, client_query):
        self.request_tracker_insert(client_query.request_identifier, client_query, module_index=DNS.SERVER)

    # TODO: A, NS records are supported only. consider expanding
    def _pre_inspect(self, client_query):
        if (client_query.qr != DNS.QUERY or client_query.qtype not in [DNS.A, DNS.NS]):
            return False

        local_record = self._dns_records_get(client_query.request)

        # generating server response and sending to client. client query is passed in twice for compatibility
        # with external lookups using a separate class/instance to generate the data.
        if (local_record):
            query_response = client_query.generate_record_response(local_record)
            send_to_client(query_response, client_query)

            return False

        # if domain is local (no tld) and it was not in local records, we can ignore.
        elif (client_query.local_domain):
            return False

        return True

    # thread to handle all received requests from the listener.
    def _request_queue(self):
        return_ready = self.REQ_TRACKER.return_ready

        for _ in RUN_FOREVER():

            # this blocks until request tracker returns (at least 1 client query has been inspected)
            requests = return_ready()

            for client_query, decision in requests:

                # if request is allowed, search cache before sending to relay.
                if decision is DNS.ALLOWED and not self._cached_response(client_query):
                    self._handle_query(client_query)

                    Log.debug(f'{self.protocol.name} Relay ALLOWED | {client_query}')

    def _cached_response(self, client_query):
        '''searches cache for query name. if a cached record is found, a response will be generated
        and sent back to the client.'''

        # only A, CNAME records are cached and CNAMEs are always attached to A record query responses.
        if (client_query.qtype != DNS.A):
            return False

        cached_dom = self._records_cache_search(client_query.request)
        if (cached_dom.records):
            query_response = client_query.generate_cached_response(cached_dom)
            send_to_client(query_response, client_query)

            return True

    @classmethod
    # top_domain will now be set by caller, so we don't have to track that within the query object.
    def _handle_query(cls, client_query, *, top_domain=False):

        # generating dns query packet data
        client_query.generate_dns_query(
            # returns new unique id after storing {id: request info} in request map
            get_unique_id(cls._request_map, (top_domain, client_query)), cls.protocol
        )

        # send query instance to currently enabled protocol/relay for sending to external resolver.
        if (cls.protocol is PROTO.UDP):
            UDPRelay.relay.add(client_query)

        elif (cls.protocol is PROTO.DNS_TLS):
            TLSRelay.relay.add(client_query)

    @dnx_queue(Log, name='DNSServer')
    def responder(self, received_data):
        # dns id is the first 2 bytes in the dns header
        dns_id = btoia(received_data[:2])

        # recently moved here for clarity. silently drops keepalive responses since they are not needed.
        if (dns_id == DNS.KEEPALIVE):
            return

        top_domain, client_query = self._request_map_pop(dns_id, INVALID_RESPONSE)
        if (not client_query):
            return

        try:
            query_response, cache_data = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            if (not top_domain):
                send_to_client(query_response, client_query)

            if (cache_data):
                self._records_cache_add(client_query.qname, cache_data)

    @staticmethod
    def listener_sock(intf, intf_ip):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        l_sock.setblocking(False)

        l_sock.bind((f'{intf_ip}', PROTO.DNS))

        return l_sock


# DNS ID generation. this value is guaranteed unique for the life of the request.
_id_lock = threading.Lock()

def get_unique_id(request_map, request_info):

    with _id_lock:
        # NOTE: maybe tune this number. under high load collisions could occur and other requests must wait for this
        # process to complete since we are now using a queue system for checking decision instead of individual threads.
        for _ in RUN_FOREVER:

            dns_id = randint(70, 32000)
            if (dns_id not in request_map):

                request_map[dns_id] = request_info

                return dns_id

def send_to_client(query_response, client_query):
    try:
        client_query.sendto(query_response, client_query.address)
    except OSError:
        pass
