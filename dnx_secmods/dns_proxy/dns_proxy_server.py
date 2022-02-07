#!/usr/bin/env python3

import threading
import socket

from random import randint
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_namedtuples import DNS_SERVERS
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.protocol_tools import btoia
from dnx_iptools.packet_classes import Listener

from dns_proxy_automate import Configuration, Reachability
from dns_proxy_cache import dns_cache, request_tracker
from dns_proxy_protocols import UDPRelay, TLSRelay
from dns_proxy_packets import ClientQuery, ttl_rewrite
from dns_proxy_log import Log

INVALID_RESPONSE: Tuple[None, None] = (None, None)

REQ_TRACKER = request_tracker()
REQ_TRACKER_INSERT = REQ_TRACKER.insert

udp_relay_add = UDPRelay.relay.add
tls_relay_add = TLSRelay.relay.add


class DNSServer(Listener):
    protocol = PROTO.NOT_SET
    tls_down = True
    udp_fallback = False
    keepalive_interval = 8

    # NOTE: setting values to None to denote initialization has not been completed.
    dns_records = {}
    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None},
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None}
    )

    _request_map = {}
    _records_cache = None
    _id_lock = threading.Lock()

    _packet_parser = ClientQuery

    __slots__ = (
        '_request_map_pop', '_dns_records_get'
    )

    @classmethod
    def _setup(cls) -> None:
        Configuration.server_setup(cls)

        # setting parent class callback to allow custom actions on subclasses
        cls.set_proxy_callback(func=REQ_TRACKER_INSERT)

        Reachability.run(cls)
        TLSRelay.run(cls, fallback_relay=UDPRelay.relay)
        UDPRelay.run(cls)

    # extending parent method because we need to passthrough threaded and always on attrs.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        threading.Thread(target=self.responder).start()
        threading.Thread(target=self._request_queue).start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop
        self._dns_records_get = self.dns_records.get

    # thread to handle all received requests from the listener.
    def _request_queue(self) -> None:
        return_ready = REQ_TRACKER.return_ready

        for _ in RUN_FOREVER():

            # generator that blocks until at least 1 request is in the queue. if multiple requests are present, they
            # will be yielded back until the queue is empty.
            for client_query in return_ready():

                # search cache before sending to relay.
                if not self._cache_available(client_query):
                    self.handle_query(client_query)

    # TODO: A, NS records are supported only. consider expanding
    def _pre_inspect(self, client_query: ClientQuery) -> bool:
        if (client_query.qr != DNS.QUERY or client_query.qtype not in [DNS.A, DNS.NS]):
            return False

        local_record = self._dns_records_get(client_query.request)

        # generating server response and sending to client.
        if (local_record):
            query_response = client_query.generate_record_response(local_record)
            send_to_client(client_query, query_response)

            return False

        # if domain is local (no tld) and it was not in local records, we can ignore.
        elif (client_query.local_domain):
            return False

        return True

    @dnx_queue(Log, name='DNSServer')
    def responder(self, received_data: bytes) -> None:
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
                send_to_client(client_query, query_response)

            if (cache_data):
                dns_cache_add(client_query.qname, cache_data)

    @classmethod
    # top_domain will now be set by caller, so we don't have to track that within the query object.
    def handle_query(cls, client_query: ClientQuery, *, top_domain: bool = False) -> None:

        # generating dns query packet data
        client_query.generate_dns_query(
            # returns new unique id after storing {id: request info} in request map
            get_unique_id(cls._request_map, (top_domain, client_query)), cls.protocol
        )

        # send query instance to currently enabled protocol/relay for sending to external resolver.
        if (cls.protocol is PROTO.UDP):
            udp_relay_add(client_query)

        elif (cls.protocol is PROTO.DNS_TLS):
            tls_relay_add(client_query)

    @staticmethod
    def _cache_available(client_query: ClientQuery) -> bool:
        '''searches cache for query name. if a cached record is found, a response will be generated
        and sent back to the client.'''

        # only A, CNAME records are cached and CNAMEs are always attached to A record query responses.
        if (client_query.qtype != DNS.A):
            return False

        cached_dom = dns_cache_search(client_query.request)
        if (cached_dom.records):
            query_response = client_query.generate_cached_response(cached_dom)
            send_to_client(client_query, query_response)

            return True

    @staticmethod
    def listener_sock(intf: str, intf_ip: IPv4Address) -> socket:
        l_sock = socket(AF_INET, SOCK_DGRAM)

        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        l_sock.setblocking(False)

        l_sock.bind((f'{intf_ip}', PROTO.DNS))

        return l_sock


# DNS ID generation. this value is guaranteed unique for the life of the request.
_id_lock = threading.Lock()

def get_unique_id(request_map: dict, request_info: tuple) -> int:

    with _id_lock:
        # NOTE: maybe tune this number. under high load collisions could occur and other requests must wait for this
        # process to complete since we are now using a queue system for checking decision instead of individual threads.
        for _ in RUN_FOREVER():

            dns_id = randint(70, 32000)
            if (dns_id not in request_map):

                request_map[dns_id] = request_info

                return dns_id

def send_to_client(client_query: ClientQuery, query_response: bytearray) -> None:
    try:
        client_query.sendto(query_response, client_query.address)
    except OSError:
        pass


# ======================
# DNS RECORD CACHE DICT
# ======================
# initializing dns cache/ sending in reference to needed methods for top domains
DNS_CACHE = dns_cache(
    dns_packet=ClientQuery.generate_local_query,
    request_handler=DNSServer.handle_query
)
dns_cache_add = DNS_CACHE.add
dns_cache_search = DNS_CACHE.search
