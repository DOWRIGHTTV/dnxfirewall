#!/usr/bin/env python3

from __future__ import annotations

import socket
import threading

from random import randint
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO, DNS
from dnx_gentools.def_namedtuples import DNS_SERVERS
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.protocol_tools import btoia
from dnx_iptools.packet_classes import Listener

from dns_proxy_automate import Configuration, Reachability
from dns_proxy_cache import dns_cache, request_tracker
from dns_proxy_protocols import UDPRelay, TLSRelay
from dns_proxy_packets import ClientQuery, ttl_rewrite
from dns_proxy_log import Log

INVALID_RESPONSE: tuple[None, None] = (None, None)

REQ_TRACKER: RequestTracker = request_tracker()
REQ_TRACKER_INSERT = REQ_TRACKER.insert

udp_relay_add = UDPRelay.relay.add
tls_relay_add = TLSRelay.relay.add


class DNSServer(Listener):
    protocol: ClassVar[PROTO] = PROTO.NOT_SET
    tls_down: ClassVar[bool] = True
    udp_fallback: ClassVar[bool] = False
    keepalive_interval: ClassVar[int] = 8

    # NOTE: setting values to None to denote initialization has not been completed.
    dns_records: ClassVar[dict[str, str]] = {}
    dns_servers: ClassVar[DNS_SERVERS] = DNS_SERVERS(
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None},
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None}
    )

    _request_map: ClassVar[dict[int], tuple[bool, ClientQuery]] = {}
    _id_lock: ClassVar[Lock] = threading.Lock()

    _listener_parser: ClassVar[ClientQuery] = ClientQuery

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
        self._request_map_pop: Callable[[], ClientQuery] = self._request_map.pop
        self._dns_records_get: Callable[[str], str] = self.dns_records.get

    # thread to handle all received requests from the listener.
    def _request_queue(self) -> NoReturn:
        return_ready = REQ_TRACKER.return_ready

        for _ in RUN_FOREVER:

            # generator that blocks until at least 1 request is in the queue. if multiple requests are present, they
            # will be yielded back until the queue is empty.
            for client_query in return_ready():

                # search cache before sending to relay.
                if not self._cache_available(client_query):
                    self.handle_query(client_query)

    # NOTE: A, NS records are supported only. consider expanding
    def _pre_inspect(self, client_query: ClientQuery) -> bool:
        if (client_query.qr != DNS.QUERY or client_query.qtype not in [DNS.A, DNS.NS]):
            return False

        record_ip: int = self._dns_records_get(client_query.qname)

        # generating server response and sending to client.
        if (record_ip):
            query_response = client_query.generate_record_response(record_ip)
            send_to_client(client_query, query_response)

            return False

        # if the domain is local (no tld) and it was not in local records, then we can ignore.
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

        client_query: ClientQuery = self._request_map_pop(dns_id, INVALID_RESPONSE)
        if (not client_query):
            return

        try:
            query_response, cache_data = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            if (not client_query.top_domain):
                send_to_client(client_query, query_response)

            if (cache_data):
                dns_cache_add(client_query.qname, cache_data)

    # FIXME: this was a classmethod, but i changed it thinking it didnt need to be. after looking, the cache dict
    # calls this method directly through class so this would need to be a classmethod or we need to provide the instance
    # to the cache dict for it to use.
    # top_domain will now be set by the caller, so we don't have to track that within the query object.
    def handle_query(self, client_query: ClientQuery) -> None:

        # generating dns query packet data
        send_data = client_query.generate_dns_query(
            # returns new unique id after storing {id: request info} in request map
            get_unique_id(self._request_map, client_query), self.protocol
        )

        # queue send_data to currently enabled protocol/relay for sending to external resolver.
        # request is sent for logging purposes and may be temporary.
        if (self.protocol is PROTO.UDP):
            udp_relay_add(send_data, client_query.qname)

        elif (self.protocol is PROTO.DNS_TLS):
            tls_relay_add(send_data, client_query.qname)

    @staticmethod
    def _cache_available(client_query: ClientQuery) -> bool:
        '''searches cache for query name.

        if a cached record is found, a response will be generated and sent back to the client.
        '''
        # only A, CNAME records are cached and CNAMEs are always attached to A record query responses.
        if (client_query.qtype != DNS.A):
            return False

        cached_dom = dns_cache_search(client_query.qname)
        if (not cached_dom.records):
            return False

        query_response = client_query.generate_cached_response(cached_dom)
        send_to_client(client_query, query_response)

        return True

    @staticmethod
    def listener_sock(intf: str, intf_ip: int) -> Socket:
        l_sock = socket(AF_INET, SOCK_DGRAM)

        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        l_sock.setblocking(False)

        l_sock.bind((itoip(intf_ip), PROTO.DNS))

        return l_sock


# DNS ID generation. this value is guaranteed unique for the life of the request.
_id_lock: Lock = threading.Lock()

def get_unique_id(request_map: dict, client_query: ClientQuery) -> int:

    with _id_lock:
        for _ in RUN_FOREVER:

            dns_id = randint(70, 32000)
            if (dns_id not in request_map):

                request_map[dns_id] = client_query

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
    request_handler=REQ_TRACKER_INSERT
)

dns_cache_add = DNS_CACHE.add
dns_cache_search = DNS_CACHE.search
