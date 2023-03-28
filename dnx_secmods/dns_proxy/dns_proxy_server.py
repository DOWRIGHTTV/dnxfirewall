#!/usr/bin/env python3

from __future__ import annotations

import socket
import threading

from random import randint

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_SEND
from dnx_gentools.def_enums import PROTO, DNS
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.protocol_tools import btoia
from dnx_iptools.packet_classes import Listener

from dns_proxy_automate import ServerConfiguration
from dns_proxy_protocols import UDPRelay, TLSRelay
from dns_proxy_packets import ClientQuery, ttl_rewrite
from dns_proxy_cache import dns_cache, QNAME_NOT_FOUND
from dns_proxy_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import QNAME_RECORD_UPDATE

__all__ = (
    'DNSServer',
)

# ======================
# REQUEST MAP DICT
# ======================
REQUEST_MAP: dict[int, ClientQuery] = {}
REQUEST_MAP_POP = REQUEST_MAP.pop

# acquired prior to randomly selecting dns id
dns_id_lock: Lock_T = threading.Lock()

# ======================
# DNS RECORD CACHE DICT
# ======================
# initializing dns cache/ sending in reference to needed methods for top domains
# .start_pollers() call is required for top domains and cache clearing functionality
DNS_CACHE: DNSCache_T = dns_cache(dns_packet=ClientQuery.init_local_query)
DNS_CACHE_ADD = DNS_CACHE.add
DNS_CACHE_SEARCH = DNS_CACHE.search

# GENERAL DEFINITIONS
SUPPORTED_RECORD_TYPES = [DNS.A, DNS.NS]

INVALID_RESPONSE: tuple[None, None] = (None, None)

RELAY_MAP: dict[PROTO, Callable[[DNS_SEND], None]] = {
    PROTO.UDP: UDPRelay.relay.add,
    PROTO.DNS_TLS: TLSRelay.relay.add
}

# ======================
# MAIN DNS SERVER CLASS
# ======================
#   ServerConfiguration - provides config management between memory and filesystem
#   Listener - provides packet data Linux interface socket
# ======================
# todo: move the AAAA (ipv6) record not supported error response to the server and have proxy silenty ignore.
#   this will ensure AAAA record issues with linux (maybe mac too) will be mitigated without requiring dns proxy.
class DNSServer(ServerConfiguration, Listener):

    _listener_parser: ClassVar[ClientQuery] = ClientQuery

    __slots__ = (
        '_dns_records_get',
    )

    def __init__(self):
        # assigning object methods to reduce lookups
        self._dns_records_get = self.dns_records.get

        super().__init__()

    def _setup(self) -> None:

        self.configure()

        # ==========================
        # SENDER / RECEIVER QUEUES
        # ==========================
        threading.Thread(target=self.response_handler).start()
        threading.Thread(target=self.request_handler).start()

        # ==========================
        # TOP DOMAINS / CACHE CLEAR
        # ==========================
        DNS_CACHE.set_request_queue(self.request_handler)
        DNS_CACHE.start_pollers()

        # ==========================
        # PROTOCOL RELAY QUEUES
        # ==========================
        UDPRelay.run(self.__class__)
        TLSRelay.run(self.__class__, fallback_relay=UDPRelay.relay)

    def _pre_inspect(self, client_query: ClientQuery) -> bool:
        # this filter is required with new request queue api
        if (client_query.top_domain):
            return INSPECT_PACKET

        # NOTE: A/NS records are supported only. consider expanding
        if (client_query.qr != DNS.QUERY or client_query.qtype not in SUPPORTED_RECORD_TYPES):
            return DONT_INSPECT_PACKET

        record_ip: int = self._dns_records_get(client_query.qname)
        # generating server response and sending to client.
        if (record_ip):
            query_response = client_query.generate_record_response(record_ip)
            send_to_client(client_query, query_response)

            return DONT_INSPECT_PACKET

        # if the domain is local (no tld) and it was not in local records, then we can ignore.
        elif (client_query.local_domain):
            return DONT_INSPECT_PACKET

        return INSPECT_PACKET

    def _listener_sock(self, intf: str, intf_ip: int) -> Socket_T:
        l_sock: Socket_T = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        l_sock.setblocking(False)

        l_sock.bind((itoip(intf_ip), PROTO.DNS))

        return l_sock

    @dnx_queue(Log, name='DNSServer')
    def request_handler(self, client_query: ClientQuery) -> None:
        # fast path for certain conditions
        if self._pre_inspect(client_query) == DONT_INSPECT_PACKET:
            return

        qname_cache = cache_available(client_query)
        if (qname_cache is not QNAME_NOT_FOUND):
            send_to_client(client_query, client_query.generate_cached_response(qname_cache))

        else:
            # generating dns query packet data
            send_data = client_query.generate_dns_query(
                # returns new unique id after storing {id: request info} in request map
                get_unique_id(client_query), self.protocol
            )

            # queue send_data to currently enabled protocol/relay for sending to external resolver
            RELAY_MAP[self.protocol](
                DNS_SEND(client_query.qname, send_data)
            )

    @dnx_queue(Log, name='DNSServer')
    def response_handler(self, received_data: bytes) -> None:
        # dns id is the first 2 bytes in the dns header
        dns_id: int = btoia(received_data[:2])

        # recently moved here for clarity. silently drops keepalive responses since they are not needed.
        if (dns_id == DNS.KEEPALIVE):
            return

        client_query: ClientQuery = REQUEST_MAP_POP(dns_id, None)
        if (client_query is None):
            return

        try:
            query_response, cache_data = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            if (not client_query.top_domain):
                send_to_client(client_query, query_response)

            if (cache_data.records):
                DNS_CACHE_ADD(client_query.qname, cache_data)


# ==================
# GENERAL FUNCTIONS
# ==================
def get_unique_id(client_query: ClientQuery) -> int:
    '''DNS ID generation.

    this value is guaranteed unique for the life of the request.
    '''
    with dns_id_lock:
        for _ in RUN_FOREVER:

            dns_id = randint(70, 32000)
            if (dns_id not in REQUEST_MAP):

                REQUEST_MAP[dns_id] = client_query

                return dns_id

def cache_available(client_query: ClientQuery) -> QNAME_RECORD_UPDATE:
    '''searches cache for query name.

    if a cached record is found, a response will be generated and sent back to the client.
    '''
    # only A/CNAME records are cached and CNAME records are always attached to an A record query responses.
    if (client_query.qtype != DNS.A or client_query.top_domain):
        return QNAME_NOT_FOUND

    return DNS_CACHE_SEARCH(client_query.qname)

def send_to_client(client_query: ClientQuery, query_response: bytearray) -> None:
    try:
        client_query.sendto(query_response, (itoip(client_query.client_ip), client_query.client_port))
    except OSError:
        pass
