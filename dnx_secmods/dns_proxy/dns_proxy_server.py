#!/usr/bin/python3

import os, sys
import threading
import socket

from random import randint

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.def_namedtuples import DNS_SERVERS
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.packet_classes import Listener
from dnx_secmods.dns_proxy.dns_proxy_automate import Configuration, Reachability
from dnx_secmods.dns_proxy.dns_proxy_cache import DNSCache, RequestTracker
from dnx_secmods.dns_proxy.dns_proxy_protocols import UDPRelay, TLSRelay
from dnx_secmods.dns_proxy.dns_proxy_packets import ClientRequest, ServerResponse

from dnx_secmods.dns_proxy.dns_proxy_log import Log


# the socket returns after "connecting" to remote server, but the protocol is listed as 0. when the relay
# attempts to send the requests, we get no return (prob cuz tcp handshake never happened)
class DNSServer(Listener):
    protocol = PROTO.NOT_SET
    tls_up   = False

    REQ_TRACKER = RequestTracker()

    # NOTE: settings valued to None to denote initialization has not been completed.
    dns_records = {}
    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None},
        {'ip': None, PROTO.UDP: None, PROTO.DNS_TLS: None}
    )

    _request_map = {}
    _records_cache = None
    _id_lock = threading.Lock()

    # dynamic inheritance reference
    _packet_parser = ClientRequest

    __slots__ = (
        '_request_map_pop', '_dns_records_get', '_records_cache_add',
        '_records_cache_search', 'request_tracker_insert'
    )

    @classmethod
    def _setup(cls):
        Configuration.server_setup(cls, DNSCache)

        # setting parent class callback to allow custom actions on subclasses
        cls.set_proxy_callback(func=cls.receive_request)

        Reachability.run(cls)
        TLSRelay.run(cls, fallback_relay=UDPRelay.relay)
        UDPRelay.run(cls)

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query
        )

    # must extend parent method
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        threading.Thread(target=self.responder).start()
        threading.Thread(target=self._request_queue).start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop
        self._dns_records_get = self.dns_records.get
        # self._req_results_pop = self.REQ_RESULTS.pop
        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search

        self.request_tracker_insert = self.REQ_TRACKER.insert

    # NOTE: this is the callback assigned on start and is called by the listener parent class after parsing.
    def receive_request(self, client_query):
        self.request_tracker_insert(client_query.request_identifier, client_query, module_index=DNS.SERVER)

    @dnx_queue(Log, name='DNSServer')
    def responder(self, server_response):
        server_response = ServerResponse(server_response)
        try:
            server_response.parse()
        except Exception:
            raise
        else:
            client_query = self._request_map_pop(server_response.dns_id, None)
            if (not client_query): return

            # generate response for client, if top domain generate for cache storage
            server_response.generate_server_response(client_query.dns_id)
            if (not client_query.top_domain):
                self.send_to_client(server_response, client_query)

            #NOTE: will is valid check prevent empty RRs from being cached.??
            if (server_response.data_to_cache):
                self._records_cache_add(client_query.request, server_response.data_to_cache)

    def _pre_inspect(self, client_query):
        if (client_query.qr != DNS.QUERY or client_query.qtype not in [DNS.A, DNS.NS]):
            return False

        local_record = self._dns_records_get(client_query.request)

        # generating server response and sending to client. client query is passed in twice for compatibility
        # with external lookups using a separate class/instance to generate the data.
        if (local_record):
            client_query.generate_record_response(local_record)
            self.send_to_client(client_query, client_query)

            return False

        # if domain is local (example.local or no tld) and it was not in local records, we can ignore.
        elif (client_query.dom_local):
            return False

        return True

    # thread to handle all received requests from the listerner.
    def _request_queue(self):
        return_ready = self.REQ_TRACKER.return_ready

        while True:

            # this blocks until request tracker returns (at least 1 client query has been inspected)
            requests = return_ready()

            for client_query, decision in requests:

                # if request is allowed, search cache before sending sending to relay.
                if decision is DNS.ALLOWED and not self._cached_response(client_query):
                    self._handle_query(client_query)

                    Log.debug(f'{self.protocol.name} Relay ALLOWED | {client_query}') # pylint: disable=no-member

    def _cached_response(self, client_query):
        '''searches cache for query name. if a cached record is found, a response will be generated
        and sent back to the client.'''

        cached_dom = self._records_cache_search(client_query.request)
        if (cached_dom.records):
            client_query.generate_cached_response(cached_dom)
            self.send_to_client(client_query, client_query)

            return True

    @classmethod
    def _handle_query(cls, client_query):
        new_dns_id = cls._get_unique_id()
        cls._request_map[new_dns_id] = client_query

        # TODO: lets put a direct reference to relay add for perf!!!
        client_query.generate_dns_query(new_dns_id, cls.protocol)
        if (cls.protocol is PROTO.UDP):
            UDPRelay.relay.add(client_query) # pylint: disable=no-member

        elif (cls.protocol is PROTO.DNS_TLS):
            TLSRelay.relay.add(client_query) # pylint: disable=no-member
        else:
            # TODO: raise exception fatal, log
            pass

    @classmethod
    # NOTE: maybe put a sleep on iteration, use a for loop?
    def _get_unique_id(cls):
        request_map = cls._request_map

        with cls._id_lock:
            # NOTE: maybe tune this number. under high load collisions could occur and we dont want it to waste time
            # because other requests must wait for this process to complete since we are now using a queue system for
            # while waiting for a decision instead of individual threads.
            for _ in range(100):
            # while True:
                dns_id = randint(70, 32000)
                if (dns_id not in request_map):

                    request_map[dns_id] = 1

                    return dns_id

    @staticmethod
    def send_to_client(server_response, client_query):
        try:
            client_query.sendto(server_response.send_data, client_query.address)
        except OSError:
            pass

    @staticmethod
    def listener_sock(intf, intf_ip):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        l_sock.setblocking(0)

        l_sock.bind((f'{intf_ip}', PROTO.DNS))

        return l_sock
