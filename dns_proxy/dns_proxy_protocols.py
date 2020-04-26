#!usr/bin/env python3

import os, sys
import random
import threading
import traceback
import ssl
import socket

from copy import deepcopy
from collections import deque

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_namedtuples import RELAY_CONN
from dnx_iptools.dnx_parent_classes import ProtoRelay
from dnx_iptools.dnx_structs import short_unpackf
from dnx_iptools.dnx_standard_tools import looper, dnx_queue

from dns_proxy.dns_proxy_log import Log
from dns_proxy.dns_proxy_packets import ClientRequest, ServerResponse

from dnx_configure.dnx_code_profiler import profiler


class UDPRelay(ProtoRelay):
    _protocol = PROTO.UDP

    __slots__ = ()

    @property
    def standby_condition(self):
        if (self.DNSServer.udp_fallback and not self.DNSServer.tls_up):
            return True

        return False

    def _register_new_socket(self):
        with self.DNSServer.server_lock:
            for dns_server in self.DNSServer.dns_servers:
                if (not dns_server[self._protocol]): continue

                return self._create_socket(dns_server['ip']) # never fail so will always return True
            else:
                Log.critical('NO UDP SERVER AVAILABLE.')

    @dnx_queue(Log, name='UDPRelay')
    def relay(self, client_query):
        self._send_query(client_query)

    # TODO: see if this can be moved into parent class
    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self):
        while True:
            try:
                data_from_server = self._relay_conn.sock.recv(1024)
            except (socket.timeout, OSError) as e:
                print(f'RCV SOCKET ERROR: {e}')
                break
            else:
                if (not data_from_server): continue
                self._reset_fail_detection()
                self.DNSServer.queue.add(data_from_server)

        self._relay_conn.sock.close()

    def _create_socket(self, server_ip):
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.connect((server_ip, PROTO.DNS))

        self._relay_conn = RELAY_CONN(server_ip, dns_sock)

        return True


class TLSRelay(ProtoRelay):
    _protocol   = PROTO.DNS_TLS
    _keepalives = False
    _dns_packet = ClientRequest.generate_keepalive

    __slots__ = (
        '_tls_context'
    )

    # TODO: see if tls up can be moved here. | reachability???
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._create_tls_context()
        threading.Thread(target=self._tls_keepalive).start()

    @property
    def fail_condition(self):
        if (not self.DNSServer.tls_up and self.DNSServer.udp_fallback):
            return True

        return False

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isnt already established when attempting to send query.
    def _register_new_socket(self, client_query=None):
        with self.DNSServer.server_lock:
            for tls_server in self.DNSServer.dns_servers:
                if (not tls_server[self._protocol]): continue

                if self._tls_connect(tls_server['ip']): return True

                self.mark_server_down()
            else:
                Log.error('NO SECURE SERVERS AVAILABLE!')
                self.DNSServer.tls_up = False
                if (self.DNSServer.udp_fallback and client_query):
                    self._send_to_fallback(client_query)

    @dnx_queue(Log, name='TLSRelay')
    def relay(self, client_query):
        if (self.fail_condition and self._fallback):
            return self._send_to_fallback(client_query)

        self._send_query(client_query)

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self):
        recv_buffer = []
        while True:
            try:
                data_from_server = self._relay_conn.sock.recv(1024)
            except (socket.timeout, OSError) as e:
                Log.dprint(f'RECV HANDLER: {e}')
                break

            else:
                self._reset_fail_detection()
                if (not data_from_server):
                    Log.dprint('RECV HANDLER: PIPELINE CLOSED BY REMOTE SERVER!')
                    break

                recv_buffer.append(data_from_server)
                while recv_buffer:
                    current_data = b''.join(recv_buffer)[2:]
                    data_len = short_unpackf(recv_buffer[0])[0]
                    if (len(current_data) == data_len):
                        recv_buffer = []
                    elif (len(current_data) > data_len):
                        recv_buffer = [current_data[data_len:]]
                    else: break

                    if not self.is_keepalive(current_data):
                        self.DNSServer.responder.add(current_data[:data_len])

        self._relay_conn.sock.close()

#    @profiler
    def _tls_connect(self, tls_server):
        Log.dprint(f'Opening Secure socket to {tls_server}: 853')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # NOTE: this should improve sending performance since we expect a dns record to only be a small
        # portion of available bytes in MTU/max bytes(1500). seems to provide no improvement after 1 run.
        # there could be other bottlenecks in play so we can re evaluate later.
        # sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        dns_sock = self._tls_context.wrap_socket(sock, server_hostname=tls_server)
        try:
            dns_sock.connect((tls_server, PROTO.DNS_TLS))
        except OSError:
            return None
        else:
            return True
        finally:
            self._relay_conn = RELAY_CONN(tls_server, dns_sock)

    @looper(8)
    # will send a valid dns query every ^ seconds to ensure the pipe does not get closed by remote server for
    # inactivity. this is only needed if servers are rapidly closing connections and can be enable/disabled.
    def _tls_keepalive(self):
        if (not self.is_enabled or not self._keepalives): return

        self.relay.add(self._dns_packet(KEEP_ALIVE_DOMAIN, self._protocol)) # pylint: disable=no-member

    def _create_tls_context(self):
        self._tls_context = ssl.create_default_context()
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
