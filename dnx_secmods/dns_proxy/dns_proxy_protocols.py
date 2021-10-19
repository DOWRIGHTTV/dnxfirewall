#!usr/bin/env python3

import threading
import ssl

from socket import socket, timeout, AF_INET, SOCK_STREAM, SOCK_DGRAM

from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import RELAY_CONN

from dnx_secmods.dns_proxy.dns_proxy_packets import ClientRequest
from dnx_secmods.dns_proxy.dns_proxy_log import Log

from dnx_iptools.packet_classes import ProtoRelay
from dnx_iptools.def_structs import short_unpackf
from dnx_gentools.standard_tools import looper, dnx_queue

RELAY_TIMEOUT = 10


class UDPRelay(ProtoRelay):
    _protocol = PROTO.UDP

    __slots__ = ()

    def _register_new_socket(self):
        for dns_server in self._DNSServer.dns_servers:

            # if server is down we will skip over it
            if (not dns_server[self._protocol]): continue

            # never fail so will always return True
            return self._create_socket(dns_server['ip'])

        else:
            Log.critical(f'[{self._protocol}] No DNS servers available.')

    @dnx_queue(Log, name='UDPRelay')
    def relay(self, client_query):
        self._send_query(client_query)

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self):
        conn_recv = self._relay_conn.recv
        responder_add = self._DNSServer.responder.add

        while True:
            try:
                data_from_server = conn_recv(1024)
            except OSError:
                break

            except timeout:
                self.mark_server_down()

                return

            else:
                # passing over empty udp payloads.
                if (data_from_server):
                    responder_add(data_from_server)

                self._reset_fail_detection()

        self._relay_conn.sock.close()

    def _create_socket(self, server_ip):
        dns_sock = socket(AF_INET, SOCK_DGRAM)

        # udp connect allows send method to be used, but does not actually have an underlying connection
        dns_sock.connect((server_ip, PROTO.DNS))
        dns_sock.settimeout(RELAY_TIMEOUT)

        self._relay_conn = RELAY_CONN(server_ip, dns_sock, dns_sock.send, dns_sock.recv, 'UDP')

        return True


class TLSRelay(ProtoRelay):
    _protocol   = PROTO.DNS_TLS
    _keepalives = False
    _dns_packet = ClientRequest.generate_keepalive

    __slots__ = (
        '_tls_context'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._create_tls_context()
        threading.Thread(target=self._tls_keepalive).start()

    @property
    def fail_condition(self):
        return not self._DNSServer.tls_up and self._DNSServer.udp_fallback

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isnt already established when attempting to send query.
    def _register_new_socket(self): #, client_query=None):
        for tls_server in self._DNSServer.dns_servers:

            # skipping over known down server
            if (not tls_server[self._protocol]): continue

            # attempting to connect via tls. if successful will return True, otherwise mark server as
            # down and try next server.
            if self._tls_connect(tls_server['ip']): return True

            self.mark_server_down(remote_server=tls_server['ip'])

        else:
            self._DNSServer.tls_up = False

            Log.error(f'[{self._protocol}] No DNS servers available.')

    @dnx_queue(Log, name='TLSRelay')
    def relay(self, client_query):
        # if servers are down and a fallback is configured, it will be forwarded to that relay queue, otherwise
        # the request will be silently dropped here if fallback is not configured.
        if (self.fail_condition and self._fallback_relay):
            self._fallback_relay_add(client_query)

        else:
            self._send_query(client_query)

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self, recv_buffer=[]):
        Log.debug(f'[{self._relay_conn.remote_ip}/{self._protocol.name}] Response handler opened.') # pylint: disable=no-member
        recv_buff_append = recv_buffer.append
        recv_buff_clear  = recv_buffer.clear
        conn_recv = self._relay_conn.recv
        responder_add = self._DNSServer.responder.add

        while True:
            try:
                data_from_server = conn_recv(2048)
            except OSError:
                break

            except timeout:
                self.mark_server_down()

                Log.warning(f'[{self._relay_conn.remote_ip}/{self._protocol.name}] Remote server connection timeout. Marking down.') # pylint: disable=no-member

                return

            else:
                # if no data is received/EOF the remote end has closed the connection
                if (not data_from_server):
                    break

                self._reset_fail_detection()

            recv_buff_append(data_from_server)
            while recv_buffer:
                current_data = byte_join(recv_buffer)
                data_len, data = short_unpackf(current_data)[0], current_data[2:]

                # more data is needed for a complete response. NOTE: this scenario is kind of dumb
                # and shouldnt happen unless the server sends length of record and record seperately.
                if (len(data) < data_len): break

                # clearing the buffer since we either have nothing left to process or we will re add
                # the leftover bytes back with the next condition.
                recv_buff_clear()

                # if expected data length is greater than local buffer, multiple records were returned
                # in a batch so appending leftover bytes after removing the current records data from buffer.
                if (len(data) > data_len):
                    recv_buff_append(data[data_len:])

                # ignoring internally generated connection keepalives
                if (data[0] != DNS.KEEPALIVE):
                    responder_add(data[:data_len])

        self._relay_conn.sock.close()

    def _tls_connect(self, tls_server):

        Log.dprint(f'[{tls_server}/{self._protocol.name}] Opening secure socket.') # pylint: disable=no-member
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(RELAY_TIMEOUT)

        dns_sock = self._tls_context.wrap_socket(sock, server_hostname=tls_server)
        try:
            dns_sock.connect((tls_server, PROTO.DNS_TLS))
        except OSError:
            Log.error(f'[{tls_server}/{self._protocol.name}] Failed to connect to server: {E}') # pylint: disable=no-member

        except Exception as E:
            Log.console(f'[{tls_server}/{self._protocol.name}] TLS context error while attemping to connect to server: {E}') # pylint: disable=no-member
            Log.debug(f'[{tls_server}/{self._protocol.name}] TLS context error while attemping to connect to server: {E}') # pylint: disable=no-member

        else:
            self._relay_conn = RELAY_CONN(
                tls_server, dns_sock, dns_sock.send, dns_sock.recv, dns_sock.version()
            )

            return True

        return None

    @looper(8)
    # will send a valid dns query every ^ seconds to ensure the pipe does not get closed by remote server for
    # inactivity. this is only needed if servers are rapidly closing connections and can be enable/disabled.
    def _tls_keepalive(self):
        if (self.is_enabled and self._keepalives):

            self.relay.add(self._dns_packet(KEEP_ALIVE_DOMAIN, self._protocol)) # pylint: disable=no-member

    def _create_tls_context(self):
#        self._tls_context = ssl.create_default_context()
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations(CERTIFICATE_STORE)
