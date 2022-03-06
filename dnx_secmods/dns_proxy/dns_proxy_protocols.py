#!usr/bin/env python3

from __future__ import annotations

import threading
import ssl

from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO
from dnx_gentools.def_namedtuples import RELAY_CONN
from dnx_gentools.standard_tools import dnx_queue

from dnx_iptools.protocol_tools import btoia
from dnx_iptools.packet_classes import ProtoRelay

from dns_proxy_packets import ClientQuery
from dns_proxy_log import Log


class UDPRelay(ProtoRelay):
    _protocol: ClassVar[PROTO] = PROTO.UDP

    __slots__ = ()

    def _register_new_socket(self) -> bool:
        for dns_server in self._dns_server.dns_servers:

            # skip downed servers
            if (not dns_server[PROTO.UDP]): continue

            # never fails, so will always return True
            return self._create_socket(dns_server['ip'])

        else:
            Log.critical(f'[{self._protocol}] No DNS servers available.')

            return False

    @dnx_queue(Log, name='UDPRelay')
    def relay(self, send_data: bytearray, request: str):
        self._send_query(send_data, request)

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self) -> None:
        conn_recv = self._relay_conn.recv
        responder_add = self._dns_server.responder.add

        for _ in RUN_FOREVER:
            try:
                data_from_server = conn_recv(2048)
            except OSError:
                break

            # passing over empty udp payloads.
            if (not data_from_server):
                continue

            responder_add(data_from_server)

            # resetting fail detection
            self._last_rcvd = fast_time()
            self._send_cnt = 0

        self._relay_conn.sock.close()

    def _create_socket(self, server_ip: str) -> bool:
        dns_sock = socket(AF_INET, SOCK_DGRAM)

        # udp connect allows 'send' method to be used, but does not actually have an underlying connection
        dns_sock.connect((server_ip, PROTO.DNS))
        dns_sock.settimeout(RELAY_TIMEOUT)

        self._relay_conn = RELAY_CONN(server_ip, dns_sock, dns_sock.send, dns_sock.recv, 'UDP')

        return True


# ============================
# TLS sender/receiver
# ============================
# direct reference to alternate constructor
_keepalive = ClientQuery.generate_local_query

class TLSRelay(ProtoRelay):
    _protocol: ClassVar[PROTO] = PROTO.DNS_TLS

    __slots__ = (
        '_tls_context', '_keepalive_status'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # create tls context
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations(CERTIFICATE_STORE)

        # tls connection keepalive. hard set to 8 seconds, but can be enabled/disabled
        self._keepalive_status: Event = threading.Event()
        threading.Thread(target=self._keepalive_run).start()

    @property
    def fail_condition(self) -> bool:
        return self._dns_server.tls_down and self._dns_server.udp_fallback

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isn't already established when attempting to send query.
    def _register_new_socket(self) -> bool:
        for tls_server in self._dns_server.dns_servers:

            # skipping over known down server.
            if (not tls_server[PROTO.DNS_TLS]):
                continue

            # attempting to connect via tls.
            # if successful will return True, otherwise mark server as down and try next server.
            if self._tls_connect(tls_server['ip']):
                return True

            self.mark_server_down(remote_server=tls_server['ip'])

        else:
            self._dns_server.tls_down = True

            Log.error(f'[{self._protocol}] No DNS servers available.')

            return False

    @dnx_queue(Log, name='TLSRelay')
    def relay(self, send_data: bytearray, request: str) -> None:
        # if servers are down and a fallback is configured, it will be forwarded to that relay queue, otherwise
        # the request will be silently dropped.
        if (not self.fail_condition):
            self._send_query(send_data, request)

        # slicing out length field which is tcp only.
        elif (self._fallback_relay):
            self._fallback_relay_add(send_data[2:], request)

    # receive data from server and call parse method when valid message is recvd, else will close the socket.
    def _recv_handler(self) -> None:
        Log.debug(f'[{self._relay_conn.remote_ip}/{self._protocol.name}] Response handler opened.')

        conn_recv = self._relay_conn.recv
        keepalive_reset = self._keepalive_status.set

        responder_add = self._dns_server.responder.add

        recv_buf = bytearray(2048)
        recv_buffer = memoryview(recv_buf)

        # allocating 4096 bytes of memory as bytearray, then building memory view. access to memory via the byte array
        # will not be needed. 4096 gives space for 8 max length sized udp dns messages (not sure if dot mirrors)
        processing_buffer = memoryview(bytearray(4096))
        b_ct: int = 0

        for _ in RUN_FOREVER:
            try:
                # recv_into | no need to specify the amount to return and mtu covers max len
                # not inplace adding byte count to protect against cases where a public resolves sends a single
                # response over multiple packets and connection is closed in between (this is highly unlikely since
                # most cases it would be via timeout, but I have seen worse.)
                nbytes: int = conn_recv(recv_buffer)
            except OSError:
                break

            # if no data is received/EOF the remote end has closed the connection
            if (not nbytes):
                break

            # resetting fail detection
            self._last_rcvd = fast_time()
            self._send_cnt = 0

            # breaking keepalive timer from blocking, which will effectively reset the timer.
            keepalive_reset()

            # transferring data from single packet buffer to general processing buffer, memoryview()
            processing_buffer[b_ct:b_ct + nbytes] = recv_buffer[:nbytes]

            # incrementing amount of filled bytes in processing buffer accounting for 2 byte len field
            b_ct += nbytes

            # =========================
            # PROCESSING BUFFER LOGIC
            # =========================
            # loop is needed to cover cases where dns responses are split over multiple packets or multiple responses
            # are contained within a single packet.
            for _ in RUN_FOREVER:

                data_len, data = btoia(processing_buffer[:2]), processing_buffer[2:]

                request_len = data_len + 2  # adding 2 byte len field

                # normal case - exactly 1 complete dns response in buffer
                if (b_ct == request_len):

                    # using memoryview(), so need to copy response data or it will be corrupted by subsequent operations
                    # which are running concurrent to the receiving processor.
                    responder_add(bytes(data[:data_len]))

                    b_ct = 0

                    break

                # if expected data length is greater than local buffer, multiple records were returned in a batch so
                # appending leftover bytes after removing the current records' data from buffer.
                elif (b_ct > request_len):
                    extra_bytes = processing_buffer[request_len:b_ct]

                    b_ct -= request_len

                    processing_buffer[:b_ct] = extra_bytes

                # more data is needed for a complete response. NOTE: this scenario is kind of dumb
                # and shouldn't happen unless the server sends length of record and record separately.
                # elif (b_ct < data_len): break
                else: break

        # cleanup after the main loop exits
        self._relay_conn.sock.close()

    def _tls_connect(self, tls_server: str) -> bool:

        Log.informational(f'[{tls_server}/{self._protocol.name}] Opening secure socket.')

        sock: Socket = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)

        dot_sock = self._tls_context.wrap_socket(sock, server_hostname=tls_server)
        try:
            dot_sock.connect((tls_server, PROTO.DNS_TLS))
        except OSError:
            Log.error(f'[{tls_server}/{self._protocol.name}] Failed to connect to {tls_server}.')

        # TODO: will this even catch anything other than programmer errors?
        except Exception as E:
            Log.debug(f'[{tls_server}/{self._protocol.name}] TLS context error while attempting to connect to {E}.')

        else:
            dot_sock.settimeout(RELAY_TIMEOUT)

            self._relay_conn = RELAY_CONN(
                tls_server, dot_sock, dot_sock.send, dot_sock.recv_into, dot_sock.version()
            )

            return True

        return False

    # settings will take effect on next iteration
    def _keepalive_run(self):
        keepalive_interval = self._dns_server.keepalive_interval
        keepalive_timer = self._keepalive_status.wait
        keepalive_continue = self._keepalive_status.clear

        relay_add = self.relay.add

        for _ in RUN_FOREVER:

            # if tls_relay OR keepalive is disabled
            if not (self.is_enabled or keepalive_interval):
                fast_sleep(TEN_SEC)

                continue

            # returns True if reset which means we do not need to send a keep alive. If timeout is reached will return
            # False notifying that a keepalive should be sent
            if keepalive_timer(keepalive_interval):
                keepalive_continue()

            else:
                relay_add(_keepalive(KEEP_ALIVE_DOMAIN, keepalive=True))

                Log.debug(f'[keepalive][{keepalive_interval}] Added to relay queue and cleared')
