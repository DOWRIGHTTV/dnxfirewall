#!/usr/bin/env python3

import os, sys
import time
import json
import ssl
import traceback

from socket import socket, error, AF_INET, SOCK_DGRAM, SOCK_STREAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

# pylint: disable=unused-wildcard-import
from dnx_configure.dnx_constants import *
from dnx_configure.dnx_system_info import System as Sys

LINEBREAK = b'\r\n'


class UDPMessage:
    def __init__(self, SyslogService):
        self.SyslogService = SyslogService

    def send_message(self, udp_socket, message):
        server_list = self.SyslogService.syslog_servers

        # sending to all configured server, soft cap of 2
        for server, server_info in server_list.items():
            server_port = server_info['port']
            try:
                udp_socket.sendto(message, (server, server_port))
            except OSError:
                traceback.print_exc()
            finally:
                udp_socket.close()

    def create_udp_socket(self):
        udp_socket = socket(AF_INET, SOCK_DGRAM)

        return udp_socket

class TCPMessage:
    def __init__(self, SyslogService):
        self.SyslogService = SyslogService

        self._create_tls_conxtext()

        self.tcp_sockets    = [socket(), socket()]
        self.secure_sockets = [socket(), socket()]

    def send_queue(self, tcp_connections):
        for attempt in range(2):
            try:
                message = self.SyslogService.syslog_queue.popleft()
                for socket in self.tcp_sockets:
                    socket.send(message + LINEBREAK)
            except OSError:
                traceback.print_exc()
                self.tls_connect()
            else:
                break

    # Standard TCP Connect logic. will call Socket method to connect to server
    def tcp_connect(self):
        for server, server_info in self.SyslogService.syslog_servers.items():
            server_port = server_info['port']
            if (server_info['tcp']):
                error = self.create_tcp_socket(server, server_port)
                if (not error):
                    continue

                with self.SyslogService.server_lock:
                    if server in self.SyslogService.syslog_servers:
                        self.SyslogService.syslog_servers[server] = {'tcp': False}

                self.SyslogService.syslog_servers[server].update({'tcp': True})

    # Standard TCP socket creation, will return socket object if success or None if not
    def create_tcp_socket(self, server, server_port):
        sock = socket(AF_INET, SOCK_STREAM)
        try:
            sock.connect((server, server_port))
        except OSError:
            traceback.print_exc()
        else:
            return sock

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp.
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method. if tcp fallback is enabled and no tls servers connection the
    # standard connect method gets called to attempt to connect and return normal tcp sockets
    def tls_connect(self):
        now = time.time()
        secure_tcp_connections = []
        for secure_server, server_info in self.SyslogService.syslog_servers.items():
            retry = now - server_info.get('tls_retry', now)
            # if server tls status is good or if retry time has been met, will attempt to create a tls socket
            if (server_info['tls'] or retry >= self.SyslogService.tls_retry):
                # will attempt to connect 3 times before timing out and marking the server as down.
                for attempt in range(3):
                    secure_tcp_socket = self.create_tls_socket(secure_server)
                    if (secure_tcp_socket):
                        secure_tcp_connections.append(secure_tcp_socket)
                        break
                # marking server tls status as down due to 3 failed attempts to connect
                else:
                    self.SyslogService.syslog_servers[secure_server].update({'tls': False, 'tls_retry': now})

                # resetting server tls status back since socket was successfully created
                self.SyslogService.syslog_servers[secure_server].update({'tls': True})

        return secure_tcp_connections

    def create_tls_socket(self, secure_server):
        print(f'Opening Secure socket to {secure_server}: 6514')

        # checking certificate validation status here instead of when creating context to allow for setting update
        # without restarting the service.
        self._update_certificate_verify()

        sock = socket(AF_INET, SOCK_STREAM)
        # NOTE: this should improve sending performance since we expect a dns record to only be a small
        # portion of available bytes in MTU/max bytes(1500). seems to provide no improvement after 1 run.
        # there could be other bottlenecks in play so we can re evaluate later.
        # sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, SYSLOG_TLS_PORT))
        except OSError as E:
            traceback.print_exc()
            print(f'CONNECT: {E}')
        else:
            return secure_socket

    def disconnect_socket(self, tcp_connections):
        for socket in tcp_connections:
            socket.close()

    def _create_tls_conxtext(self):
        self._tls_context = ssl.create_default_context()
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

    def _update_certificate_verify(self):
        if (not self.SyslogService.self_signed_cert):
            self._tls_context.verify_mode = ssl.CERT_REQUIRED
        else:
            self._tls_context.verify_mode = ssl.CERT_OPTIONAL
