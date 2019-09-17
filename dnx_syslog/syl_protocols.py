#!/usr/bin/env python3

import os, sys
import time
import json
import ssl
import traceback

from socket import socket, error, AF_INET, SOCK_DGRAM, SOCK_STREAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_system_info import System as Sys

class UDPMessage:
    def __init__(self, SyslogService):
        self.SyslogService = SyslogService

    def SendQueue(self, udp_socket, queue_lock):
        server_list = self.SyslogService.server_list
        with queue_lock:
            while self.SyslogService.syslog_queue:
                try:
                    message = self.SyslogService.syslog_queue.popleft()
                    # sending to all configured server, soft cap of 2
                    for server, server_info in server_list.items():
                        server_port = server_info['port']
                        udp_socket.sendto(message, (server, server_port))

                except error:
                    traceback.print_exc()
                finally:
                    udp_socket.close()

    def CreateSocket(self):
        udp_socket = socket(AF_INET, SOCK_DGRAM)
        udp_socket.bind((self.SyslogService.lan_ip, 0))

        return udp_socket

class TCPMessage:
    def __init__(self, SyslogService):
        self.SyslogService = SyslogService

    def SendQueue(self, tcp_connections, queue_lock):
        line_break = b'\r\n'
        with queue_lock:
            while self.SyslogService.syslog_queue:
                try:
                    message = self.SyslogService.syslog_queue.popleft()
                    for socket in tcp_connections:
                        socket.send(message + line_break)

                except error:
                    traceback.print_exc()
                finally:
                    self.Disconnect(tcp_connections)

    # Standard TCP Connect logic. will call Socket method to connect to server
    def StandardConnect(self):
        server_list = self.SyslogService.syslog_servers
        tcp_retry = self.SyslogService.tcp_retry

        now = time.time()
        tcp_connections = []
        for server, server_info in server_list.items():
            server_port = server_info['port']
            retry = now - server_info.get('tcp_retry', now)
            if (server_info['tcp'] or retry >= tcp_retry):
                for attempt in range(1,4):
                    tcp_socket = self.StandardSocket(server, server_port)
                    if (socket):
                        tcp_connections.append(tcp_socket)
                        break

                if (attempt < 3):
                    server_list[server].update({'tcp': True})
                else:
                    server_list[server].update({'tcp': False, 'tcp_retry': now})

        return tcp_connections

    # Standard TCP socket creation, will return socket object if success or None if not
    def StandardSocket(self, server, server_port):
        lan_ip = self.SyslogService.lan_ip
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((lan_ip, 0))
            sock.settimeout(3)
            sock.connect((server, server_port))

        except Exception:
            sock = None
            traceback.print_exc()

        return sock

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp.
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method. if tcp fallback is enabled and no tls servers connection the
    # standard connect method gets called to attempt to connect and return normal tcp sockets
    def TLSConnect(self):
        server_list = self.SyslogService.syslog_servers
        tcp_fallback = self.SyslogService.tcp_fallback
        tls_retry = self.SyslogService.tls_retry

        secure_tcp_connections = []
        for secure_server, server_info in server_list.items():
            now = time.time()
            retry = now - server_info.get('tls_retry', now)
            # if server tls status is good or if retry time has been met, will attempt to create a tls socket
            if (server_info['tls'] or retry >= tls_retry):
                # will attempt to connect 3 times before timing out and marking the server as down.
                for attempt in range(1,4):
                    secure_tcp_socket = self.TLSSocket(secure_server)
                    if (secure_tcp_socket):
                        secure_tcp_connections.append(secure_tcp_socket)
                        break

                # resetting server tls status back since socket was successfully created
                if (attempt < 3):
                    server_list[secure_server].update({'tls': True})
                # marking server tls status as down due to 3 failed attempts to connect
                else:
                    server_list[secure_server].update({'tls': False, 'tls_retry': time.time()})

        # if all tls connections failed and tcp fallback is enabled, will attempt to connect to same servers over standard tcp port
        if (not secure_tcp_connections and tcp_fallback):
            secure_tcp_connections = self.StandardConnect()

        return secure_tcp_connections


    def TLSSocket(self, secure_server):
        lan_ip = self.SyslogService.lan_ip
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((lan_ip, 0))

            context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            if (not self.SyslogService.self_signed_cert):
                context.verify_mode = ssl.CERT_REQUIRED

            # Wrap socket and Connect. If exception will add to attempt value. If successful
            # connect will break while loop and allow queue handler to send syslog message

            print(f'Opening Secure socket to {secure_server}: 6514')
            secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, SYSLOG_TLS_PORT))
        except Exception as E:
            secure_socket = None
            traceback.print_exc()
            print(f'CONNECT: {E}')

        return secure_socket

    def Disconnect(self, tcp_connections):
        for socket in tcp_connections:
            socket.close()
