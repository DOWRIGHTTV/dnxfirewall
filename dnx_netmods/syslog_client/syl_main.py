#!/usr/bin/env python3

import os, sys
import time
import threading
import traceback

from collections import deque
from socket import socket, AF_INET, SOCK_DGRAM
from socket import SOL_SOCKET, SO_REUSEADDR

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('.'))
sys.path.insert(0, HOME_DIR)

import dnx_iptools.interface_ops as interface

from dnx_sysmods.configure.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.def_namedtuples import SYSLOG_SERVERS
from dnx_gentools.standard_tools import dnx_queue
from dnx_sysmods.logging.log_main import LogHandler as Log
from dnx_netmods.syslog_client.syl_format import SyslogFormat
from dnx_netmods.syslog_client.syl_protocols import UDPMessage, TCPMessage

LOG_MOD = 'syslog'


class SyslogService:

    syslog_servers = SYSLOG_SERVERS(
        {}, {}
    )

    def __init__(self):
        self.tcp_fallback = False
        self.udp_fallback = False
        self.tls_enabled = False
        self.syslog_protocol = None

        self.syslog_queue = deque()
        self.syslog_servers = {}

    def start(self):

        self.get_interface_settings()

        self.SyslogUDP = UDPMessage(self)
        self.SyslogTCP = TCPMessage(self)

        self.automate_threads()
        self.initialize()

        self._ready_interface_service()

    def initialize(self):
        interface.wait_for_interface(self.lan_int)
        self.lan_ip = interface.wait_for_ip(self.lan_int)
        while True:
            if (self.syslog_servers): break

            fast_sleep(FIVE_SEC)

        threading.Thread(target=self.process_message_queue).start()

    @dnx_queue(Log, name='SyslogClient')
    # Checking the syslog message queue for entries. if entries it will connection to the configured server over the
    # configured protocol/ports, then send the sockets to the protocol classes to actually send the messages
    def process_message_queue(self):
        if (self.syslog_protocol == PROTO.TCP):
            if (self.tls_enabled):
                tcp_connections = self.SyslogTCP.tls_connect()
                # if all tls connections failed and tcp fallback is enabled, will attempt to connect to same servers over standard tcp port
                if (not tcp_connections and self.tcp_fallback):
                    self.SyslogTCP.tcp_connect()
            else:
                self.SyslogTCP.tcp_connect()

            if (tcp_connections):
                self.SyslogTCP.send_queue(tcp_connections)

        if (self.syslog_protocol == PROTO.UDP) or (self.udp_fallback and not tcp_connections):
            udp_socket = self.SyslogUDP.create_udp_socket()
            if (udp_socket):
                self.SyslogUDP.send_queue(udp_socket)

    @looper(NO_DELAY)
    # local socket receiving messages to be sent over syslog from all processes firewall wide. once a message is
    # received it will add it to the queue to be handled by a separate method.
    def _main(self):
        try:
            syslog_message = self.service_sock.recv(2048)
        except OSError:
            traceback.print_exc()
            #NOTE: should report this to front end if service socket error.
        else:
            if (syslog_message):
                self.syslog_queue.append(syslog_message)

    def _ready_interface_service(self):
        while True:
            error = self._create_service_socket()
            if (not error):
                break

            time.sleep(ONE_SEC)

        self._main()

    # using loopback so shouldnt have problems, but just taking precautions.
    def _create_service_socket(self):
        self.service_sock = socket(AF_INET, SOCK_DGRAM)
        self.service_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            self.service_sock.bind((LOCALHOST, SYSLOG_SOCKET))
        except OSError:
            # failed to create socket. interface may be down.
            return True


class SyslogHandler:
    def __init__(self, *, process, module):
        self.process = process
        self.module  = module
        self.Format  = SyslogFormat()

        self._create_socket()

    def start(self):
        threading.Thread(target=self._get_settings, args=('syslog_client.json',)).start()

    def add_to_queue(self, msg_type, msg_level, message):
        message = self.Format.message(self.process.lan_ip, self.module, msg_type, msg_level, message)
        for attempt in range(2):
            try:
                self.handler_sock.send(message)
            except OSError:
                self._create_socket()
            else:
                # NOTE: should log to front end
                break

    @cfg_read_poller
    def _get_settings(self, cfg_file):
        syslog_settings = load_configuration(cfg_file)

        self.process.syslog_enabled = syslog_settings['syslog']['enabled']

    def _create_socket(self):
        self.handler_sock = socket(AF_INET, SOCK_DGRAM)
        self.handler_sock.bind((LOCALHOST, 0))
        self.handler_sock.connect((LOCALHOST, SYSLOG_SOCKET))

if __name__ == '__main__':
    Syslog = SyslogService()
    Syslog.start()
