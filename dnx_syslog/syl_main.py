#!/usr/bin/env python3

import os, sys
import time
import json
import threading
import asyncio
import traceback

from copy import deepcopy
from collections import deque
from socket import socket, SHUT_RDWR, AF_INET, SOCK_DGRAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_system_info import Interface as Int
from dnx_syslog.syl_format import SyslogFormat
from dnx_syslog.syl_protocols import UDPMessage, TCPMessage


class SyslogService:
    def __init__(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as configs:
            config = json.load(configs)
        lan_int = config['settings']['interface']['inside']

        Interface = Int()
        self.lan_ip = Interface.IP(lan_int)

        self.syslog_queue = deque()
        self.tls_retry = 0
        self.tcp_retry = 0
        self.tcp_fallback = False
        self.tcp_fallback = False

        self.queue_lock = threading.Lock()

    def Start(self):

        self.SyslogUDP = UDPMessage(self)
        self.SyslogTCP = TCPMessage(self)

        threading.Thread(target=self.MessageQueue).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    # Checking the syslog message queue for entries. if entries it will connection to the configured server over the
    # configured protocol/ports, then send the sockets to the protocol classes to actually send the messages
    def MessageQueue(self):
        while True:
            tcp_connections = None
            with self.queue_lock:
                if (not self.syslog_queue):
                    # waiting 1 second before checking queue again for idle perf
                    time.sleep(1)
                    continue

            if (self.syslog_protocol == TCP):
                ## TCP Fallback is wrapped into TLS connect. if it fails it will attempt standard connections
                ## if tcp fallback is enabled. Consider moving the logic to fallback here.
                if (self.tls_enabled):
                    tcp_connections = self.SyslogTCP.TLSConnect()
                else:
                    tcp_connections = self.SyslogTCP.StandardConnect()

                if (tcp_connections):
                    self.SyslogTCP.SendQueue(tcp_connections, self.queue_lock)

            elif (self.syslog_protocol == UDP) or (self.udp_fallback and not tcp_connections):
                udp_socket = self.SyslogUDP.CreateSocket()
                if (udp_socket):
                    self.SyslogUDP.SendQueue(udp_socket, self.queue_lock)

    async def Main(self):

        await asyncio.gather(self.Settings(), self.Reachability(), self.SyslogSocket())

    async def Settings(self):
        while True:
            with open(f'{HOME_DIR}/data/syslog_client.json') as syslog_settings:
                syslog = json.load(syslog_settings)

            syslog_servers = syslog['syslog']['servers']
            self.syslog_enabled = syslog['syslog']['enabled']
            self.syslog_protocol = syslog['syslog']['protocol']
            self.tls_enabled = syslog['syslog']['tls']['enabled']
            self.tls_retry = syslog['syslog']['tls']['retry']
            self.tcp_fallback = syslog['syslog']['tls']['fallback']

            # Make this configurable
            self.udp_fallback = False
            self.tcp_retry = syslog['syslog']['tcp']['retry']
            self.self_signed_cert = True

            self.syslog_list = {}

            ## figure out a better way to deal with this. this can cause a issues during the ms that the dict is empty
            self.syslog_servers = {}

            for server_info in syslog_servers.values():
                server = server_info['ip_address']
                port = server_info['port']
                self.syslog_servers.update({server: {'port': port, 'tls': True, 'tcp': True}})

            print('settings checked.')
            print(self.syslog_servers)

            await asyncio.sleep(SETTINGS_TIMER)

    async def Reachability(self):
        await asyncio.sleep(5)
#        loop = asyncio.get_running_loop()
        while True:
            syslog_servers = deepcopy(self.syslog_servers)
            for server_ip in syslog_servers:
                reach = await asyncio.create_subprocess_shell(
                f'ping -c 1 {server_ip}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)

                await reach.communicate()

#                previous_status = self.syslog_servers[server_ip].get('reach')
                if (reach.returncode == 0):
                    self.syslog_servers[server_ip].update({'reach': True})
                else:
                    self.syslog_servers[server_ip].update({'reach': False})
#                current_status = self.syslog_servers[server_ip].get('reach')
#                if (current_status != previous_status):
#                    message = (f'DNS Server {server_ip} reachability status changed to {current_status}.')
#                    await loop.run_in_executor(None, self.DNSProxy.Log.AddtoQueue, message)

            with open(f'{HOME_DIR}/data/syslog_server_status.json', 'w') as dns_server:
                json.dump(self.syslog_servers, dns_server, indent=4)

            await asyncio.sleep(SHORT_POLL)

    # local socket receiving messages to be sent over syslog from all processes firewall wide. once a message is
    # received it will add it to the queue to be handled by a separate method.
    async def SyslogSocket(self):
        loop = asyncio.get_running_loop()
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.bind((LOCALHOST, SYSLOG_SOCKET))
        sock.setblocking(0)
        while True:
            try:
                data = await loop.sock_recv(sock, 1024)
                if (data):
                    self.syslog_queue.append(data)
            except Exception:
                traceback.print_exc()

class SyslogHandler:
    def __init__(self, module):
        self.module_class = module
        self.lan_ip = module.lan_ip
        self.Format = SyslogFormat()


    async def Settings(self, module):
        self.module = module
        while True:
            with open(f'{HOME_DIR}/data/syslog_client.json') as syslog_settings:
                syslog = json.load(syslog_settings)

            self.module_class.syslog_enabled = syslog['syslog']['enabled']

            await asyncio.sleep(SETTINGS_TIMER)

    def Message(self, msg_type, msg_level, message):
        message = self.Format.Message(self.lan_ip, self.module, msg_type, msg_level, message)
        message = message.encode('utf-8')

        attempt = 0
        while attempt < 3:
            try:
                sock = socket(AF_INET, SOCK_DGRAM)
                sock.bind((LOCALHOST, 0))

                sock.sendto(message, (LOCALHOST, SYSLOG_SOCKET))
            except Exception:
                attempt += 1
                traceback.print_exc()

            finally:
                sock.shutdown(SHUT_RDWR)
                sock.close()

if __name__ == '__main__':
    Syslog = SyslogService()
    Syslog.Start()
