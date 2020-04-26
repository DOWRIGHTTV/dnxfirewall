#!/usr/bin/env python3

import os, sys
import time
import json
import asyncio

from copy import deepcopy

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

# pylint: disable=unused-wildcard-import
from dnx_configure.dnx_constants import *
from dnx_configure.dnx_file_operations import load_configuration, write_configuration


class Automate:
    def __init__(self, SyslogService):
        self.SyslogService = SyslogService

    def get_settings(self):
        while True:
            syslog_settings = load_configuration('syslog_client.json')

            syslog = syslog_settings['syslog']
            syslog_servers = syslog['servers']

            self.SyslogService.syslog_enabled   = syslog['enabled']
            self.SyslogService.syslog_protocol  = syslog['protocol']
            self.SyslogService.tls_enabled      = syslog['tls']['enabled']
            self.SyslogService.self_signed_cert = syslog['tls']['self_signed']
            self.SyslogService.tcp_fallback     = syslog['tcp']['fallback']
            self.SyslogService.udp_fallback     = syslog['udp']['fallback']

            # will convert server dict to a list and compare the IPs in memory with the IPs on disk. if the are different,
            # the new key/value pairs will overwrite the running settings.
            if (list(syslog_servers) != list(self.SyslogService.syslog_servers)):
                svr1_ip = syslog_servers['server1']['ip_address']
                svr1_port = syslog_servers['server1']['port']
                svr2_ip = syslog_servers['server1']['ip_address']
                svr2_port = syslog_servers['server1']['port']
                self.SyslogService.syslog_servers = {
                    svr1_ip: {'reach': True, 'port': svr1_port, 'tls': True, 'tcp': True},
                    svr2_ip: {'reach': True, 'port': svr2_port, 'tls': True, 'tcp': True},
                    }

            time.sleep(FIVE_MIN)

    # def reachability(self):
    #     while True:
    #         syslog_servers = deepcopy(self.SyslogService.syslog_servers)
    #         for server_ip in syslog_servers:
    #             reach = await asyncio.create_subprocess_shell(
    #                 f'ping -c 2 {server_ip}',
    #                 stdout=asyncio.subprocess.PIPE,
    #                 stderr=asyncio.subprocess.PIPE)

    #             await reach.communicate()

    #             previous_status = self.SyslogService.syslog_servers[server_ip].get('reach')
    #             if (reach.returncode == 0):
    #                 self.SyslogService.syslog_servers[server_ip].update({'reach': True})
    #             else:
    #                 self.SyslogService.syslog_servers[server_ip].update({'reach': False})
    #             current_status = self.SyslogService.syslog_servers[server_ip].get('reach')
    #             if (current_status != previous_status):
    #                 message = (f'Syslog Server {server_ip} reachability status changed to {current_status}.')
    #                 self.SyslogService.Log.add_to_queue(message)

    #         write_configuration(self.SyslogService.syslog_servers, 'syslog_server_status.json')

    #         time.sleep(TEN_SEC)
