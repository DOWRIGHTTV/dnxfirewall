#!/usr/bin/env python3

import os, sys
import time
import json
import threading

from copy import deepcopy

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)


from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_logging.log_main import LogHandler as Log
from dnx_iptools.dnx_standard_tools import Initialize
from dnx_configure.dnx_file_operations import cfg_read_poller, load_configuration


class Configuration:
    _service_setup = False

    def __init__(self, name):
        self.Initialize = Initialize(Log, name)

    @classmethod
    def service_setup(cls, SyslogService):
        '''start threads for tasks required by the syslog service. blocking until settings are loaded/initialized.'''
        if (cls._service_setup):
            raise RuntimeError('service setup should only be called once.')

        cls._service_setup = True

        self = cls(SyslogService.__name__)
        self.SyslogService = SyslogService

        self.Initialize.wait_for_threads(count=1)
        threading.Thread(target=self.get_settings).start()

    @cfg_read_poller('syslog_client')
    def get_settings(self, cfg_file):
        syslog = load_configuration(cfg_file)['syslog']

        SyslogService = self.SyslogService

        SyslogService.syslog_enabled   = syslog['enabled']
        SyslogService.syslog_protocol  = syslog['protocol']
        SyslogService.tls_enabled      = syslog['tls']['enabled']
        SyslogService.self_signed_cert = syslog['tls']['self_signed']
        SyslogService.tcp_fallback     = syslog['tcp']['fallback']
        SyslogService.udp_fallback     = syslog['udp']['fallback']

        syslog_servers = syslog['servers']

        # if service is started without servers configured we will return here.
        if not syslog_servers: return

        names = ['primary', 'secondary']
        with SyslogService.server_lock:
            for name, cfg_server, mem_server in zip(names, syslog_servers.values(), SyslogService.syslog_servers):
                if (cfg_server['ip_address'] == mem_server.get('ip')): continue

                getattr(SyslogService.syslog_servers, name).update({
                    'ip': syslog_servers[name]['ip_address'],
                    PROTO.UDP: True, PROTO.TCP: True, PROTO.DNS_TLS: True
                })

    def get_interface_settings(self):
        interface_settings = load_configuration('config.json')
        self.lan_int = interface_settings['settings']['interface']['inside']

class Reachability:
    pass

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
