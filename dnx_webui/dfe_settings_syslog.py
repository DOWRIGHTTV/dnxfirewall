#!/usr/bin/python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_sysmods.configure.web_validate as validate

from dnx_sysmods.configure.def_constants import INVALID_FORM
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError

_SYSLOG_DISABLED = True

def load_page():
    # syslog_server_status = load_configuration('syslog_server_status')

    syslog = load_configuration('syslog_client')

    syslog_servers = syslog['servers']

    syslog_enabled  = syslog['enabled']
    syslog_protocol = syslog['protocol']

    tls_enabled = syslog['tls']['enabled']
    self_signed = syslog['tls']['self_signed']
    tls_retry_time = syslog['tls']['retry'] /60
    tcp_retry_time = syslog['tcp']['retry'] /60
    tcp_fallback = syslog['tcp']['fallback']
    udp_fallback = syslog['udp']['fallback']

    for server, server_info in list(syslog_servers.items()):
        status = server_info.get(server_info['ip_address'], None)
        if (not status):
            tls = 'Waiting'
            dns = 'Waiting'
        else:
            dns = 'UP' if status['dns_up'] else 'Down'
            tls = 'UP' if status['tls_up'] else 'Down'

        if (not tls_enabled):
            tls = 'Disabled'

        syslog_servers[server]['dns_up'] = dns
        syslog_servers[server]['tls_up'] = tls

    syslog_settings = {
        'syslog_servers': syslog_servers, 'enabled': syslog_enabled, 'protocol': syslog_protocol,
        'tls': tls_enabled, 'self_signed': self_signed, 'tcp_fallback': tcp_fallback,
        'udp_fallback': udp_fallback, 'tls_retry': tls_retry_time, 'tcp_retry': tcp_retry_time,
    }

    return syslog_settings

def update_page(form):
    if (_SYSLOG_DISABLED):
        return 'Syslog is currently disabled due to rework.'

    elif ('servers_update' in form):
        syslog_server1 = form.get('syslog_server1', None)
        syslog_server2 = form.get('syslog_server2', None)

        syslog_port1 = form.get('syslog_port1', None)
        syslog_port2 = form.get('syslog_port2', None)

        syslog_servers = {
            'server1': {
                'ip_address': syslog_server1, 'port': syslog_port1
            },
            'server2': {
                'ip_address': syslog_server2, 'port': syslog_port2
            }
        }

        # both servers are not present/ form keys missing
        if (any(x is None for x in [syslog_server1, syslog_port1])
                or any(x is None for x in [syslog_server2, syslog_port2])):
            return INVALID_FORM

        try:
            for server_info in syslog_servers.values():
                if (server_info['ip_address'] or server_info['port']):
                    validate.ip_address(server_info['ip_address'])
                    validate.network_port(server_info['port'])
        except ValidationError as ve:
            return ve
        else:
            configure.set_syslog_servers(syslog_servers)

    elif ('server_remove' in form):
        syslog_server_number = form.get('syslog_server_remove')
        server_num = validate.convert_int(syslog_server_number)
        if (not server_num):
            return INVALID_FORM

        configure.remove_syslog_server(server_num)

    elif ('settings_update' in form):
        enabled_tls_settings = form.getlist('syslog_tls')
        enabled_syslog_settings = form.getlist('syslog_settings')
        fallback_settings = form.getlist('fallback_settings')

        tls_retry = form.get('tls_retry_time', None)
        tcp_retry = form.get('tcp_retry_time', None)
        syslog_settings = {
            'tls': enabled_tls_settings, 'syslog': enabled_syslog_settings,
            'fallback': fallback_settings, 'tls_retry': tls_retry,
            'tcp_retry': tcp_retry
        }

        if (not tls_retry or not tcp_retry):
            return INVALID_FORM

        try:
            validate.syslog_settings(syslog_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.set_syslog_settings(syslog_settings)

        return INVALID_FORM
