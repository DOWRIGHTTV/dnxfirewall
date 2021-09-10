#!/usr/bin/python3

import sys, os
import time

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_sysmods.configure.web_validate as validate

from dnx_sysmods.configure.def_constants import INVALID_FORM, CFG, DATA
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError
from dnx_sysmods.configure.system_info import Services

def load_page(form):
    dns_server = load_configuration('dns_server')
    dns_cache  = load_configuration('dns_cache')
    servers_status = load_configuration('dns_server_status')

    dns_servers = dns_server['resolvers']
    dns_records = dns_server['records']

    top_domains_clear_pending = dns_server['cache']['top_domains']
    cache_clear_pending = dns_server['cache']['standard']

    tls_settings = dns_server['tls']
    tls_enabled  = tls_settings['enabled']
    udp_fallback = tls_settings['fallback']

    for server, server_info in list(dns_servers.items()):
        status = servers_status.get(server_info['ip_address'], None)
        if (not status):
            tls = 'Waiting'
            dns = 'Waiting'
        else:
            dns = 'UP' if status['dns_up'] else 'Down'
            tls = 'UP' if status['tls_up'] else 'Down'

        if (not tls_enabled):
            tls = 'Disabled'

        dns_servers[server]['dns_up'] = dns
        dns_servers[server]['tls_up'] = tls

    dns_settings = {
        'dns_servers': dns_servers, 'dns_records': dns_records,
        'tls': tls_enabled, 'udp_fallback': udp_fallback, 'top_domains': dns_cache,
        'cache': {
            'clear_top_domains': top_domains_clear_pending,
            'clear_dns_cache': cache_clear_pending}
        }

    return dns_settings

def update_page(form):
    # TODO: i dont like this. fix this. i did alittle, but more can be done

    if ('dns_update' in form):
        dns_servers = {
            form.get('dnsname1', DATA.INVALID): form.get('dnsserver1', DATA.INVALID),
            form.get('dnsname2', DATA.INVALID): form.get('dnsserver2', DATA.INVALID)
        }

        # explicit identity check on None to prevent from matching empty fields vs missing for keys.
        if (DATA.INVALID in [*dns_servers.keys(), *dns_servers.values()]):
            return INVALID_FORM

        try:
            dns_server_info = {}
            for i, (server_name, server_ip) in enumerate(dns_servers.items(), 1):
                if (server_ip != ''):
                    validate.standard(server_name)
                    validate.ip_address(server_ip)

                dns_server_info[form.get(f'dnsname{i}')] = form.get(f'dnsserver{i}')
        except ValidationError as ve:
            return ve

        else:
            configure.set_dns_servers(dns_server_info)

    elif ('dns_record_update' in form):
        dns_record_name = form.get('dns_record_name', None)
        dns_record_ip = form.get('dns_record_ip', None)
        if (not dns_record_name or not dns_record_ip):
            return INVALID_FORM

        try:
            validate.dns_record_add(dns_record_name)
            validate.ip_address(dns_record_ip)
        except ValidationError as ve:
            return ve

        else:
            configure.update_dns_record(dns_record_name, CFG.ADD, dns_record_ip)

    elif ('dns_record_remove' in form):
        dns_record_name = form.get('dns_record_remove', None)
        if (not dns_record_name):
            return INVALID_FORM

        try:
            validate.dns_record_remove(dns_record_name)
        except ValidationError as ve:
            return ve

        else:
            configure.update_dns_record(dns_record_name, CFG.DEL)

    elif ('dns_protocol_update' in form):
        dns_tls_settings = {
            'enabled': form.getlist('dns-protocol-settings')
        }

        try:
            validate.dns_over_tls(dns_tls_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.set_dns_over_tls(dns_tls_settings)

    elif ('dns_cache_clear' in form):
        clear_dns_cache = {
            'top_domains': form.get('clear_top_domains', DATA.INVALID),
            'dns_cache': form.get('clear_dns_cache', DATA.INVALID)
        }

        # only one is required, so will only be invalid if both are missing.
        if all([x is DATA.INVALID for x in clear_dns_cache.values()]):
            return INVALID_FORM

        configure.set_dns_cache_clear_flag(clear_dns_cache)

    else:
        return INVALID_FORM
