#!/usr/bin/python3

from typing import Optional

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration

from dnx_routines.configure.system_info import System
from dnx_routines.configure.web_validate import ValidationError, VALID_DOMAIN, get_convert_bint


def load_page(form):
    dns_server = load_configuration('dns_server')
    dns_cache  = load_configuration('dns_server', ext_override='.cache')

    dns_settings = {
        'dns_servers': System.dns_status(), 'dns_records': dns_server.get_items('records'),
        'tls': dns_server['tls->enabled'], 'udp_fallback': dns_server['tls->fallback'],
        'top_domains': dns_cache.get_items('top_domains'),
        'cache': {
            'clear_top_domains': dns_cache['clear->top_domains'],
            'clear_dns_cache': dns_cache['clear->standard']
        }
    }

    return dns_settings

def update_page(form):
    # TODO: i dont like this. fix this. i did a little, but more can be done

    if ('dns_update' in form):
        dns_servers = config(**{
            form.get('dnsname1', DATA.MISSING): form.get('dnsserver1', DATA.MISSING),
            form.get('dnsname2', DATA.MISSING): form.get('dnsserver2', DATA.MISSING)
        })

        # explicit identity check on None to prevent from matching empty fields vs missing for keys.
        if (DATA.MISSING in [*dns_servers.keys(), *dns_servers.values()]):
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
            set_dns_servers(dns_server_info)

    elif ('dns_record_update' in form):
        dns_record = config(**{
            'name': form.get('dns_record_name', DATA.MISSING),
            'ip': form.get('dns_record_ip', DATA.MISSING),
            'action': CFG.ADD
        })
        if (DATA.MISSING in dns_record.values()):
            return INVALID_FORM

        try:
            validate_dns_record(dns_record.name, action=CFG.ADD)
            validate.ip_address(dns_record.ip)
        except ValidationError as ve:
            return ve

        else:
            update_dns_record(dns_record)

    elif ('dns_record_remove' in form):
        dns_record = config(**{
            'name': form.get('dns_record_remove', DATA.MISSING),
            'action': CFG.DEL
        })

        if (DATA.MISSING in dns_record.values()):
            return INVALID_FORM

        error = validate_dns_record(dns_record.name, action=CFG.DEL)
        if (error):
            return error

        update_dns_record(dns_record)

    elif ('dns_protocol_update' in form):
        print(form)
        protocol_settings = config(**{
            'dns_over_tls': get_convert_bint(form, 'dns_over_tls'),
            'udp_fallback': get_convert_bint(form, 'udp_fallback')
        })
        print(protocol_settings)
        if any([opt in [DATA.MISSING, DATA.INVALID] for opt in protocol_settings.values()]):
            return INVALID_FORM

        error = validate_proto_update(protocol_settings)
        if (error):
            return error

        configure_protocol_options(protocol_settings)

    elif ('dns_cache_clear' in form):
        clear_dns_cache = config(**{
            'top_domains': get_convert_bint(form, 'top_domains'),
            'dns_cache': get_convert_bint(form, 'dns_cache')
        })

        # only one is required, so will only be invalid if both are missing.
        if all([x is DATA.MISSING for x in clear_dns_cache.values()]):
            return INVALID_FORM

        set_dns_cache_clear_flag(clear_dns_cache)

    else:
        return INVALID_FORM

# ==============
# VALIDATION
# ==============

def validate_dns_record(query_name: str, *, action: CFG) -> Optional[ValidationError]:

    if (action is CFG.ADD):

        if (not VALID_DOMAIN.match(query_name) and not query_name.isalnum()):
            return ValidationError('Local DNS record is not valid.')

    elif (action is CFG.DEL):
        dns_server = load_configuration('dns_server').searchable_user_data

        if (query_name == 'dnx.rules'):
            return ValidationError('Cannot remove dnxfirewall dns record.')

        if (query_name not in dns_server['records']):
            return ValidationError(INVALID_FORM)

def validate_proto_update(settings: config) -> Optional[ValidationError]:

    print(settings)
    if any([x not in (0, 1) for x in settings.values()]):
        return ValidationError(INVALID_FORM)

    if (settings.udp_fallback and not settings.dns_over_tls):
        return ValidationError('DNS over TLS must be enabled to configure UDP fallback.')

# ==============
# CONFIGURATION
# ==============

def update_dns_record(dns_record: config):
    with ConfigurationManager('dns_server') as dnx:
        dns_records = dnx.load_configuration()

        if (dns_record.action is CFG.ADD):
            dns_records[f'dns_server->records->{dns_record.name}'] = dns_record.ip

        elif (dns_record.action is CFG.DEL):
            del dns_records[f'dns_server->records->{dns_record.name}']

        dnx.write_configuration(dns_records.expanded_user_data)

def configure_protocol_options(settings: config) -> None:
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        if (settings.udp_fallback and not settings.dns_over_tls):
            settings.udp_fallback = 0

        dns_server_settings['tls->enabled'] = settings.dns_over_tls
        dns_server_settings['tls->fallback'] = settings.udp_fallback

        dnx.write_configuration(dns_server_settings.expanded_user_data)

def set_dns_cache_clear_flag(clear_cache):
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        dns_server_settings['dns_server->cache->standard'] = clear_cache.standard
        dns_server_settings['dns_server->cache->top_domains'] = clear_cache.top_domains

        dnx.write_configuration(dns_server_settings.expanded_user_data)
