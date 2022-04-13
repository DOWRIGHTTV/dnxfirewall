#!/usr/bin/python3

from __future__ import annotations

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration

from dnx_routines.configure.system_info import System

from source.web_typing import *
from source.web_validate import ValidationError, VALID_DOMAIN, get_convert_bint, standard, ip_address


def load_page(_: Form) -> dict[str, Any]:
    server_settings = load_configuration('dns_server')
    server_cache    = load_configuration('dns_server', ext='cache')

    return {
        'dns_servers': System.dns_status(), 'dns_records': server_settings.get_items('records'),
        'tls': server_settings['tls->enabled'], 'udp_fallback': server_settings['tls->fallback'],
        'top_domains': server_cache.get_items('top_domains'),
        'cache': {
            'clear_top_domains': server_cache['clear->top_domains'],
            'clear_dns_cache': server_cache['clear->standard']
        }
    }

def update_page(form: Form) -> str:
    # TODO: i dont like this. fix this. i did a little, but more can be done
    if ('dns_update' in form):

        dns_servers = config(**{
            'primary': [form.get('dnsname1', DATA.MISSING), form.get('dnsserver1', DATA.MISSING)],
            'secondary': [form.get('dnsname2', DATA.MISSING), form.get('dnsserver2', DATA.MISSING)]
        })

        # explicit identity check on None to prevent from matching empty fields vs missing for keys.
        if any([DATA.MISSING in x for x in dns_servers.values()]):
            return INVALID_FORM

        error = validate_dns_servers(dns_servers)
        if (error):
            return error.message

        else:
            set_dns_servers(dns_servers)

    elif ('dns_record_update' in form):
        dns_record = config(**{
            'name': form.get('dns_record_name', DATA.MISSING),
            'ip': form.get('dns_record_ip', DATA.MISSING),
            'action': CFG.ADD
        })
        if (DATA.MISSING in dns_record.values()):
            return INVALID_FORM

        try:
            ip_address(dns_record.ip)
            validate_dns_record(dns_record.name, action=CFG.ADD)
        except ValidationError as ve:
            return ve.message

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
            return error.message

        update_dns_record(dns_record)

    elif ('dns_over_tls' in form):
        protocol_settings = config(**{
            'enabled': get_convert_bint(form, 'enabled')
        })

        if (protocol_settings.enabled is DATA.INVALID):
            return INVALID_FORM

        configure_protocol_options(protocol_settings, field='dot')

    elif ('udp_fallback' in form):
        protocol_settings = config(**{
            'fallback': get_convert_bint(form, 'fallback')
        })

        if (protocol_settings.fallback is DATA.INVALID):
            return INVALID_FORM

        error = validate_fallback_settings(protocol_settings)
        if (error):
            return error.message

        configure_protocol_options(protocol_settings, field='fallback')

    elif ('dns_cache_clear' in form):
        clear_dns_cache = config(**{
            'top_domains': get_convert_bint(form, 'top_domains'),
            'dns_cache': get_convert_bint(form, 'dns_cache')
        })

        # only one is required, so it will only be invalid if both are missing.
        if all([x is DATA.MISSING for x in clear_dns_cache.values()]):
            return INVALID_FORM

        set_dns_cache_clear_flag(clear_dns_cache)

    else:
        return INVALID_FORM

# ==============
# VALIDATION
# ==============
def validate_dns_servers(server_info: config) -> Optional[ValidationError]:

    for server in server_info.values():
        try:
            standard(server[0])
            ip_address(server[1])
        except ValidationError as ve:
            return ve

    if server_info.primary[1] == server_info.secondary[1]:
        return ValidationError('Server addresses must be unique.')

def validate_dns_record(query_name: str, *, action: CFG) -> Optional[ValidationError]:

    if (action is CFG.ADD):

        if (not VALID_DOMAIN.match(query_name) and not query_name.isalnum()):
            return ValidationError('Local DNS record is not valid.')

    elif (action is CFG.DEL):
        dns_server = load_configuration('dns_server').searchable_user_data

        if (query_name == 'dnx.firewall'):
            return ValidationError('Cannot remove dnxfirewall dns record.')

        if (query_name not in dns_server['records']):
            return ValidationError(INVALID_FORM)

def validate_fallback_settings(settings: config) -> Optional[ValidationError]:
    with ConfigurationManager('dns_server') as dnx:
        server_settings: ConfigChain = dnx.load_configuration()

        dot_enabled = server_settings['tls->enabled']

    if (settings.fallback and not dot_enabled):
        return ValidationError('DNS over TLS must be enabled to configure UDP fallback.')

# ==============
# CONFIGURATION
# ==============
def set_dns_servers(server_info: config) -> None:
    with ConfigurationManager('dns_server') as dnx:
        server_settings: ConfigChain = dnx.load_configuration()

        server_settings['resolvers->primary->name'] = server_info.primary[0]
        server_settings['resolvers->primary->ip_address'] = server_info.primary[1]

        server_settings['resolvers->secondary->name'] = server_info.secondary[0]
        server_settings['resolvers->secondary->ip_address'] = server_info.secondary[1]

        dnx.write_configuration(server_settings.expanded_user_data)

def update_dns_record(dns_record: config):
    with ConfigurationManager('dns_server') as dnx:
        dns_records: ConfigChain = dnx.load_configuration()

        if (dns_record.action is CFG.ADD):
            dns_records[f'dns_server->records->{dns_record.name}'] = dns_record.ip

        elif (dns_record.action is CFG.DEL):
            del dns_records[f'dns_server->records->{dns_record.name}']

        dnx.write_configuration(dns_records.expanded_user_data)

def configure_protocol_options(settings: config, *, field: str) -> None:
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings: ConfigChain = dnx.load_configuration()

        if (field == 'dot'):
            dns_server_settings['tls->enabled'] = settings.enabled

            if (not settings.enabled):
                dns_server_settings['tls->fallback'] = 0

        elif (field == 'fallback'):
            dns_server_settings['tls->fallback'] = settings.fallback

        dnx.write_configuration(dns_server_settings.expanded_user_data)

def set_dns_cache_clear_flag(clear_cache):
    with ConfigurationManager('dns_server', ext='cache') as dnx:
        dns_server_settings: ConfigChain = dnx.load_configuration()

        dns_server_settings['clear->standard'] = clear_cache.standard
        dns_server_settings['clear->top_domains'] = clear_cache.top_domains

        dnx.write_configuration(dns_server_settings.expanded_user_data)
