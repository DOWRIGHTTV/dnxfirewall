#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config
from dnx_gentools.system_info import System

from dnx_iptools.cprotocol_tools import iptoi, itoip
from dnx_iptools.iptables import IPTablesManager

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(_: Form) -> dict[str, Any]:
        ips_profile: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/ids_ips')
        ips_global: ConfigChain = load_configuration('global', cfg_type='security/ids_ips')

        passive_block_ttl = ips_profile['passive_block_ttl']
        ids_mode = ips_profile['ids_mode']

        ddos = {
            'enabled': ips_profile['ddos->enabled'],
            'tcp': ips_profile['ddos->limits->source->tcp'],
            'udp': ips_profile['ddos->limits->source->udp'],
            'icmp': ips_profile['ddos->limits->source->icmp']
        }

        portscan = {
            'enabled': ips_profile['port_scan->enabled'],
            'reject': ips_profile['port_scan->reject']
        }

        ips_enabled = ddos['enabled'] or portscan['enabled']
        nats_configured = ips_global['open_protocols->tcp'] or ips_global['open_protocols->udp']

        ddos_notify = False if ddos['enabled'] or nats_configured else True
        ps_notify   = False if portscan['enabled'] or nats_configured else True

        # converting standard timestamp to a frontend-readable string format
        passively_blocked_hosts = []
        pbh = System.ips_passively_blocked()
        for host, timestamp in pbh:
            passively_blocked_hosts.append((itoip(host), timestamp, System.offset_and_format(timestamp)))

        return {
            'security_profile': 1,
            'profile_name': ips_profile['name'],
            'profile_desc': ips_profile['description'],
            'enabled': ips_enabled, 'length': passive_block_ttl, 'ids_mode': ids_mode,
            'ddos': ddos, 'port_scan': portscan,
            'ddos_notify': ddos_notify, 'ps_notify': ps_notify,
            'ip_whitelist': ips_profile.get_items('whitelist->ip_whitelist'),
            'dns_server_whitelist': ips_profile['whitelist->dns_servers'],
            'passively_blocked_hosts': passively_blocked_hosts
        }

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        # prevents errors while in dev mode.
        if ('security_profile' in form):
            return -1, 'temporarily limited to profile 1.'

        if ('ddos_enabled' in form):

            ddos = config(**{
                'enabled': get_convert_bint(form, 'ddos_enabled')
            })
            if (DATA.INVALID in ddos.values()):
                return 1, INVALID_FORM

            configure_ddos(ddos)

        elif ('ddos_limits' in form):
            ddos_limits = config(**{
                'tcp': get_convert_int(form, 'tcp_limit'),
                'udp': get_convert_int(form, 'udp_limit'),
                'icmp': get_convert_int(form, 'icmp_limit')
            })

            if (DATA.INVALID in ddos_limits.values()):
                return 2, INVALID_FORM

            if not all([limit in range(5, 100) for limit in ddos_limits.values()]):
                return 3, 'protocol limits must be in within range 5-100.'

            configure_ddos_limits(ddos_limits)

        elif ('ps_enabled' in form):
            settings = config(**{
                'enabled': get_convert_bint(form, 'ps_enabled')
            })

            if (DATA.INVALID in settings.values()):
                return 4, INVALID_FORM

            configure_portscan(settings, field='enabled')

        elif ('ps_reject' in form):
            settings = config(**{
                'reject': get_convert_bint(form, 'ps_reject')
            })

            if (DATA.INVALID in settings.values()):
                return 5, INVALID_FORM

            if error := validate_portscan_reject(settings):
                return 6, error.message

            configure_portscan(settings, field='reject')

        elif ('passive_block_length' in form):
            settings = config(**{
                'pb_length': get_convert_int(form, 'passive_block_length')
            })

            if any([x in [DATA.MISSING, DATA.INVALID] for x in settings.values()]):
                return 7, INVALID_FORM

            if error := validate_passive_block_length(settings):
                return 8, error.message

            configure_general_settings(settings, 'pb_length')

        elif ('ids_mode' in form):
            settings = config(**{
                'ids_mode': get_convert_bint(form, 'ids_mode')
            })

            if (DATA.INVALID in settings.values()):
                return 9, INVALID_FORM

            configure_general_settings(settings, 'ids_mode')

        elif ('ips_wl_add' in form):
            whitelist = config(**{
                'ip': form.get('ips_wl_ip', DATA.MISSING),
                'name': form.get('ips_wl_name', DATA.MISSING)
            })

            if (DATA.MISSING in whitelist.values()):
                return 10, INVALID_FORM

            try:
                ip_address(whitelist.ip)
                standard(whitelist.name)
            except ValidationError as ve:
                return 11, ve.message
            else:
                configure_ip_whitelist(whitelist, action=CFG.ADD)

        elif ('ips_wl_remove' in form):
            whitelist = config(**{
                'ip': form.get('ips_wl_ip', DATA.MISSING)
            })
            if (DATA.MISSING in whitelist.values()):
                return 12, INVALID_FORM

            try:
                ip_address(whitelist.ip)
            except ValidationError as ve:
                return 13, ve.message
            else:
                configure_ip_whitelist(whitelist, action=CFG.DEL)

        elif ('dns_svr_wl' in form):
            settings = config(**{
                'action': get_convert_bint(form, 'dns_svr_wl')
            })

            if (DATA.INVALID in settings.values()):
                return 14, INVALID_FORM

            configure_dns_whitelist(settings)

        elif ('ips_pbl_remove' in form):
            host_info = form.get('ips_pbl_remove', DATA.INVALID)
            if (host_info is DATA.INVALID):
                return 15, INVALID_FORM

            try:
                host_ip, timestamp = host_info.split('/')

                ip_address(host_ip)
            except:
                return 16, INVALID_FORM

            if (convert_int(timestamp) is DATA.INVALID):
                return 17, INVALID_FORM

            pbl_remove_notify(iptoi(host_ip), int(timestamp))

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

# ==============
# VALIDATION
# ==============
def validate_portscan_reject(settings: config, /) -> Optional[ValidationError]:
    ips: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/ids_ips')

    current_prevention = ips['port_scan->enabled']
    if (settings.reject and not current_prevention):
        return ValidationError('Prevention must be enabled to configure portscan reject.')

def validate_passive_block_length(settings: config, /) -> Optional[ValidationError]:
    if (settings.pb_length not in [0, 24, 48, 72]):
        return ValidationError(INVALID_FORM)

# ==============
# CONFIGURATION
# ==============
def configure_ddos(ddos: CFG) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        ips_settings['ddos->enabled'] = ddos.enabled

        dnx.write_configuration(ips_settings.expanded_user_data)

def configure_ddos_limits(ddos_limits: config) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        for protocol, limit in ddos_limits.items():
            ips_settings[f'ddos->limits->source->{protocol}'] = limit

        dnx.write_configuration(ips_settings.expanded_user_data)

def configure_portscan(portscan: config, *, field: str) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        if (field == 'enabled'):
            ips_settings['port_scan->enabled'] = portscan.enabled

            if (not portscan.enabled):
                ips_settings['port_scan->reject'] = 0

        elif (field == 'reject'):
            ips_settings['port_scan->reject'] = portscan.reject

        dnx.write_configuration(ips_settings.expanded_user_data)

def configure_general_settings(settings: config, /, field) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        if (field == 'pb_length'):
            ips_settings['passive_block_ttl'] = settings.pb_length

        elif (field == 'ids_mode'):
            ips_settings['ids_mode'] = settings.ids_mode

        dnx.write_configuration(ips_settings.expanded_user_data)

def configure_ip_whitelist(whitelist: config, *, action: CFG) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        if (action is CFG.ADD):
            ips_settings[f'whitelist->ip_whitelist->{whitelist.ip}'] = whitelist.name

        elif (action is CFG.DEL):
            del ips_settings[f'whitelist->ip_whitelist->{whitelist.ip}']

        dnx.write_configuration(ips_settings.expanded_user_data)

def configure_dns_whitelist(settings: config, /) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ids_ips') as dnx:
        ips_settings: ConfigChain = dnx.load_configuration(strict=False)

        ips_settings['whitelist->dns_servers'] = settings.action

        dnx.write_configuration(ips_settings.expanded_user_data)

# error condition should never be met, but just for initial implementation and piece of mind
def pbl_remove_notify(host: int, timestamp: int) -> None:
    error = True
    with IPTablesManager() as iptables:
        iptables.remove_passive_block(host, timestamp)

        error = False

    if error: return

    with ConfigurationManager('global', cfg_type='security/ids_ips') as dnx:
        ips_global_settings: ConfigChain = dnx.load_configuration(strict=False)

        ips_global_settings[f'pbl_remove->{host}'] = timestamp

        dnx.write_configuration(ips_global_settings.expanded_user_data)


