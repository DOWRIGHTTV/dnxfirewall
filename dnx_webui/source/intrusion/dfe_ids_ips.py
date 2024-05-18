#!/usr/bin/env python3

from __future__ import annotations

from functools import partial

from source.web_typing import *

web_module_load_callout(__file__)

from source.web_validate import *

from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, ConfigurationError, load_configuration, config
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
    def load(form: Form) -> WebLoadResponse:
        # this was previously validated by the update method if it is present
        # on a direct page load, the profile will be set to the default (1).
        sec_profile = int(form.get('security_profile', 1))

        ips_profile: ConfigChain = load_configuration(f'profiles/profile_{sec_profile}', cfg_type='security/ids_ips')
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
        for blocked_host in System.ips_passively_blocked():

            passively_blocked_hosts.append((*blocked_host, System.offset_and_format(blocked_host[2])))

        return {
            'security_profile': sec_profile,
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
    def update(form: Form) -> WebUpdateError:

        error, ids_ips_info = form_validator.parse_form(form)
        if (error):
            return 1, error.message

        if (ids_ips_info.btn == 'security_profile_ident'):
            if error := configure_security_profile_ident(ids_ips_info):
                return 11, error.message

        elif (ids_ips_info.btn == 'ddos_enabled'):
            if error := configure_ddos(ids_ips_info):
                return 12, error.message

        elif (ids_ips_info.btn == 'ddos_limits'):
            if error := configure_ddos_limits(ids_ips_info):
                return 13, error.message

        elif (ids_ips_info.btn == 'ps_enabled'):
            if error := configure_portscan(ids_ips_info, field='enabled'):
                return 14, error.message

        elif (ids_ips_info.btn == 'ps_reject'):
            if error := configure_portscan(ids_ips_info, field='reject'):
                return 15, error.message

        elif (ids_ips_info.btn == 'passive_block_length'):
            if error := configure_general_settings(ids_ips_info, field='pb_length'):
                return 16, error.message

        elif (ids_ips_info.btn == 'ids_mode'):
            if error := configure_general_settings(ids_ips_info, field='ids_mode'):
                return 17, error.message

        elif (ids_ips_info.btn == 'ips_wl_add'):
            if error := configure_ip_whitelist(ids_ips_info, action=CFG.ADD):
                return 18, error.message

        elif (ids_ips_info.btn == 'ips_wl_remove'):
            if error := configure_ip_whitelist(ids_ips_info, action=CFG.DEL):
                return 19, error.message

        elif (ids_ips_info.btn == 'dns_svr_wl'):
            if error := configure_dns_whitelist(ids_ips_info):
                return 20, error.message

        elif (ids_ips_info.btn == 'ips_pbl_remove'):
            if error := pbl_remove_notify(ids_ips_info):
                return 21, error.message

        return NO_STANDARD_ERROR


# ==============
# VALIDATION
# ==============
def validate_pbl_remove(host: str, /) -> Optional[ValidationError]:
    try:
        host_ip, profile, timestamp = host.split('/')
    except ValueError:
        return ValidationError(INVALID_FORM)

    try:
        ip_address(host_ip)
    except ValidationError:
        return ValidationError('Unknown IP address specified.')

    if error := check_in_range(profile, (1, 15)):
        return error

    if error := check_digit(timestamp):
        return ValidationError('Invalid timestamp format.')

# =========================
# FORM VALIDATION TEMPLATE
# =========================
form_validator = ValidationConfigForm({
    '__on_enter': {
        # security profile should always be present so defaulting to -1 if missing to trigger error
        ValidationPageContext(
            call=lambda form: check_in_range(form.get('security_profile', -1), (1, 15)),
            append=lambda form, cfg: cfg.update({'security_profile': cfg.security_profile})
        )
    },
    'security_profile': SKIP_VALIDATION,
    'security_profile_ident': {
        'security_profile_name': ValidationFieldInfo(cfg_key='name', format=partial(alpha_maxlen, maxlen=12)),
        'security_profile_desc': ValidationFieldInfo(
            cfg_key='desc', format=partial(alpha_maxlen, maxlen=32, override=[' '])),
    },
    'ddos_enabled': {
        'ddos_enabled': ValidationFieldInfo(cfg_key='enabled', format=check_bint, convert=int)
    },
    'ddos_limits': {
        'tcp_limit': ValidationFieldInfo(
            cfg_key='tcp', format=partial(check_in_range, r=(5, 100)), convert=int),
        'udp_limit': ValidationFieldInfo(
            cfg_key='udp', format=partial(check_in_range, r=(5, 100)), convert=int),
        'icmp_limit': ValidationFieldInfo(
            cfg_key='icmp', format=partial(check_in_range, r=(5, 100)), convert=int)
    },
    'ps_enabled': {
        'ps_enabled': ValidationFieldInfo(cfg_key='enabled', format=check_bint, convert=int)
    },
    'ps_reject': {
        'ps_reject': ValidationFieldInfo(cfg_key='reject', format=check_bint, convert=int)
    },
    'passive_block_length': {
        'passive_block_length': ValidationFieldInfo(
            cfg_key='pb_length', format=partial(check_in_options_int, o=(0, 24, 48, 72)), convert=int)
    },
    'ids_mode': {
        'ids_mode': ValidationFieldInfo(cfg_key='ids_mode', format=check_bint, convert=int)
    },
    'ips_wl_add': {
        'ips_wl_ip': ValidationFieldInfo(cfg_key='ip', format=ip_address),  # idea:: convert to iptoi here?
        'ips_wl_name': ValidationFieldInfo(cfg_key='name', format=partial(alphanum_maxlen, maxlen=16))
    },
    'ips_wl_remove': {
        'ips_wl_remove': ValidationFieldInfo(cfg_key='ip', format=ip_address, convert=iptoi)
    },
    'dns_svr_wl': {
        'dns_svr_wl': ValidationFieldInfo(cfg_key='action', format=check_bint, convert=int)
    },
    'ips_pbl_remove': {
        'ips_pbl_remove': ValidationFieldInfo(cfg_key='host_info', validation=validate_pbl_remove),
        # idea:: see if there is a better "lazy" way to do this without needed to make a function.
        # note: converting post validation to separate the fields compressed into a single int.
        '_on_exit': ValidationFieldContext(
            call=lambda cfg: exec("h = cfg.host_info.split('/'), cfg.update({'host': iptoi(h[0]), 'profile_idx': int(h[1]), 'timestamp': int(h[2])})"))
    }
})

# ==============
# CONFIGURATION
# ==============
def configure_security_profile_ident(sp_ident: config) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{sp_ident.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        security_profile_settings: ConfigChain = ids_ips.load_configuration()

        security_profile_settings['name'] = sp_ident.name
        security_profile_settings['description'] = sp_ident.desc

        ids_ips.write_configuration(security_profile_settings.expanded_user_data)

    return ids_ips.error

def configure_ddos(ddos: CFG) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{ddos.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        ips_settings['ddos->enabled'] = ddos.enabled

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

def configure_ddos_limits(ddos_limits: config) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{ddos_limits.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        for protocol, limit in ddos_limits.items():
            ips_settings[f'ddos->limits->source->{protocol}'] = limit

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

def configure_portscan(portscan: config, *, field: str) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{portscan.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        if (field == 'enabled'):
            ips_settings['port_scan->enabled'] = portscan.enabled

            if (not portscan.enabled):
                ips_settings['port_scan->reject'] = 0

        elif (field == 'reject'):
            ips_settings['port_scan->reject'] = portscan.reject

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

def configure_general_settings(settings: config, *, field: str) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{settings.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        if (field == 'pb_length'):
            ips_settings['passive_block_ttl'] = settings.pb_length

        elif (field == 'ids_mode'):
            ips_settings['ids_mode'] = settings.ids_mode

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

def configure_ip_whitelist(whitelist: config, *, action: CFG) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{whitelist.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        if (action is CFG.ADD):
            ips_settings[f'whitelist->ip_whitelist->{whitelist.ip}'] = whitelist.name

        elif (action is CFG.DEL):
            del ips_settings[f'whitelist->ip_whitelist->{whitelist.ip}']

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

def configure_dns_whitelist(settings: config, /) -> Optional[ConfigurationError]:
    ids_ips = ConfigurationManager(
        f'profiles/profile_{settings.profile}', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        ips_settings['whitelist->dns_servers'] = settings.action

        ids_ips.write_configuration(ips_settings.expanded_user_data)

    return ids_ips.error

# error condition should never be met, but just for initial implementation and piece of mind
def pbl_remove_notify(pbl: config) -> Optional[ConfigurationError]:
    iptables = IPTablesManager(err_as_value=True)
    with iptables:
        iptables.remove_passive_block(pbl.host, pbl.profile_idx, pbl.timestamp)

    if (iptables.error):
        return iptables.error

    ids_ips = ConfigurationManager('global', cfg_type='security/ids_ips', err_as_value=True)
    with ids_ips:
        ips_global_settings: ConfigChain = ids_ips.load_configuration(strict=False)

        ips_global_settings[f'pbl_remove->{pbl.host}'] = [pbl.profile_idx, pbl.timestamp]

        ids_ips.write_configuration(ips_global_settings.expanded_user_data)

    return ids_ips.error
