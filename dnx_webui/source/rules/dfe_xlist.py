#!/usr/bin/python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import INVALID_FORM, fast_time
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration

from dnx_routines.configure.system_info import System
from source.web_validate import ValidationError, VALID_DOMAIN, get_convert_int, standard, ip_address

VALID_RULESETS = ['whitelist', 'blacklist']

def load_page(form):
    blacklist = load_configuration('blacklist')

    for info in blacklist['time_based'].values():
        st_offset = System.calculate_time_offset(info['time'])

        info['time'] = System.format_date_time(st_offset)

    blacklist_settings = {
        'time_based': blacklist['time_based'],
        'pre_proxy': blacklist['pre_proxy']
    }

    return blacklist_settings

def update_page(form) -> Union[str, ValidationError]:
    page_name = form.get('page_name', DATA.MISSING)
    if (page_name is DATA.MISSING):
        return INVALID_FORM

    if ('xl_add' in form):
        xlist_settings = config(**{
            'domain': form.get('domain', DATA.MISSING),
            'timer': get_convert_int(form, 'rule_length'),
            'ruleset': page_name
        })

        if any([x in [DATA.MISSING, DATA.INVALID] for x in xlist_settings.values()]):
            return INVALID_FORM

        error = validate_time_based(xlist_settings)
        if (error):
            return error.message

        configure_proxy_domain(xlist_settings, action=CFG.ADD)

    elif ('xl_remove' in form):
        xlist_settings = config(**{
            'domain': form.get('bl_remove', DATA.MISSING),
            'ruleset': page_name
        })

        if (DATA.MISSING in xlist_settings.values()):
            return INVALID_FORM

        configure_proxy_domain(xlist_settings, action=CFG.DEL)

    elif ('exc_add' in form):
        exception_settings = config(**{
            'domain': form.get('domain', DATA.MISSING),
            'reason': form.get('reason', DATA.MISSING),
            'ruleset': page_name
        })

        if (DATA.MISSING in exception_settings.values()):
            return INVALID_FORM

        error = validate_pre_proxy_exc(exception_settings)
        if (error):
            return error.message

        configure_pre_proxy_exc(exception_settings, action=CFG.ADD)

    elif ('exc_remove' in form):
        exception_settings = config(**{
            'domain': form.get('exc_remove', DATA.MISSING),
            'ruleset': page_name
        })

        # doing the iter for consistency
        if (DATA.MISSING in exception_settings.values()):
            return INVALID_FORM

        configure_pre_proxy_exc(exception_settings, action=CFG.DEL)

    else:
        return INVALID_FORM

    # =====================
    # WHITELIST ONLY FORMS
    # =====================

    # TODO: this should not restrict ips to only "local_net" now that we have multiple interfaces.
    # we should have the user select which interface it will be active on so we can properly validate the
    # ip address falls within that subnet.

    if ('ip_wl_add' in form):
        whitelist_settings = config(**{
            'ip': form.get('ip_wl_ip', DATA.MISSING),
            'user':form.get('ip_wl_user', DATA.MISSING),
            'type': form.get('ip_wl_type', DATA.MISSING)
        })

        if (DATA.MISSING in whitelist_settings.values()):
            return INVALID_FORM

        error = validate_ip_whitelist(whitelist_settings)
        if (error):
            return error.message

        configure_ip_whitelist(whitelist_settings, action=CFG.ADD)

    elif ('ip_wl_remove' in form):
        whitelist_ip = form.get('ip_wl_ip', DATA.INVALID)

        if (whitelist_ip is DATA.INVALID):
            return INVALID_FORM

        try:
            ip_address(whitelist_ip)
        except ValidationError as ve:
            return ve

        configure_ip_whitelist(whitelist_ip, action=CFG.DEL)

    else:
        return INVALID_FORM


# ==============
# VALIDATION
# ==============

def validate_time_based(settings: config) -> Optional[ValidationError]:
    if (settings.ruleset not in VALID_RULESETS):
        return ValidationError(INVALID_FORM)

    if (not VALID_DOMAIN.match(settings.domain)):
        return ValidationError('Domain name is not valid.')

    if (not 1 <= settings.timer <= 1440):
        return ValidationError('Timer must be between 1 and 1440 (24 hours).')

def validate_pre_proxy_exc(settings: config) -> Optional[ValidationError]:
    if (not VALID_DOMAIN.match(settings.domain)):
        return ValidationError('Domain name is not valid.')

    try:
        standard(settings.reason)
    except ValidationError as ve:
        return ve

def validate_ip_whitelist(settings: config) -> Optional[ValidationError]:
    try:
        ip_address(settings.ip)
        standard(settings.user)
    except ValidationError as ve:
        return ve

    if (settings.type != 'ip'):
        return ValidationError(INVALID_FORM)

# ==============
# CONFIGURATION
# ==============

# adds a time based rule to whitelist/blacklist
def configure_proxy_domain(settings: config, *, action: CFG):
    input_time: int = int(fast_time())

    with ConfigurationManager(settings.ruleset) as dnx:
        domain_list = dnx.load_configuration()

        if (action is CFG.ADD):

            domain_list[f'time_based->{settings.domain}->time'] = input_time
            domain_list[f'time_based->{settings.domain}->rule_length'] = settings.timer
            domain_list[f'time_based->{settings.domain}->expire'] = input_time + settings.timer * 60

        elif (action is CFG.DEL):
            del domain_list[f'time_based->{settings.domain}']

        dnx.write_configuration(domain_list.expanded_user_data)

def configure_pre_proxy_exc(exc: config, *, action: CFG):
    with ConfigurationManager(exc.ruleset) as dnx:
        exceptions_list = dnx.load_configuration()

        if (action is CFG.ADD):

            exceptions_list[f'pre_proxy->{exc.domain}'] = exc.reason

        elif (action is CFG.DEL):

            del exceptions_list[exc.domain]

        dnx.write_configuration(exceptions_list.expanded_user_data)

def configure_ip_whitelist(ip_wl: config, /, *, action: CFG):
    with ConfigurationManager('whitelist') as dnx:
        whitelist = dnx.load_configuration()

        if (action is CFG.ADD):
            whitelist[f'ip_bypass->{ip_wl.ip}->user'] = ip_wl.user
            whitelist[f'ip_bypass->{ip_wl.ip}->type'] = ip_wl.type

        elif (action is CFG.DEL):
            del whitelist[f'ip_bypass->{ip_wl.ip}']

        dnx.write_configuration(whitelist.expanded_user_data)
