#!/usr/bin/python3

from __future__ import annotations

from flask import request

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_constants import fast_time
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration

from dnx_gentools.system_info import System

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

# TODO: this needs to be reworked to be handled on a per profile basis.
DISABLED = True

VALID_RULESETS = ['whitelist', 'blacklist']


class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        list_type = str(request.url_rule).split('/')[-1]

        xlist: ConfigChain = load_configuration(list_type, cfg_type='global')

        for info in xlist.get_values('time_based'):
            st_offset = System.calculate_time_offset(info['time'])

            info['time'] = System.format_date_time(st_offset)

        xlist_settings = {
            'time_based': xlist['time_based'],
            'pre_proxy': xlist['pre_proxy']
        }

        return xlist_settings

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        list_type = str(request.url_rule).split('/')[-1]

        if (DISABLED):
            return 98, 'overrides disabled for rework.'

        if ('xl_add' in form):
            xlist_settings = config(**{
                'domain': form.get('domain', DATA.MISSING),
                'timer': get_convert_int(form, 'rule_length'),
                'ruleset': list_type
            })

            if any([x in [DATA.MISSING, DATA.INVALID] for x in xlist_settings.values()]):
                return 1, INVALID_FORM

            if error := validate_time_based(xlist_settings):
                return 2, error.message

            configure_proxy_domain(xlist_settings, action=CFG.ADD)

        elif ('xl_remove' in form):
            xlist_settings = config(**{
                'domain': form.get('bl_remove', DATA.MISSING),
                'ruleset': list_type
            })

            if (DATA.MISSING in xlist_settings.values()):
                return 3, INVALID_FORM

            configure_proxy_domain(xlist_settings, action=CFG.DEL)

        elif ('exc_add' in form):
            exception_settings = config(**{
                'domain': form.get('domain', DATA.MISSING),
                'reason': form.get('reason', DATA.MISSING),
                'ruleset': list_type
            })

            if (DATA.MISSING in exception_settings.values()):
                return 4, INVALID_FORM

            if error := validate_pre_proxy_exc(exception_settings):
                return 6, error.message

            configure_pre_proxy_exc(exception_settings, action=CFG.ADD)

        elif ('exc_remove' in form):
            exception_settings = config(**{
                'domain': form.get('exc_remove', DATA.MISSING),
                'ruleset': list_type
            })

            # doing the iter for consistency
            if (DATA.MISSING in exception_settings.values()):
                return 6, INVALID_FORM

            configure_pre_proxy_exc(exception_settings, action=CFG.DEL)

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

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

# ==============
# CONFIGURATION
# ==============
# adds a time-based rule to whitelist/blacklist
def configure_proxy_domain(settings: config, *, action: CFG):
    input_time = fast_time()

    with ConfigurationManager(settings.ruleset) as dns_proxy:
        if (action is CFG.ADD):

            dns_proxy.config_data[f'time_based->{settings.domain}->time'] = input_time
            dns_proxy.config_data[f'time_based->{settings.domain}->rule_length'] = settings.timer
            dns_proxy.config_data[f'time_based->{settings.domain}->expire'] = input_time + settings.timer * 60

        elif (action is CFG.DEL):
            del dns_proxy.config_data[f'time_based->{settings.domain}']

def configure_pre_proxy_exc(exc: config, *, action: CFG):
    with ConfigurationManager(exc.ruleset) as dnx:
        exceptions_list: ConfigChain = dnx.load_configuration()

        if (action is CFG.ADD):

            exceptions_list[f'pre_proxy->{exc.domain}'] = exc.reason

        elif (action is CFG.DEL):

            del exceptions_list[exc.domain]

        dnx.write_configuration(exceptions_list.expanded_user_data)
