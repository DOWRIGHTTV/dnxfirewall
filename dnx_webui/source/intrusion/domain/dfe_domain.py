#!/usr/bin/env python3

from __future__ import annotations

import json

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import DATA
from dnx_gentools.def_exceptions import ConfigurationError
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

STANDARD_CATEGORY_CODES = (0, 1)
TETHERED_CATEGORY_CODES = (2, 3)
VALID_CATEGORY_CODES = (*STANDARD_CATEGORY_CODES, *TETHERED_CATEGORY_CODES)

class WebPage(StandardWebPage):
    '''
    available methods: load, update, handle_ajax
    '''
    @staticmethod
    # TODO: if system category gets disabled that had keyword enabled. it does not disable the keyword search.
    def load(_: Form) -> dict[str, Any]:
        proxy_profile: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

        builtins = proxy_profile.get_items('categories->built-in')

        domain_settings = {
            'security_profile': 1,
            'profile_name': proxy_profile['name'],
            'profile_desc': proxy_profile['description'],
            'built-in': builtins,
            'user_defined': proxy_profile.get_items('categories->custom'),
            'tld': proxy_profile.get_items('tld')
        }

        return domain_settings

    @staticmethod
    def update(form: Form) -> tuple[int, str]:

        # prevents errors while in dev mode.
        if ('security_profile' in form):
            return -1, 'temporarily limited to profile 1.'

        return NO_STANDARD_ERROR

    @staticmethod
    def handle_ajax(form: Form) -> tuple[bool, WebError]:

        ruleset = form.get('type', DATA.MISSING)
        if (ruleset is DATA.MISSING):
            return False, {'error': 1, 'message': INVALID_FORM}

        category = config(**{
            'data': form.get('category', DATA.MISSING),
            'enable_code': get_convert_in_range(form, 'enabled')
        })

        if any([x for x in category.values() if x in [DATA.MISSING, DATA.INVALID]]):
            return False, {'error': 2, 'message': INVALID_FORM}

        if error := validate_domain_categories(category, ruleset=ruleset):
            return False, {'error': 3, 'code': error[0], 'message': error[1].message}

        try:
            configure_domain_categories(category, ruleset=ruleset)
        except ConfigurationError as CE:
            return False, {'error': 4, 'message': CE.message}

        return True, {'error': 0, 'message': ''}

# ==============
# VALIDATION
# ==============
# it is easier and safer to match on the cases we want to see and error on everything else
def validate_domain_categories(category: config, *, ruleset: str) -> Optional[tuple[int, ValidationError]]:

    dns_proxy: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    if (ruleset in ['built-in', 'custom', 'keyword']):
        # keyword and built-in share categories
        r_set = 'built-in' if ruleset == 'keyword' else ruleset

        # category data should be a string form of a tuple. converting to tuple to validate
        category_data = json.loads(category.data)
        try:
            cat_group, cat_name = category_data
        except ValueError:
            return 1, ValidationError(INVALID_FORM)

        # reassigning data in config object to tuple for later use
        category.group = cat_group
        category.name = cat_name

        # general category membership test
        if not (cat := dns_proxy.get_dict(f'categories->{r_set}->{cat_group}').get(cat_name, None)):
            return 2, ValidationError(INVALID_FORM)

        if (ruleset == 'keyword'):
            # category is enabled and the code is in the valid range
            if (cat['enabled'] and category.enable_code in VALID_CATEGORY_CODES):
                return

            # category is tethered and the code is in the tethered range
            if (cat['tethered'] and category.enable_code in TETHERED_CATEGORY_CODES):
                return

        # category enable-code is in the valid range
        elif (ruleset == 'built-in' and category.enable_code in VALID_CATEGORY_CODES):
            return

        # custom category enable-code is in the standard range only
        elif (ruleset == 'custom' and category.enable_code in STANDARD_CATEGORY_CODES):
            return

    elif (ruleset in ['tld']):
        # general category membership test
        if not dns_proxy.get_dict('tld').get(category.name, None):
            return 3, ValidationError(INVALID_FORM)

        # tld enable-code is in the standard range only
        if (category.enable_code in STANDARD_CATEGORY_CODES):
            return

    return 99, ValidationError(INVALID_FORM)

# ==============
# CONFIGURATION
# ==============
# im being very explicit on the if statements because i would rather get the logic more right than pretty.
def configure_domain_categories(category: config, *, ruleset: str):
    with ConfigurationManager('profiles/profile_1', cfg_type='security/dns') as dnx:
        dns_proxy: ConfigChain = dnx.load_configuration()

        # weird naming/ category structures are remnants from older config file formatting.
        if (ruleset in ['built-in', 'keyword']):

            key = ruleset if ruleset != 'built-in' else 'enabled'

            if (category.enable_code in STANDARD_CATEGORY_CODES):
                dns_proxy[f'categories->built-in->{category.group}->{category.name}->{key}'] = category.enable_code

                # ensures keyword searching gets disabled if the general category gets disabled
                # TODO: consider making these independent even unless explicitly tethered
                if (ruleset in ['built-in'] and category.enable_code == 0):
                    dns_proxy[f'categories->built-in->{category.group}->{category.name}->keyword'] = category.enable_code

            # subtracting 2 to normalize tethered code to on/off
            elif (category.enable_code in TETHERED_CATEGORY_CODES):
                dns_proxy[f'categories->built-in->{category.group}->{category.name}->enabled'] = category.enable_code - 2
                dns_proxy[f'categories->built-in->{category.group}->{category.name}->keyword'] = category.enable_code - 2

        if (ruleset == 'custom'):
            dns_proxy[f'categories->custom->{category.name}->enabled'] = category.enable_code

        elif (ruleset in ['tld']):
            dns_proxy[f'tld->{category.name}'] = category.enable_code

        dnx.write_configuration(dns_proxy.expanded_user_data)
