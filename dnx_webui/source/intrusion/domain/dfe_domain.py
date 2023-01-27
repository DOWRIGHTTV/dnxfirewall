#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import DATA
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

        domain_settings = {
            'security_profile': 1,
            'profile_name': proxy_profile['name'],
            'profile_desc': proxy_profile['description'],
            'built-in': proxy_profile.get_items('categories->built-in'),
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
            'name': form.get('category', DATA.MISSING),
            'enable_code': get_convert_in_range(form, 'enabled')
        })

        if any([x for x in category.values() if x in [DATA.MISSING, DATA.INVALID]]):
            return False, {'error': 2, 'message': INVALID_FORM}

        if error := validate_domain_categories(category, ruleset=ruleset):
            return False, {'error': 3, 'message': error.message}

        configure_domain_categories(category, ruleset=ruleset)

        return True, {'error': 0, 'message': ''}

# ==============
# VALIDATION
# ==============
def validate_domain_categories(category: config, *, ruleset: str) -> Optional[ValidationError]:

    dns_proxy: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    if (ruleset in ['built-in', 'custom', 'keyword']):
        # keyword and built-in share categories
        r_set = 'built-in' if ruleset == 'keyword' else ruleset

        if not (cat := dns_proxy.get_dict(f'categories->{r_set}').get(category.name, None)):
            return ValidationError(INVALID_FORM)

        if (ruleset == 'keyword'):
            # ensuring the category is enabled when settings keywords unless they are tethered
            if not cat['enabled'] and category.enable_code not in TETHERED_CATEGORY_CODES:
                return ValidationError(INVALID_FORM)

            # ensuring the enable-code is within the valid range(0, 5)
            elif (cat['enabled'] and category.enable_code not in VALID_CATEGORY_CODES):
                return ValidationError(INVALID_FORM)

        # ensuring general categories enable-code is valid
        elif (ruleset == 'built-in' and category.enable_code not in VALID_CATEGORY_CODES):
            return ValidationError(INVALID_FORM)

        # ensuring custom categories enable-code are within the standard range
        elif (ruleset == 'custom' and category.enable_code not in STANDARD_CATEGORY_CODES):
            return ValidationError(INVALID_FORM)

    elif (ruleset in ['tld']):
        # ensuring the tld enable-code is within the standard range
        if (category.enable_code not in STANDARD_CATEGORY_CODES):
            return ValidationError(INVALID_FORM)

        if not dns_proxy.get_dict('tld').get(category.name, None):
            return ValidationError(INVALID_FORM)

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
                dns_proxy[f'categories->built-in->{category.name}->{key}'] = category.enabled

            # subtracting 2 to normalize tethered code to on/off
            elif (category.enable_code in TETHERED_CATEGORY_CODES):
                dns_proxy[f'categories->built-in->{category.name}->enabled'] = category.enable_code - 2
                dns_proxy[f'categories->built-in->{category.name}->keyword'] = category.enable_code - 2

        if (ruleset == 'custom'):
            dns_proxy[f'categories->custom->{category.name}->enabled'] = category.enabled

        elif (ruleset in ['tld']):
            dns_proxy[f'tld->{category.name}'] = category.enabled

        dnx.write_configuration(dns_proxy.expanded_user_data)
