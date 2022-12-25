#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

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
    # TODO: figure out how to refresh page or update keyword options after domain cat change
    def handle_ajax(form: Form) -> tuple[bool, WebError]:

        ruleset = form.get('type', DATA.MISSING)
        if (ruleset is DATA.MISSING):
            return False, {'error': 1, 'message': INVALID_FORM}

        category = config(**{
            'name': form.get('category', DATA.MISSING),
            'enabled': get_convert_bint(form, 'enabled')
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

    if (ruleset in ['built-in', 'custom']):
        cat_list = dns_proxy.get_list(f'categories->{ruleset}')

    elif (ruleset in ['tld']):
        cat_list = dns_proxy.get_list('tld')

    elif (ruleset in ['keyword']):
        domain_cats = dns_proxy.get_list('categories->built-in')

        if (category.name not in domain_cats):
            return ValidationError(INVALID_FORM)

        # ensuring the associated url cat is enabled since it is a pre-req to enable keywords
        if (not dns_proxy[f'categories->built-in->{category.name}->enabled']):
            return ValidationError(INVALID_FORM)

        # skipping over last check which is not valid for keyword validation
        return None

    else:
        return ValidationError(INVALID_FORM)

    if (category.name not in cat_list):
        return ValidationError(INVALID_FORM)

# ==============
# CONFIGURATION
# ==============
def configure_domain_categories(category: config, *, ruleset: str):
    with ConfigurationManager('profiles/profile_1', cfg_type='security/dns') as dnx:
        dns_proxy: ConfigChain = dnx.load_configuration()

        if (ruleset in ['built-in', 'user_defined']):

            dns_proxy[f'categories->{ruleset}->{category.name}->enabled'] = category.enabled

        elif (ruleset in ['tld']):

            dns_proxy[f'tld->{category.name}'] = category.enabled

        elif (ruleset in ['keyword']):

            dns_proxy[f'categories->built-in->{category.name}->keyword'] = category.enabled

        dnx.write_configuration(dns_proxy.expanded_user_data)
