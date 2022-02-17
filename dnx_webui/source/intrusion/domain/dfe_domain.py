#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional

from dnx_gentools.def_constants import INVALID_FORM, ppt
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from dnx_routines.configure.web_validate import ValidationError, get_convert_bint

# TODO: if system category gets disabled that had keyword enabled. it does not disable the keyword search.
def load_page(form):
    dns_proxy = load_configuration('dns_proxy')

    domain_settings = {
        'default': dns_proxy.get_items('categories->default'),
        'user_defined': dns_proxy.get_items('categories->user_defined'),
        'tld': dns_proxy.get_items('tld')
    }

    ppt(domain_settings)
    return domain_settings

# TODO: figure out how to refresh page or update keyword options after domain cat change
def update_page(form: dict) -> tuple[bool, dict]:

    ruleset = form.get('type', DATA.MISSING)

    if (ruleset is not DATA.MISSING):
        category = config(**{
            'name': form.get('category', DATA.MISSING),
            'enabled': get_convert_bint(form, 'enabled')
        })
        print(category)
        if ([x for x in category.values() if x in [DATA.MISSING, DATA.INVALID]]):
            return False, {'error': 1, 'message': INVALID_FORM}

        error = validate_domain_categories(category, ruleset=ruleset)
        if (error):
            return False, {'error': 2, 'message': error.message}

        configure_domain_categories(category, ruleset=ruleset)

    else:
        return False, {'error': 3, 'message': INVALID_FORM}

    return True, {'error': 0, 'message': None}

# ==============
# VALIDATION
# ==============

def validate_domain_categories(category: config, *, ruleset: str) -> Optional[ValidationError]:

    dns_proxy = load_configuration('dns_proxy')

    if (ruleset in ['default', 'user_defined']):
        cat_list = dns_proxy.get_list(f'categories->{ruleset}')

        if category.name in ['malicious', 'cryptominer']:
            return ValidationError('high risk categories cannot be disabled at this time.')

    elif (ruleset in ['tld']):
        cat_list = dns_proxy.get_list('tld')

    elif (ruleset in ['keyword']):
        domain_cats = dns_proxy.get_list('categories->default')

        if (category.name not in domain_cats):
            return ValidationError(INVALID_FORM)

        # ensuring url cat is enabled since it is a pre-req to enable keywords
        if (not dns_proxy[f'categories->default->{category.name}->enabled']):
            return ValidationError(INVALID_FORM)

        # skipping over last check which is not valid for keyword validation
        return None

    else:
        return ValidationError(INVALID_FORM)

    if category.name not in cat_list:
        return ValidationError(INVALID_FORM)

# ==============
# CONFIGURATION
# ==============

def configure_domain_categories(category: config, *, ruleset):
    with ConfigurationManager('dns_proxy') as dnx:
        dns_proxy = dnx.load_configuration()

        if category.name in ['malicious', 'cryptominer']:
            return

        dns_proxy[f'categories->{ruleset}->{category.name}->enabled'] = category.enabled

        dnx.write_configuration(dns_proxy.expanded_user_data)

def configure_domain_tlds(tld: config):
    with ConfigurationManager('dns_proxy') as dnx:
        proxy_settings = dnx.load_configuration()

        proxy_settings[f'tlds->{tld.name}'] = tld.enabled

        dnx.write_configuration(proxy_settings.expanded_user_data)
#
# def set_domain_category_keywords(en_keywords):
#     with ConfigurationManager('dns_proxy') as dnx:
#         dns_proxy_categories = dnx.load_configuration()
#
#         domain_cats = dns_proxy_categories['categories']['default']
#         for cat, settings in domain_cats.items():
#             settings['keyword'] = True if cat in en_keywords else False
#
#         dnx.write_configuration(dns_proxy_categories)
