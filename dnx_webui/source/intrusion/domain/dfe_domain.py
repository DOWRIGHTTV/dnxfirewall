#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import *

web_module_load_callout(__file__)

from source.web_validate import *

from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import ConfigurationManager, ConfigurationError, load_configuration, config

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
    def load(form: Form) -> WebLoadResponse:
        # this was previously validated by the update method if it is present
        # on a direct page load, the profile will be set to the default (1).
        sec_profile = int(form.get('security_profile', 1))

        proxy_profile: ConfigChain = load_configuration(f'profiles/profile_{sec_profile}', cfg_type='security/dns')

        builtins = proxy_profile.get_items('categories->built-in')

        domain_settings = {
            'security_profile': sec_profile,
            'profile_name': proxy_profile['name'],
            'profile_desc': proxy_profile['description'],
            'built-in': builtins,
            'user_defined': proxy_profile.get_items('categories->custom'),
            'tld': proxy_profile.get_items('tld')
        }

        return domain_settings

    @staticmethod
    def update(form: Form) -> WebUpdateError:
        # this needs to be first because "security profile" key will also be present in the form.
        if ('security_profile_ident' in form):
            sp_ident = config(**{
                'idx':  get_convert_in_range(form, 'security_profile', bounds=(1, 15)),
                'name': form.get('security_profile_name', DATA.MISSING),
                'desc': form.get('security_profile_desc', DATA.MISSING)
            })

            if ([x for x in [DATA.MISSING, DATA.INVALID] if x in sp_ident.values()]):
                return -2, INVALID_FORM

            if error := validate_security_profile_ident(sp_ident):
                return -3, error.message

            configure_security_profile_ident(sp_ident)

        # this is needed here to prevent webui thinking request is invalid, so we might as well do the validation here.
        elif ('security_profile' in form):
            sec_profile = get_convert_in_range(form, 'security_profile', bounds=(1, 15))
            if (sec_profile in [DATA.MISSING, DATA.INVALID]):
                return -1, 'unknown security profile selection.'

        else: return 99, INVALID_FORM

        return NO_STANDARD_ERROR

    @staticmethod
    def handle_ajax(form: JSON) -> WebAjaxResponse:

        ruleset: str | DATA = form.get('type', DATA.MISSING)
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
def validate_security_profile_ident(sp_ident: config) -> Optional[ValidationError]:
    if (not sp_ident.name.isalpha()):
        return ValidationError('Security profile name can only contain characters in the alphabet.')

    if (len(sp_ident.name) > 12):
        return ValidationError('Security profile name must be less than 12 characters.')

    description = sp_ident.desc.split()
    if ([x for x in description if not x.isalpha()]):
        return ValidationError('Security profile description can only contain characters in the alphabet or spaces.')

    if (len(sp_ident.desc) > 32):
        return ValidationError('Security profile name must be less than 32 characters.')

# it is easier and safer to match on the cases we want to see and error on everything else
def validate_domain_categories(category: config, *, ruleset: str) -> Optional[tuple[int, ValidationError]]:

    dns_proxy: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    if (ruleset in ['built-in', 'custom', 'keyword']):
        # keyword and built-in share categories
        r_set = 'built-in' if ruleset == 'keyword' else ruleset

        # category data should be a string form of a tuple. converting to tuple to validate
        try:
            cat_group, cat_name = category.data.split(',')
        except ValueError:
            return 1, ValidationError(INVALID_FORM)

        # reassigning data in config object to tuple for later use
        category.group = cat_group
        category.name = cat_name

        # general category membership test
        if not (cat := dns_proxy.get_dict(f'categories->{r_set}->{cat_group}').get(cat_name, None)):
            return 2, ValidationError(INVALID_FORM)

        if (ruleset == 'keyword' and category.enable_code in VALID_CATEGORY_CODES):

            if (not cat['tethered'] and (category.enable_code and not cat['enabled'])):
                return 3, ValidationError('standard must be enabled first for this category to use keyword.')

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
def configure_security_profile_ident(sp_ident: config) -> None:
    with ConfigurationManager(f'profiles/profile_{sp_ident.idx}', cfg_type='security/dns') as dnx:
        security_profile_settings: ConfigChain = dnx.load_configuration()

        security_profile_settings['name'] = sp_ident.name
        security_profile_settings['description'] = sp_ident.desc

        dnx.write_configuration(security_profile_settings.expanded_user_data)

# im being very explicit on the if statements because I would rather get the logic right before pretty.
def configure_domain_categories(category: config, *, ruleset: str):
    with ConfigurationManager('profiles/profile_1', cfg_type='security/dns') as dnx:
        # TODO: does this need to be strict?
        dns_proxy: ConfigChain = dnx.load_configuration()

        # weird naming/ category structures are remnants from older config file formatting.
        if (ruleset in ['built-in', 'keyword']):

            # converts config key to 'enabled' if the ruleset is built-in
            key = ruleset if ruleset != 'built-in' else 'enabled'

            tethered = dns_proxy[f'categories->built-in->{category.group}->{category.name}->tethered']

            cat_config = f'categories->built-in->{category.group}->{category.name}'

            # changes standard and keyword to the user specified setting
            if (tethered):
                dns_proxy[f'{cat_config}->enabled'] = category.enable_code
                dns_proxy[f'{cat_config}->keyword'] = category.enable_code

            # changes the user specified setting for the category
            else:

                dns_proxy[f'{cat_config}->{key}'] = category.enable_code

                # ensures keyword searching gets disabled if the general category gets disabled
                # TODO: consider making these independent even unless explicitly tethered
                if (ruleset in ['built-in'] and category.enable_code == 0):
                    dns_proxy[f'{cat_config}->keyword'] = category.enable_code

        if (ruleset == 'custom'):
            dns_proxy[f'categories->custom->{category.name}->enabled'] = category.enable_code

        elif (ruleset in ['tld']):
            dns_proxy[f'tld->{category.name}'] = category.enable_code

        dnx.write_configuration(dns_proxy.expanded_user_data)
