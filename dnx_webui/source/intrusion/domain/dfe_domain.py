#!/usr/bin/env python3

from __future__ import annotations

from functools import partial

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
        error, dnsp_info = form_validator.parse_form(form)
        if (error):
            return 1, error.message

        if (dnsp_info.btn == 'security_profile_ident'):
            if error := configure_security_profile_ident(dnsp_info):
                return 11, error.message

        return NO_STANDARD_ERROR

    @staticmethod
    def handle_ajax(aform: JSON) -> WebAjaxResponse:

        ruleset: str | DATA = aform.get('type', DATA.MISSING)
        if (ruleset is DATA.MISSING):
            return False, {'error': 1, 'message': INVALID_FORM}

        category = config(**{
            'security_profile': get_convert_in_range(aform, 'security_profile', bounds=(1, 15)),
            'data': aform.get('category', DATA.MISSING),
            'enable_code': get_convert_in_range(aform, 'enabled')
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

    # category data should be a string form of a tuple. converting to tuple to validate
    try:
        cat_group, cat_name = category.data.split(',')
    except ValueError:
        return 1, ValidationError('Invalid category data format.')

    # reassigning data in config object to tuple for later use
    category.group = cat_group
    category.name = cat_name

    if (ruleset in ['built-in', 'custom', 'keyword']):
        # keyword and built-in share categories
        r_set = 'built-in' if ruleset == 'keyword' else ruleset

        # general category membership test
        if not (cat := dns_proxy.get_dict(f'categories->{r_set}->{cat_group}').get(cat_name, None)):
            return 2, ValidationError('Unknown domain category specified.')

        if (ruleset == 'keyword' and category.enable_code in VALID_CATEGORY_CODES):

            if (not cat['tethered'] and (category.enable_code and not cat['enabled'])):
                return 3, ValidationError('Standard must be enabled first for this category to use keyword.')

            return

        # category enable-code is in the valid range
        elif (ruleset == 'built-in' and category.enable_code in VALID_CATEGORY_CODES):
            return

        # custom category enable-code is in the standard range only
        elif (ruleset == 'custom' and category.enable_code in STANDARD_CATEGORY_CODES):
            return

    elif (ruleset in ['tld']):
        # general category membership test, tld only has a single setting so must check against "None"
        cat_setting = dns_proxy.get_dict(f'tld->{cat_group}').get(cat_name, None)
        if (cat_setting is None):
            return 3, ValidationError('Unknown TLD category specified.')

        # tld enable-code is in the standard range only
        if (category.enable_code in STANDARD_CATEGORY_CODES):
            return

    return 99, ValidationError(INVALID_FORM)

# =========================
# FORM VALIDATION TEMPLATE
# =========================
form_validator = ValidationConfigForm({
    # security profile should always be present so defaulting to -1 if missing to trigger error
    '__on_enter': {
        'security_profile': ValidationPageContext(
            call=lambda form: check_in_range(form.get('security_profile', -1), (1, 15)),
            append=lambda form, cfg: cfg.update({'security_profile': form['security_profile']})
        )
    },
    'security_profile': SKIP_VALIDATION,
    'security_profile_ident': {
        'security_profile_name': ValidationFieldInfo(cfg_key='name', validation=partial(alpha_maxlen, maxlen=12)),
        'security_profile_desc': ValidationFieldInfo(
            cfg_key='desc', validation=partial(alpha_maxlen, maxlen=32, override=[' '])),
    }
})

# ==============
# CONFIGURATION
# ==============
def configure_security_profile_ident(sp_ident: config) -> Optional[ConfigurationError]:
    dnsp = ConfigurationManager(
        f'profiles/profile_{sp_ident.security_profile}', cfg_type='security/ip', err_as_value=True)
    with dnsp:
        dnsp.config_data['name'] = sp_ident.name
        dnsp.config_data['desc'] = sp_ident.desc

    return dnsp.error

# im being very explicit on the if statements because I would rather get the logic right before pretty.
def configure_domain_categories(category: config, *, ruleset: str):
    with ConfigurationManager(f'profiles/profile_{category.security_profile}', cfg_type='security/dns') as dnx:
        # note: when custom categories are reintroduced, this will need to set strict=False
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
            dns_proxy[f'tld->{category.group}->{category.name}'] = category.enable_code

        dnx.write_configuration(dns_proxy.expanded_user_data)
