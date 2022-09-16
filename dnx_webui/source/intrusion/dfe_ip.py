#!/usr/bin/python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import ValidationError, convert_int, get_convert_int, convert_bint

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import DATA, GEO, DIR
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config


def load_page(form: Form) -> dict:
    proxy_settings: ConfigChain = load_configuration('ip_proxy')
    country_map: ConfigChain = load_configuration('geolocation', filepath='dnx_webui/data')

    # controlling whether to load defaults or user selected view.
    # NOTE: These are validated by the update function, so it is safe to assume types.
    geo_region = form.get('region', 'africa')
    geo_direction = int(form.get('menu_dir', DIR.OFF))

    selected_region = set(country_map[f'{geo_region}->countries'])

    geolocation = []
    geolocation_append = geolocation.append
    for country, direction in proxy_settings.get_items('geolocation'):

        # region level filter
        if (country not in selected_region):
            continue

        # state level filters
        # direct match
        if (direction == geo_direction):
            geolocation_append((country, direction))

        # all on match
        elif (geo_direction == DIR.ON and direction > DIR.OFF):
            geolocation_append((country, direction))

        # full list
        elif (geo_direction == DIR.ALL):
            geolocation_append((country, direction))

    tr_settings = proxy_settings['time_restriction->start'].split(':')

    hour, minutes = int(tr_settings[0]), int(tr_settings[1])
    suffix = 'AM'
    if (hour > 12):
        hour -= 12
        suffix = 'PM'

    tr_length = proxy_settings['time_restriction->length']

    tr_length /= 3600
    tlen_hour = tr_length
    tlen_minutes = 0
    if (isinstance(tr_length, float)):
        tr_length = str(tr_length).split('.')
        tlen_hour = int(tr_length[0])
        tlen_minutes = float(f'.{tr_length[1]}')
        tlen_minutes = int(tlen_minutes * 60)

    tr_settings = {
        'hour': hour, 'minutes': minutes, 'suffix': suffix,
        'length_hour': tlen_hour, 'length_minutes': tlen_minutes,
        'enabled': proxy_settings['time_restriction->enabled']
    }

    ipp_settings = {
        'sec_profile': 1,
        'reputation': proxy_settings.get_items('reputation'),
        'tr_settings': tr_settings, 'regions': sorted(country_map.get_list()),
        'image_map': {
            DIR.OFF: 'allow_up-down.png', DIR.OUTBOUND: 'block_up.png',
            DIR.INBOUND: 'block_down.png', DIR.BOTH: 'block_up-down.png'
        },
        'geolocation': {
            'region': geo_region,
            'menu_dir': geo_direction,
            'countries': sorted(geolocation)
        }
    }

    return ipp_settings

def update_page(form: Form) -> tuple[bool, WebError]:

    # no action needed for this at this time. in the future, validations may be required, but the load page has been
    # expanded to generate the user select data.
    if ('change_geo_view' in form):
        geo_direction = convert_int(form.get('menu_dir', DATA.MISSING))

        if (geo_direction not in range(6)):
            return False, {'error': 1, 'message': INVALID_FORM}

        valid_regions = load_configuration('geolocation', filepath='dnx_webui/data').get_list()
        if (form.get('region') not in valid_regions):
            return False, {'error': 2, 'message': INVALID_FORM}

    elif ('restriction_enable' in form):
        tr_settings = config(**{
            'enabled': get_convert_int(form, 'restriction_enable')
        })
        if (DATA.INVALID in tr_settings.values()):
            return False, {'error': 3, 'message': INVALID_FORM}

        configure_time_restriction(tr_settings, 'enabled')

    elif ('time_res_update' in form):
        tr_settings = config(**{
            'hour': get_convert_int(form, 'hour'),
            'minutes': get_convert_int(form, 'minutes'),
            'suffix': form.get('time_suffix', DATA.MISSING),
            'hour_len': get_convert_int(form, 'length_hour'),
            'min_len': get_convert_int(form, 'length_minutes')
        })

        if any([x in [DATA.MISSING, DATA.INVALID] for x in tr_settings.values()]):
            return False, {'error': 4, 'message': INVALID_FORM}

        error = validate_time_restriction(tr_settings)
        if (error):
            return False, {'error': 5, 'message': error.message}

        configure_time_restriction(tr_settings, 'all')

    elif ('continent' in form):
        return False, {'error': 69, 'message': 'Bulk actions are still in development.'}

    else:
        return False, {'error': 6, 'message': INVALID_FORM}

# ----------------
# AJAX PROCESSING
# ----------------
def update_field(form: Form) -> tuple[bool, WebError]:

    category = config(**{
        'type': form.get('type', DATA.MISSING),
        'name': form.get('category', DATA.MISSING),
        'direction': get_convert_int(form, 'direction')
    })

    if ([x for x in category.values() if x in [DATA.MISSING, DATA.INVALID]]):
        return False, {'error': 1, 'message': INVALID_FORM}

    if (category.type == 'reputation'):

        error = validate_reputation(category)
        if (error):
            return False, {'error': 2, 'message': error.message}

        configure_reputation(category)

    elif (category.type == 'country'):

        error = validate_geolocation(category, rtype='country')  # NOTE: to know its country vs continent
        if (error):
            return False, {'error': 3, 'message': error.message}

        configure_geolocation(category, rtype='country')

    else:
        return False, {'error': 69, 'message': 'unknown action'}

    return True, {'error': 0, 'message': ''}

# ==============
# VALIDATION
# ==============
def validate_reputation(category: config) -> Optional[ValidationError]:
    ip_proxy = load_configuration('ip_proxy')

    valid_categories = ip_proxy.get_list('reputation')

    if (category.name not in valid_categories):
        return ValidationError(INVALID_FORM)

    if (category.direction not in range(4)):
        return ValidationError(INVALID_FORM)

def validate_geolocation(category: config, rtype: str = 'country') -> Optional[ValidationError]:

    if (category.direction not in range(4)):
        return ValidationError(INVALID_FORM)

    if (rtype == 'country'):
        try:
            GEO[category.name.upper()]
        except:
            return ValidationError(INVALID_FORM)

    elif (rtype == 'continent'):
        geolocation = load_configuration('geolocation', filepath='dnx_webui/data')

        # TODO: test this.
        if (category[rtype] not in geolocation.searchable_system_data):
            return ValidationError(INVALID_FORM)

    else:
        return ValidationError(INVALID_FORM)

def validate_time_restriction(tr: config, /) -> Optional[ValidationError]:

    if (tr.hour not in range(1, 13) or tr.min not in [00, 15, 30, 45]):
        return ValidationError('Restriction settings are not valid.')

    if (tr.hour_len not in range(1, 13) and tr.min_len not in [00, 15, 30, 45]):
        return ValidationError('Restriction settings are not valid.')

    if (tr.suffix not in ['AM', 'PM']):
        return ValidationError('Restriction settings are not valid.')

# ==============
# CONFIGURATION
# ==============
def configure_reputation(category: config, *, ruleset: str = 'reputation') -> None:
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings: ConfigChain = dnx.load_configuration()

        ip_proxy_settings[f'{ruleset}->{category.name}'] = category.direction

        dnx.write_configuration(ip_proxy_settings.expanded_user_data)

def configure_geolocation(category: config, *, rtype: str = 'country') -> None:
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings: ConfigChain = dnx.load_configuration()

        # setting the individual country to user set value
        if (rtype == 'country'):
            ip_proxy_settings[f'geolocation->{category.name.lower()}'] = category.direction

        # iterating over all countries within specified continent and setting their
        # direction as the user set value # TODO: implement this
        elif (rtype == 'continent'):
            pass

        dnx.write_configuration(ip_proxy_settings.expanded_user_data)

def configure_time_restriction(tr: config, /, field) -> None:
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings: ConfigChain = dnx.load_configuration()

        if (field == 'enabled'):
            ip_proxy_settings['time_restriction->enabled'] = tr.enabled

        else:
            tr.hour += 12 if tr.suffix == 'PM' else tr.hour

            start_time = f'{tr.hour}:{tr.minutes}'

            min_fraction = str(tr.min_len/60).strip('0.')
            res_length = f'{tr.hour_len}.{min_fraction}'

            res_length = int(float(res_length) * 3600)

            ip_proxy_settings['time_restriction->start'] = start_time
            ip_proxy_settings['time_restriction->length'] = res_length

        dnx.write_configuration(ip_proxy_settings.expanded_user_data)
