#!/usr/bin/python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import DATA, GEO, DIR
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config, load_data

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

class WebPage(StandardWebPage):
    '''
    available methods: load, update, handle_ajax
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        proxy_profile: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/ip')
        proxy_global: ConfigChain = load_configuration('global', cfg_type='security/ip')

        # country_map: ConfigChain = load_configuration('geolocation', filepath='dnx_webui/data')

        # TODO: get selected security profile setting and render accordingly. start with converting current config to
        #  use "profile 1", with proxy set for profiles. once that is good then we can expand to more profiles.

        # controlling whether to load defaults or user selected view.
        # NOTE: These are validated by the update function, so it is safe to assume types.
        geo_region = form.get('region', 'africa')
        geo_direction = int(form.get('menu_dir', DIR.OFF))

        # selected_region = set(country_map[f'{geo_region}->countries'])

        geolocation = []
        geolocation_append = geolocation.append
        for country, direction in proxy_profile.get_items(f'geolocation->{geo_region}->countries'):

            # region level filter
            # if (country not in selected_region):
            #     continue

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

        tr_settings = proxy_global['time_restriction->start'].split(':')

        hour, minutes = int(tr_settings[0]), int(tr_settings[1])
        suffix = 'AM'
        if (hour > 12):
            hour -= 12
            suffix = 'PM'

        tr_length = proxy_global['time_restriction->length']

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
            'enabled': proxy_global['time_restriction->enabled']
        }

        ipp_settings = {
            'security_profile': 1,
            'profile_name': proxy_profile['name'],
            'profile_desc': proxy_profile['description'],
            'reputation': proxy_profile.get_items('reputation->built-in'),
            'tr_settings': tr_settings, 'regions': proxy_profile.get_list('geolocation'),  # sorted(country_map.get_list()),
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

    @staticmethod
    def update(form: Form) -> tuple[int, str]:

        # prevents errors while in dev mode.
        if ('security_profile' in form):
            return -1, 'temporarily limited to profile 1.'

        if ('change_geo_view' in form):
            geo_direction = convert_int(form.get('menu_dir', DATA.MISSING))

            if (geo_direction not in range(6)):
                return 1, INVALID_FORM

            valid_regions = load_configuration('geolocation', filepath='dnx_webui/data').get_list()
            if (form.get('region') not in valid_regions):
                return 2, INVALID_FORM

        elif ('restriction_enable' in form):
            tr_settings = config(**{
                'enabled': get_convert_int(form, 'restriction_enable')
            })
            if (DATA.INVALID in tr_settings.values()):
                return 3, INVALID_FORM

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
                return 4, INVALID_FORM

            if error := validate_time_restriction(tr_settings):
                return 5, error.message

            configure_time_restriction(tr_settings, 'all')

        elif ('continent' in form):
            return 69, 'Bulk actions not available.'

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

    @staticmethod
    def handle_ajax(json_data: dict) -> tuple[bool, WebError]:

        category = config(**{
            'type': json_data.get('type', DATA.MISSING),
            'name': json_data.get('category', DATA.MISSING),
            'direction': get_convert_int(json_data, 'direction')
        })

        if ([x for x in category.values() if x in [DATA.MISSING, DATA.INVALID]]):
            return False, {'error': 1, 'message': INVALID_FORM}

        if (category.type == 'reputation'):

            if error := validate_reputation(category):
                return False, {'error': 2, 'message': error.message}

            configure_reputation(category)

        elif (category.type == 'country'):

            if error := validate_geolocation(category, rtype='country'):  # NOTE: to know its country vs continent
                return False, {'error': 3, 'message': error.message}

            configure_geolocation(category, rtype='country')

        else:
            return False, {'error': 69, 'message': 'unknown action'}

        return True, {'error': 0, 'message': ''}

# ==============
# VALIDATION
# ==============
def validate_reputation(category: config) -> Optional[ValidationError]:
    ip_proxy = load_configuration('profiles/profile_1', cfg_type='security/ip')

    valid_categories = ip_proxy.get_list('reputation->built-in')

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

# TODO: time restriction should probably be moved out of ip proxy. this will ultimately be merged with quotas.
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
def configure_reputation(category: config) -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ip') as dnx:
        ip_proxy_settings: ConfigChain = dnx.load_configuration()

        ip_proxy_settings[f'reputation->built-in->{category.name}'] = category.direction

        dnx.write_configuration(ip_proxy_settings.expanded_user_data)

def configure_geolocation(category: config, *, rtype: str = 'country') -> None:
    with ConfigurationManager('profiles/profile_1', cfg_type='security/ip') as dnx:
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
    with ConfigurationManager('global', cfg_type='security/ip') as dnx:
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
