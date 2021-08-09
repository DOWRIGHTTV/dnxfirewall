#!/usr/bin/python3

import os, sys
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import INVALID_FORM, DATA
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError

def load_page():
    ip_proxy = load_configuration('ip_proxy')

    country_map = load_configuration('geolocation', filepath='dnx_frontend/data')

    reputation  = ip_proxy['reputation']
    geolocation = ip_proxy['geolocation']

    tr_settings = ip_proxy['time_restriction']
    tr_length   = tr_settings['length']
    tr_enabled  = tr_settings['enabled']

    tr_settings = tr_settings['start'].split(':')
    hour = int(tr_settings[0])
    minutes = int(tr_settings[1])
    suffix = 'AM'
    if (hour > 12):
        hour -= 12
        suffix = 'PM'

    # TODO: what in the actuall @#$@ is this. NOTE: this looks like the tlen_hour is will absorb the overall length
    # and will be dealt with if the result is a float.
    tr_length /= 3600
    tlen_hour = tr_length
    tlen_minutes = 0
    if (isinstance(tr_length, float)):
        tr_length = str(tr_length).split('.')
        tlen_hour = int(tr_length[0])
        tlen_minutes = float(f'.{tr_length[1]}')
        tlen_minutes = int(tlen_minutes * 60)

    tr_settings = {
        'hour': hour, 'minutes': minutes, 'length_hour': tlen_hour, 'length_minutes': tlen_minutes,
        'suffix': suffix, 'enabled': tr_enabled
    }

    ipp_settings = {
        'reputation': reputation, 'geolocation': geolocation, 'tr_settings': tr_settings, 'country_map': country_map
   }

    return ipp_settings

def update_page(form):
    print(form)
    if ('ip_hosts_update' in form):
        category_settings = form.getlist('reputation', None)
        if (not category_settings):
            return INVALID_FORM

        try:
            validate.ip_proxy_settings(category_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.update_ip_proxy_settings(category_settings)

    if ('country' in form):
        country_setting = {k: form.get(k, DATA.INVALID) for k in ['country', 'direction']}

        if (DATA.INVALID in country_setting.values()):
            return INVALID_FORM

        try:
            validate.geolocation(country_setting, rtype='country') # NOTE: to know its country vs continent
        except ValidationError as ve:
            return ve

        else:
            configure.update_geolocation(country_setting, rtype='country')

    elif ('geo_lists_update' in form):
        country_settings = form.getlist('countries', None)
        if (not country_settings):
            return INVALID_FORM

        try:
            validate.ip_proxy_settings(country_settings, ruleset='geolocation')
        except ValidationError as ve:
            return ve
        else:
            configure.update_ip_proxy_settings(country_settings, ruleset='geolocation')

    elif ('time_res_update' in form):
        hour    = form.get('hour', None)
        minutes = form.get('minutes', None)
        time_suffix  = form.get('time_suffix', None)
        tlen_hour    = form.get('tlen_hour', None)
        tlen_minutes = form.get('tlen_minutes', None)

        enabled = True if 'restriction_enable' in form else False

        tr_settings = {
            'hour': hour, 'minutes': minutes, 'suffix': time_suffix, 'length_hour': tlen_hour,
            'length_minutes': tlen_minutes, 'enabled': enabled
        }

        if not all([hour, minutes, time_suffix, tlen_hour, tlen_minutes]):
            return INVALID_FORM

        try:
            validate.time_restriction(tr_settings)
        except ValidationError as ve:
            return ve
        else:
            tr_settings['hour'] = int(hour)
            tr_settings['length_minutes'] = int(tlen_minutes)
            configure.update_ip_restriction_settings(tr_settings)

    else:
        return INVALID_FORM
