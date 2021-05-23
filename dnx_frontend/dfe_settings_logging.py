#!/usr/bin/python3

import os, sys
import time

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import fast_time, DATA, INVALID_FORM, LOG_LEVELS
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System

def load_page():
    logging_settings = load_configuration('logging_client')['logging']

    log = logging_settings['logging']

    # correcting time for configured offset.
    time_offset = logging_settings['time_offset']
    system_time = System.format_date_time(fast_time())
    local_time = System.calculate_time_offset(fast_time())
    local_time = System.format_date_time(local_time)

    logging_settings = {
        'system': system_time, 'local': local_time,
        'offset': {
            'direction': time_offset['direction'],
            'amount': time_offset['amount']
        },
        'logging': {
            'log_levels': [level.title() for level in LOG_LEVELS],
            'level': log['level'],
            'length': log['length']
        }
    }

    return logging_settings

def update_page(form):
    # matching logging update form and sending to configuration method.
    if ('logging_update' in form):
        log_settings = {
            'length': validate.get_convert_int(form, 'length'),
            'level': validate.get_convert_int(form, 'level')
        }
        if (DATA.INVALID in log_settings.values()):
            return INVALID_FORM

        try:
            validate.log_settings(log_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.set_logging(log_settings)

    # matching time offset form and sending to configuration method.
    elif ('time_offset_update' in form):
        offset_settings = {
            'direction': form.get('dir_offset', DATA.INVALID),
            'time': validate.get_convert_int(form, 'time')
        }
        if (DATA.INVALID in offset_settings.values()):
            return INVALID_FORM

        try:
            validate.time_offset(offset_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.update_system_time_offset(offset_settings)

    else:
        return INVALID_FORM
