#!/usr/bin/python3

import os, sys
import time

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_sysmods.configure.web_validate as validate

from dnx_sysmods.configure.def_constants import fast_time, DATA, INVALID_FORM, LOG_LEVELS
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError
from dnx_sysmods.configure.system_info import System

def load_page(form):
    logging_settings = load_configuration('logging_client')

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
            'time': validate.get_convert_int(form, 'time_offset')
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
