#!/usr/bin/python3

import os, sys
import time

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import fast_time, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System

def load_page():
    logging_settings = load_configuration('logging_client')['logging']

    logging = logging_settings['logging']
    log_level = logging['level']
    log_length = logging['length']
    log_settings = {'level': log_level, 'length': log_length}

    time_offset = logging_settings['time_offset']
    offset_values = {'direction': time_offset['direction'], 'amount': time_offset['amount']}

    system_time = System.format_date_time(fast_time())

    local_time = System.calculate_time_offset(fast_time())
    local_time = System.format_date_time(local_time)

    logging_settings = {
        'system': system_time, 'local': local_time, 'logging': log_settings,
        'offset': offset_values
    }

    return logging_settings

def update_page(form):
    # Matching logging update form and sending to configuration method.
    if ('logging_update' in form):
        log_length = form.get('log_length', None)
        log_level = form.get('log_level', None)
        if (not log_length or not log_level):
            return INVALID_FORM

        try:
            log_settings = {'length': int(log_length), 'level': int(log_level)}
            validate.log_settings(log_settings)
        except ValueError:
            return INVALID_FORM

        except ValidationError as ve:
            return ve
        else:
            configure.set_logging(log_settings)

    # Matching time offset form and sending to configuration method.
    elif ('time_offset_update' in form):
        dir_offset = form.get('dir-offset', None)
        time_offset = form.get('time-offset', None)
        if (not dir_offset or not time_offset):
            return INVALID_FORM

        try:
            offset_settings = {'direction': dir_offset, 'time': int(time_offset)}
            validate.time_offset(offset_settings)
        except ValueError:
            return INVALID_FORM

        except ValidationError as ve:
            return ve
        else:
            configure.update_system_time_offset(offset_settings)

    else:
        return INVALID_FORM
