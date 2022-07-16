#!/usr/bin/python3

from typing import Optional

from dnx_gentools.def_constants import fast_time, INVALID_FORM, LOG_LEVELS
from dnx_gentools.def_enums import DATA, LOG
from dnx_gentools.def_exceptions import ValidationError
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from dnx_gentools.system_info import System
from source.web_validate import get_convert_int

def load_page(form):
    logging = load_configuration('logging_client')

    # correcting time for configured offset.
    system_time = System.format_date_time(fast_time())
    local_time = System.calculate_time_offset(fast_time())
    local_time = System.format_date_time(local_time)

    logging_settings = {
        'system': system_time, 'local': local_time,
        'offset': {
            'direction': logging['time_offset->direction'],
            'amount': logging['time_offset->amount']
        },
        'logging': {
            'log_levels': [level.title() for level in LOG_LEVELS],
            'level': logging['logging->level'],
            'length': logging['logging->length']
        }
    }

    return logging_settings

def update_page(form):
    # matching logging update form and sending to configuration method.
    if ('logging_update' in form):
        log_settings = config(**{
            'length': get_convert_int(form, 'length'),
            'level': get_convert_int(form, 'level')
        })
        if any([x in [DATA.MISSING, DATA.INVALID] for x in log_settings.values()]):
            return INVALID_FORM

        error = validate_log_settings(log_settings)
        if (error):
            return error.message

        configure_logging(log_settings)

    # matching time offset form and sending to configuration method.
    elif ('time_offset_update' in form):
        offset_settings = config(**{
            'direction': form.get('dir_offset', DATA.MISSING),
            'time': get_convert_int(form, 'time_offset')
        })
        if any([x in [DATA.MISSING, DATA.INVALID] for x in offset_settings.values()]):
            return INVALID_FORM

        error = validate_time_offset(offset_settings)
        if (error):
            return error.message

        configure_sys_time_offset(offset_settings)

    else:
        return INVALID_FORM

# ==============
# VALIDATION
# ==============

def validate_log_settings(settings: config, /) -> Optional[ValidationError]:
    if (settings['length'] not in [30, 45, 60, 90]):
        return ValidationError('Invalid log settings.')

    try:
        LOG(settings['level'])
    except ValueError:
        return ValidationError('Invalid log settings.')

def validate_time_offset(settings: config, /) -> Optional[ValidationError]:

    if (settings.direction not in [' ', '-', '+']):
        return ValidationError('Invalid time offset sign.')

    if (settings.time not in range(0, 15)):
        return ValidationError('Invalid time offset value.')

    if (settings.direction == ' ' and settings.time != 0):
        return ValidationError('Direction cannot be empty if amount is not zero.')

    elif (settings.direction == '-' and settings.time in [13, 14]):
        return ValidationError('Invalid timezone/ time offset.')

# ==============
# CONFIGURATION
# ==============

def configure_logging(log: config):
    with ConfigurationManager('logging_client') as dnx:
        log_settings = dnx.load_configuration()

        log_settings['logging->length'] = log.length
        log_settings['logging->level']  = log.level

        dnx.write_configuration(log_settings.expanded_user_data)

def configure_sys_time_offset(offset: config):
    with ConfigurationManager('logging_client') as dnx:
        offset_settings = dnx.load_configuration()

        if (offset.time == 0):
            offset.direction = '+'

        offset_settings['time_offset->direction'] = offset.direction
        offset_settings['time_offset->amount'] = offset.time

        dnx.write_configuration(offset_settings.expanded_user_data)
