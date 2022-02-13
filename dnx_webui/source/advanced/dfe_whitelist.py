#!/usr/bin/python3

import dnx_routines.configure.configure as configure
import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.exceptions import ValidationError
from dnx_routines.configure.system_info import System

def load_page(form):
    whitelist = load_configuration('whitelist')

    for info in whitelist['time_based'].values():
        st_offset = System.calculate_time_offset(info['time'])

        info['time'] = System.format_date_time(st_offset)

    whitelist_settings = {
        'time_based': whitelist['time_based'], 'pre_proxy': whitelist['pre_proxy'],
        'ip_bypass':  whitelist['ip_bypass']
    }

    return whitelist_settings

def update_page(form):
    pass
