#!/usr/bin/env python3

import os, sys
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_validate import convert_int, get_convert_int
from dnx_configure.dnx_system_info import System
from dnx_backups.bck_backups import BackupHandler

_BACKUP_DISABLED = False

def load_page(form):
    backups_info, current_backups = {}, System.backups()

    for backup, c_time in current_backups.items():
        c_time = System.calculate_time_offset(c_time)
        c_time = System.format_date_time(c_time).split(maxsplit=1)

        backups_info[backup] = (c_time[0], c_time[1])

    return backups_info

## Called when front end post, parsing web forms, calling backup methods ##
def update_page(form):

    if (_BACKUP_DISABLED):
        return 'configuration backups are currently disabled.'

    backup_type = get_convert_int(form, 'cfg_backup')
    try:
        backup_action = CFG(backup_type)
    except:
        return INVALID_FORM

    name = form.get('backup_name', None)

    # only checking name if creating new backup
    if (backup_action is CFG.ADD):
        if (not name):
            return INVALID_FORM

        else:
            try:
                validate.standard(name)
            except ValidationError as ve:
                return ve

    try:
        BackupHandler.cfg_backup(name, backup_action)
    except ValidationError as ve:
        return ve
