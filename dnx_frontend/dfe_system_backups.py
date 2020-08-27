#!/usr/bin/env python3

import os, sys
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System
from dnx_backups.bck_backups import BackupService

_BACKUP_DISABLED = True

def load_page():
    backups_info = {}
    current_backups = System.backups()

    for backup, c_time in current_backups.items():
        c_time = System.calculate_time_offset(c_time)
        c_time = System.format_date_time(c_time).split(maxsplit=1)

        backups_info[backup] = (c_time[0], c_time[1])

    return backups_info

## Called when front end post, parsing web forms, calling backup methods ##
def update_page(form):
    if (_BACKUP_DISABLED):
        return 'configuration backups are currently disabled.'

    elif ('cfg_backup_create' in form):
        backup_type = form.get('cfg_backup_create')
        name = form.get('backup_name', None)
        action = CFG.ADD

    elif ('cfg_backup_remove' in form):
        backup_type = form.get('cfg_backup_remove')
        name = form.get('backup_name', None)
        action = CFG.DEL

    elif ('cfg_backup_restore' in form):
        backup_type = form.get('cfg_backup_restore')
        name = form.get('backup_name', None)
        action = 'RESTORE'

    if (not backup_type or not name):
        return INVALID_FORM

    try:
        validate.standard(name)
    except ValidationError as ae:
        error = ae
    else:
        # TODO: fix this up one day | backups
        BackupService().backup(backup_type, action, name)
