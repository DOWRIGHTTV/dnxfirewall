#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import CFG

from dnx_gentools.system_info import System
from dnx_routines.backups.bck_backups import BackupHandler

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

_BACKUP_DISABLED = True

class WebPage(StandardWebPage):
    '''
    available methods: load, handle_ajax
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        backups_info, current_backups = {}, System.backups()

        for backup, c_time in current_backups.items():
            c_time = System.calculate_time_offset(c_time)
            c_time = System.format_date_time(c_time).split(maxsplit=1)

            backups_info[backup] = (c_time[0], c_time[1])

        return backups_info

    @staticmethod
    def update_page(form: Form):

        if (_BACKUP_DISABLED):
            return 'configuration backups are currently disabled for rework.'

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

            try:
                standard(name)
            except ValidationError as ve:
                return ve

        try:
            BackupHandler.cfg_backup(name, backup_action)
        except ValidationError as ve:
            return ve
