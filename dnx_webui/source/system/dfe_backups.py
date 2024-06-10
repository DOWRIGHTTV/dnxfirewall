#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import web_module_load_callout

web_module_load_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import CFG
from dnx_gentools.system_info import System

from dnx_routines.backups.bck_backups import BackupHandler

from source.web_validate import *
from source.web_interfaces import StandardWebPage

if (TYPE_CHECKING):
    from source.web_typing import *

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
    def update(form: Form) -> tuple[int, str]:

        if (_BACKUP_DISABLED):
            return -1, 'configuration backups are currently disabled for rework.'

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
