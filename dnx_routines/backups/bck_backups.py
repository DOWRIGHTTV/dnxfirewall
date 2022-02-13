#!/usr/bin/env python3

from __future__ import annotations

import os
import tarfile

from dnx_gentools.def_enums import CFG
from dnx_routines.logging.log_client import LogHandler as Log
from dnx_routines.configure.exceptions import ValidationError

LOG_NAME = 'system'


class BackupHandler:
    '''This class provides a configuration backup service as well as automated backup for system files when
    running updates.

    This class is not process safe. A file lock should be implemented to prevent any shared state corruption.
    '''

    @classmethod
    def cfg_backup(cls, name, backup_action):
        '''passthrough function to proxy calls to the correct function based on backup action.'''

        if (backup_action is CFG.ADD):
            cls._backup_configuration(name)

        elif (backup_action is CFG.DEL):
            cls._remove_configuration(name)

        elif (backup_action is CFG.RESTORE):
            cls._restore_configuration(name)

    @staticmethod
    def _backup_configuration(name):
        backup_file_path = f'{HOME_DIR}/dnx_system/config_backups/{name}.tar'
        usr_cfg_file_path = f'{HOME_DIR}/dnx_system/data/usr'

        # check name in use before making backup/file
        if os.path.isfile(backup_file_path):
            raise ValidationError(f'Cannot overwrite existing backup file [{name}.tar].')

        with tarfile.open(backup_file_path, 'w') as tar:
            for file in os.listdir(usr_cfg_file_path):

                if (file.endswith('.sqlite3') or file == 'temp'): continue

                filename = f'{usr_cfg_file_path}/{file}'
                tar.add(filename, arcname=os.path.basename(filename))

    @staticmethod
    # extracting config backup files to temp folder, so they can be merged with running configs
    def _restore_configuration(name):

        # restoring system default consists of deleting all usr config files
        if (name == 'system_default'):
            usr_cfg_file_path = f'{HOME_DIR}/dnx_system/data/usr'

            for file in os.listdir(usr_cfg_file_path):

                # NOTE: IMPORTANT. ensuring database does not get removed
                if (file.endswith('.sqlite3') or file == 'temp'): continue

                # exception to protect process just in case it is being removed by another user at the same time.
                try:
                    os.remove(f'{usr_cfg_file_path}/{file}')
                except FileNotFoundError:
                    pass

            Log.simple_write(LOG_NAME, 'notice', f'configuration restored to system defaults')

        else: #
            try:
                with tarfile.open(f'{HOME_DIR}/dnx_system/config_backups/{name}.tar', 'r') as tar:
                    tar.extractall(path=f'{HOME_DIR}/dnx_system/data/usr/')
            except:
                raise ValidationError('Error while loading configuration. has the file been removed?')

            Log.simple_write(LOG_NAME, 'notice', f'configuration restored from file [{name}]')

    @staticmethod
    def _remove_configuration(name):
        try:
            os.remove(f'{HOME_DIR}/dnx_system/config_backups/{name}.tar')
        except FileNotFoundError:
            raise ValidationError(f'{name} is not a valid file. reload page to see current backups.')
