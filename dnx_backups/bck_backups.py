#!/usr/bin/env python3

import os, sys, time
import json
import threading
import tarfile

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_logging.log_main import LogHandler

LOG_MOD = 'update'


class BackupService:
    '''
        This class provides a configuration backup service as well as automated backup for system files when
        running updates
    '''
    def __init__(self):
        self.Log = LogHandler(module=LOG_MOD)

    # Method calling individual methods depending on what is being backedup ##
    def backup(self, backup_type, action=None, name=None, ruleset=None):
        if (backup_type == 'config'):
            if (action is True):
                self.backup_configuration(name)
            elif (action is False):
                self.remove_configuration(name)
            elif (action == 'RESTORE'):
                self.restore_configuration(name)

        elif (backup_type == 'signature'):
            return self.signature(ruleset)

        elif (backup_type == 'system'):
            return self.current_version()

    def backup_configuration(self, name):
        backup_files = ['categories', 'dhcp_server', 'tlds', 'whitelist', 'blacklist', 'config']
        backup_dir = f'{HOME_DIR}/dnx_system/config_backups'
        backup_filename = f'{name}.tar'
        # check if file already exists before making backup
        if os.path.isfile(f'{backup_dir}/{backup_filename}'):
            raise AssertionError('Cannot overwrite existing backup file.')

        # preventing system default from being deleted
        elif (name != 'system-default'):
            with tarfile.open(f'{backup_dir}/{backup_filename}', 'w') as tar:
                for file in backup_files:
                    filename = f'{HOME_DIR}/dnx_system/data/{file}.json'
                    tar.add(filename, arcname=os.path.basename(filename))

    ## TODO: REWORK THIS THING IT IS PRETTY OLD AND DOESNT NECESSARILY ALIGN WITH CURRENT SYSTEM STUFFS
    def restore_configuration(self, name):
        merge_files = ['categories', 'dhcp_server', 'tlds']
        move_files = ['whitelist', 'blacklist', 'config']

        # extracting config backup files to temp folder so they can be merged with running configs
        file_dir = f'{HOME_DIR}/dnx_system/config_backups'
        filename = f'{name}.tar'
        with tarfile.open(f'{file_dir}/{filename}', 'r') as tar:
            tar.extractall(path=f'{HOME_DIR}/dnx_system/data/tmp')

        ## Moving necessary files
        for file in move_files:
            os.rename(f'{HOME_DIR}/dnx_system/data/tmp/{file}.json', f'{HOME_DIR}/dnx_system/data/{file}.json')

        ## Merging necessary files
        for file in merge_files:
            print(f'MERGING {file}')
            with open (f'{HOME_DIR}/dnx_system/data/tmp/{file}.json', 'r') as configs:
                old_config = json.load(configs)

            with open(f'{HOME_DIR}/dnx_system/data/{file}.json', 'r') as configs:
                new_config = json.load(configs)

            if (file == 'categories'):
                old_setting = old_config['dns_proxy']
                new_setting = new_config['dns_proxy']
                ## Updating keyword setting ##
                new_setting['keyword'].update(old_setting['keyword'])
                ## Update user defined category settings ##
                old_user_defined = old_setting['categories']['user_defined']
                new_user_defined = new_setting['categories']['user_defined']
                new_user_defined.update(old_user_defined)
                ## merge system default category settings with user configured settings
                old_system_default = old_setting['categories']['default']
                new_system_default = new_setting['categories']['default']
                for category in old_system_default:
                    if (category in new_system_default):
                        new_system_default[category].update(old_system_default[category])

            elif (file == 'dhcp_server'):
                old_setting = old_config['dhcp_server']['dhcp_reservations']
                new_setting = new_config['dhcp_server']['dhcp_reservations']

                new_setting.update(old_setting)

            elif (file == 'tlds'):
                old_setting = old_config['tlds']
                new_setting = new_config['tlds']

                for tld in old_setting:
                    if (tld in new_setting):
                        new_setting[tld].update(old_setting[tld])

            with open(f'{HOME_DIR}/dnx_system/data/{file}.json', 'w') as configs:
                json.dump(new_config, configs, indent=4)

        ## Clean up temp files
        files = os.listdir(f'{HOME_DIR}/dnx_system/data/tmp')
        for file in files:
            if (file != 'bk'):
               os.remove(f'{HOME_DIR}/dnx_system/data/tmp/{file}')

    def remove_configuration(self, name):
        if (name != 'system-default'):
            try:
                os.remove(f'{HOME_DIR}/dnx_system/config_backups/{name}.tar')
            except FileNotFoundError:
                pass
                # consider logging this, if not, remove the try block.
        else:
            raise AssertionError('System default backup cannot be removed.')

    def current_version(self):
        try:
            files = os.listdir(HOME_DIR)
            with tarfile.open(f'{HOME_DIR}/dnx_system/system_backup/dnx-system-backup.tar', 'w') as tar_test:
                for file in files:
                    filename = f'{HOME_DIR}/{file}'
                    tar_test.add(filename, arcname=os.path.basename(filename), filter=self._tar_exclude)
        except Exception:
            return 'DNX SYSTEM update failed to create a system backup.'

        return False

    def signature(self, ruleset):
        try:
            with tarfile.open(f'{HOME_DIR}/dnx_system/signature_backup/dnx-{ruleset}-backup.tar', 'w') as sig_backup:
                filename = f'{HOME_DIR}/dnx_{ruleset}lists'
                sig_backup.add(filename, arcname=os.path.basename(filename), filter=self._tar_exclude)
        except Exception:
            return f'DNX {ruleset} update failed to create a signature backup.'

        return False

    def _tar_exclude(self, file_path):
        ignore_extensions = ['git', '.gitignore']
        combined_files = {'blocked.keywords', 'blocked.domains', 'blocked.ips'}
        excluded_files = {'dnx_system', 'services', 'dnxfirewall-dependencies', 'dnxlogo.png', 'dnx_web',
                            'web_run.sh', 'dnx_web.sock', '__pycache__'}

        filename = file_path.name.split('/')[-1]
        if (filename in excluded_files or filename in combined_files):
            return False

        for extension in ignore_extensions:
            if (filename.endswith(extension)):
                return False

        return True
