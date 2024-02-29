#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil

from random import randint

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.def_enums import CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, write_configuration
from dnx_gentools.file_operations import calculate_file_hash, load_data

from dnx_routines.logging.log_client import Log

from dnx_webui.source.object_manager import FWObjectManager


__all__ = (
    'DEFAULT_VERSION', 'DEFAULT_PATH', 'PENDING_RULE_FILE', 'ACTIVE_RULE_FILE', 'PUSH_RULE_FILE', 'ACTIVE_COPY_FILE',
    'convert_ruleset', 'FirewallControl'
)


DEFAULT_VERSION: str = 'pending'
DEFAULT_PATH:    str = 'dnx_profile/iptables'

PENDING_RULE_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/pending.firewall'
ACTIVE_RULE_FILE:  str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/active.firewall'

# short-lived file that has cfirewall format rules and gets os.replace over active.firewall
PUSH_RULE_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/push.firewall'

# mirror of pending rule file as it was when pushed. used for change detection.
ACTIVE_COPY_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/active_copy.firewall'

ConfigurationManager.set_log_reference(Log)

def convert_ruleset(sections: list[str], firewall_rules: dict, *, name_only: bool = False) -> None:
    '''inplace replacement of firewall objects from id to value.
    '''
    kwargs = {'name_only': True} if name_only else {'convert': True}

    with FWObjectManager(lookup=True) as obj_manager:

        lookup = obj_manager.lookup
        for section in sections:

            for rule in firewall_rules[section].values():
                rule['src_zone'] = [lookup(x, **kwargs) for x in rule['src_zone']]
                rule['src_network'] = [lookup(x, **kwargs) for x in rule['src_network']]
                rule['src_service'] = [lookup(x, **kwargs) for x in rule['src_service']]

                rule['dst_zone'] = [lookup(x, **kwargs) for x in rule['dst_zone']]
                rule['dst_network'] = [lookup(x, **kwargs) for x in rule['dst_network']]
                rule['dst_service'] = [lookup(x, **kwargs) for x in rule['dst_service']]


# =========================================
# Control - used by webui
# =========================================
class FirewallControl:
    '''intermediary between frontend and underlying C rules code.

    Front end <> FirewallControl <file monitoring> FirewallControl <> CFirewall

    rules = FirewallControl()
    print(rules.view_ruleset())

    print(rules.view_ruleset('BEFORE'))
    '''
    __slots__ = ()

    # store the main instances reference here, so it can be accessed throughout webui
    cfirewall: FirewallControl

    versions: list[str, str] = ['pending', 'active']
    sections: list[str, str, str] = ['BEFORE', 'MAIN', 'AFTER']

    def commit(self, section: str, updated_rules: dict) -> None:
        '''Updates pending configuration file with sent in firewall rules section data.

        This is a replace operation on disk and thread/process safe.
        '''
        with ConfigurationManager(DEFAULT_VERSION, ext='firewall', file_path=DEFAULT_PATH) as dnx_fw:
            fw_rules: ConfigChain = dnx_fw.load_configuration(strict=False)

            fw_rules_copy = fw_rules.get_dict()
            fw_rules_copy[section] = updated_rules

            self._generate_ids(fw_rules_copy, section)

            dnx_fw.write_configuration(fw_rules_copy)

    def push(self) -> bool:
        '''Copy the pending configuration to the active state.

        file changes are being monitored by Control class to load into cfirewall.
        '''
        push_error = True

        # ==============================
        # OBJECT ID > VALUE CONVERSIONS
        # ==============================
        with ConfigurationManager():

            # using standalone functions due to ConfigManager not being compatible with these operations
            # -> file swapping across multiple files to retain plain and encoding version of the rules
            fw_rules: ConfigChain = load_configuration('pending', ext='firewall', filepath=DEFAULT_PATH, strict=False)

            fw_rules_copy: dict[str, Any] = fw_rules.get_dict()

            convert_ruleset(self.sections, fw_rules_copy)

            write_configuration(fw_rules_copy, 'push', ext='firewall', filepath=f'{DEFAULT_PATH}/usr')

            os.replace(PUSH_RULE_FILE, ACTIVE_RULE_FILE)

            shutil.copy(PENDING_RULE_FILE, ACTIVE_COPY_FILE)

            push_error = False

        return push_error

    def revert(self):
        '''Copies active configuration to pending, which effectively wipes any unpushed changes.
        '''
        with ConfigurationManager():
            shutil.copy(ACTIVE_COPY_FILE, PUSH_RULE_FILE)

            os.replace(PUSH_RULE_FILE, PENDING_RULE_FILE)

    @staticmethod
    def view_ruleset(section: str = 'MAIN') -> dict:
        '''returns dict of requested "firewall_pending" ruleset in raw form.

        additional processing is required for webui or cli formats.
        section arg will change which ruleset is returned.
        '''
        fw_rules = load_configuration(DEFAULT_VERSION, ext='firewall', filepath=DEFAULT_PATH, strict=False).get_dict()

        try:
            return fw_rules[section]
        except KeyError:
            return {}

    @staticmethod
    def ruleset_len(section: str = 'MAIN') -> int:
        '''returns len of firewall_pending ruleset. defaults to main and returns 0 on error.
        '''
        fw_rules = load_configuration(DEFAULT_VERSION, ext='firewall', filepath=DEFAULT_PATH, strict=False).get_dict()

        try:
            return len(fw_rules[section])
        except:
            return 0

    @staticmethod
    def is_pending_changes():
        active = calculate_file_hash('active_copy.firewall', folder='iptables/usr')
        pending = calculate_file_hash('pending.firewall', folder='iptables/usr')

        # if the user has never modified rules, there is not a pending change.
        # the active file can be none if pending is present.
        # a push will write the active file.
        if (pending is None):
            return False

        return active != pending

    @staticmethod
    def modify_management_access(fields: config) -> bool:

        with ConfigurationManager('system', ext='firewall', file_path='dnx_profile/iptables') as system_rules_file:
            system_rules = system_rules_file.load_configuration()

            for svc in fields.service_ports:

                idx = str(fields.zone + svc)
                key = f'USER->{idx}'

                if (fields.action is CFG.DEL):
                    del system_rules[key]

                elif (fields.action is CFG.ADD):
                    system_rules[f'{key}->name'] = f'webui_service_{idx}'
                    system_rules[f'{key}->id'] = None
                    system_rules[f'{key}->enabled'] = 1
                    system_rules[f'{key}->src_zone'] = [fields.zone]
                    system_rules[f'{key}->src_network'] = [[2, 0, 0]]
                    system_rules[f'{key}->src_service'] = [[2, 6, 1, 65535]]
                    system_rules[f'{key}->dst_zone'] = [0]
                    system_rules[f'{key}->dst_network'] = [[2, 0, 0]]
                    system_rules[f'{key}->dst_service'] = [[1, 6, svc, svc]]
                    system_rules[f'{key}->action'] = 1
                    system_rules[f'{key}->log'] = 1
                    system_rules[f'{key}->ipp_profile'] = 0
                    system_rules[f'{key}->dns_profile'] = 0
                    system_rules[f'{key}->ips_profile'] = 0

                else:
                    return False

            system_rules_file.write_configuration(system_rules.expanded_user_data)

            return True

    @staticmethod
    def _generate_ids(firewall_rules: dict, section: str):

        ids_in_use = set()

        # first pass gets all currently used ids
        for rules in firewall_rules.values():

            for rule in rules.values():

                if (not rule['id']): continue

                ids_in_use.add(rule['id'])

        # second pass will assign an id to all new rules
        for rule in firewall_rules[section].values():

            if (rule['id']): continue

            new_id = randint(1000, 9999)
            while new_id in ids_in_use:
                new_id = randint(1000, 9999)

            rule['id'] = new_id
