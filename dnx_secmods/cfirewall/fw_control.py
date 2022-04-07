#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, write_configuration, calculate_file_hash

from dnx_routines.logging.log_client import Log

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain

    from dnx_webui import ObjectManager


DEFAULT_VERSION: str = 'pending'
DEFAULT_PATH:    str = 'dnx_system/iptables'

PENDING_RULE_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/pending.firewall'
ACTIVE_RULE_FILE:  str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/active.firewall'

# short-lived file that has cfirewall format rules and gets os.replace over active.firewall
PUSH_RULE_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/push.firewall'

# mirror of pending rule file as it was when pushed. used for change detection.
ACTIVE_COPY_FILE: str = f'{HOME_DIR}/{DEFAULT_PATH}/usr/active_copy.firewall'

ConfigurationManager.set_log_reference(Log)

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
    object_manager: ObjectManager

    versions: list[str, str] = ['pending', 'active']
    sections: list[str, str, str] = ['BEFORE', 'MAIN', 'AFTER']

    # _firewall: dict[str, Any] = load_configuration(DEFAULT_VERSION, ext='.firewall', filepath=DEFAULT_PATH).get_dict()

    @classmethod
    def commit(cls, firewall_rules: dict) -> None:
        '''Updates pending configuration file with sent in firewall rules data.

        This is a replace operation on disk and thread and process safe.'''

        with ConfigurationManager(DEFAULT_VERSION, ext='.firewall', file_path=DEFAULT_PATH) as dnx_fw:
            dnx_fw.write_configuration(firewall_rules)

        # updating instance/ mem-copy of variable for fast access
        # cls._firewall = firewall_rules

    @classmethod
    def push(cls) -> bool:
        '''Copy the pending configuration to the active state.

        file changes are being monitored by Control class to load into cfirewall.
        '''
        push_error = True

        # ==============================
        # OBJECT ID > VALUE CONVERSIONS
        # ==============================
        obj_lookup = cls.object_manager.lookup

        with ConfigurationManager():

            # using standalone functions due to ConfigManager not being compatible with these operations
            fw_rules: ConfigChain = load_configuration('pending', ext='.firewall', filepath='dnx_system/iptables')

            fw_rule_copy: dict[str, Any] = fw_rules.get_dict()

            for section in cls.sections:

                for rule in fw_rule_copy[section].values():
                    rule['src_zone'] = [obj_lookup(x, convert=True) for x in rule['src_zone']]
                    rule['src_network'] = [obj_lookup(x, convert=True) for x in rule['src_network']]
                    rule['src_service'] = [obj_lookup(x, convert=True) for x in rule['src_service']]

                    rule['dst_zone'] = [obj_lookup(x, convert=True) for x in rule['dst_zone']]
                    rule['dst_network'] = [obj_lookup(x, convert=True) for x in rule['dst_network']]
                    rule['dst_service'] = [obj_lookup(x, convert=True) for x in rule['dst_service']]

            write_configuration(fw_rule_copy, 'push', ext='.firewall', filepath='dnx_system/iptables/usr')

            os.replace(PUSH_RULE_FILE, ACTIVE_RULE_FILE)

            shutil.copy(PENDING_RULE_FILE, ACTIVE_COPY_FILE)

            push_error = False

        return push_error

    @staticmethod
    def revert():
        '''Copies active configuration to pending, which effectively wipes any unpushed changes.'''

        with ConfigurationManager():
            shutil.copy(ACTIVE_COPY_FILE, PUSH_RULE_FILE)

            os.replace(PUSH_RULE_FILE, PENDING_RULE_FILE)

    def convert_ruleset(self):
        pass

    def view_ruleset(self, section: str = 'MAIN') -> dict:
        '''returns dict of requested "firewall_pending" ruleset in raw form.

        additional processing is required for webui or cli formats.
        section arg will change which ruleset is returned.
        '''
        fw_rules = load_configuration(DEFAULT_VERSION, ext='.firewall', filepath=DEFAULT_PATH).get_dict()

        return fw_rules

        # try:
        #     return self._firewall[section]
        # except KeyError:
        #     return {}

    def ruleset_len(self, section: str = 'MAIN') -> int:
        '''returns len of firewall_pending ruleset. defaults to main and returns 0 on error.'''

        fw_rules = load_configuration(DEFAULT_VERSION, ext='.firewall', filepath=DEFAULT_PATH).get_dict()

        return len(fw_rules)

        # try:
        #     return len(self._firewall[section])
        # except:
        #     return 0

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
