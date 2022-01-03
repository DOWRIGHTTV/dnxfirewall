#!/usr/bin/env python3

import os
import shutil

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import ConfigurationManager, load_configuration

from dnx_routines.logging.log_main import LogHandler as Log

DEFAULT_VERSION = 'firewall_pending'
DEFAULT_PATH = 'dnx_system/iptables'
PENDING_RULE_FILE = f'{HOME_DIR}/{DEFAULT_PATH}/usr/firewall_pending.json'
ACTIVE_RULE_FILE  = f'{HOME_DIR}/{DEFAULT_PATH}/usr/firewall_active.json'
COPY_RULE_FILE    = f'{HOME_DIR}/{DEFAULT_PATH}/usr/firewall_copy.json'

ConfigurationManager.set_log_reference(Log)

# ========================================
# MANAGE - used by webui
# ========================================

class FirewallManage:
    '''intermediary between front end and underlying C firewall code.

    Front end <> FirewallManage <file monitoring> FirewallControl <> CFirewall

    firewall = FirewallManage()
    print(firewall.firewall)

    print(firewall.firewall['MAIN'])

    '''

    __slots__ = (
        'firewall',
    )

    # store main instance reference here so it can be accessed throughout webui
    cfirewall = None

    versions = ['pending', 'active']
    sections = ['BEFORE', 'MAIN', 'AFTER']

    def __init__(self):
        self.firewall = load_configuration(DEFAULT_VERSION, filepath=DEFAULT_PATH)

    def add(self, pos, rule, *, section):
        '''insert or append operation of new firewall rule to the specified section.'''

        # for comparison operators, but will use str as key as required for json.
        pos_int = int(pos)

        with ConfigurationManager(DEFAULT_VERSION, file_path=DEFAULT_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # position is at the beginning of the ruleset. this is needed because the slice functions don't work
            # correctly for pos 1 insertions.
            if (pos_int == 1):
                temp_rules = [rule, *ruleset.values()]

                # assigning section with new ruleset
                firewall[section] = {f'{i}': rule for i, rule in enumerate(temp_rules, 1)}

            # position is after last element so can add to end of dict directly.
            elif (pos_int == len(ruleset) + 1):
                ruleset[pos] = rule

            # position falls somewhere within already allocated memory. using slices to split open position.
            else:
                temp_rules = list(ruleset.values())

                # offset to adjust for rule num vs index
                temp_rules.insert(pos_int-1, rule)

                # assigning section with new ruleset
                firewall[section] = {f'{i}': rule for i, rule in enumerate(temp_rules, 1)}

            dnx_fw.write_configuration(firewall)

            # updating instance/ mem-copy of variable for fast access
            self.firewall = firewall

    def remove(self, pos, *, section):

        with ConfigurationManager(DEFAULT_VERSION, file_path=DEFAULT_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # this is safe if it fails because the context will immediately exit gracefully
            ruleset.pop(pos)

            firewall[section] = {f'{i}': rule for i, rule in enumerate(ruleset.values(), 1)}

            dnx_fw.write_configuration(firewall)

            # updating instance/ mem-copy of variable for fast access
            self.firewall = firewall

    def modify(self, static_pos, pos, rule, *, section):
        '''send new definition of rule and rule position to underlying firewall to be updated.

            section (rule type): BEFORE, MAIN, AFTER (will likely be an enum)
        '''

        move = True if pos != static_pos else False

        with ConfigurationManager(DEFAULT_VERSION, file_path=DEFAULT_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # TODO: make lock re entrant (non exclusive?)
            # update rule first using static_pos, then remove from list if it needs to move. cannot call add method from
            # here due to file lock being held by this current context (its not re entrant).
            ruleset[static_pos] = rule
            if (move):
                rule_to_move = ruleset.pop(static_pos)

            # writes even if it needs to move since external func will handle move operation (in the form of insertion).
            # dnx_fw.write_configuration(firewall)

            # updating instance/ mem-copy of variable for fast access
            self.firewall = firewall

        # now that we are out of the context we can use add method to re-insert the rule in specified place
        # NOTE: since the lock has been released it is possible for another process to get the lock and modify firewall
        #  rules before the move can happen. only on rare cases would this even cause an issue and only the pending
        #  config will be effected and can be reverted if need be. in the future maybe we can figure out a way to deal
        #  with this operation without releasing the lock without having to duplicate code.
        if (move):
            self.add(pos, rule_to_move, section=section)

    @staticmethod
    def commit():
        '''Copies pending configuration to active, which is being monitored by Control class
        to load into cfirewall.'''

        with ConfigurationManager():
            shutil.copy(PENDING_RULE_FILE, COPY_RULE_FILE)

            os.replace(COPY_RULE_FILE, ACTIVE_RULE_FILE)

    @staticmethod
    def revert():
        '''Copies active configuration to pending, which effectively wipes any uncommitted changes.'''

        with ConfigurationManager():
            shutil.copy(ACTIVE_RULE_FILE, COPY_RULE_FILE)

            os.replace(COPY_RULE_FILE, PENDING_RULE_FILE)

    def view_ruleset(self, section='MAIN', version='pending'):
        '''returns dict of requested ruleset in raw form. additional processing is required for web ui
        or cli formats.

        args:

        section > will change which ruleset is returned.
        version > PENDING or ACTIVE rule tables.
        '''

        if (version not in self.versions):
            return {}

        if (section not in self.sections):
            return {}

        with ConfigurationManager(f'firewall_{version}', file_path=DEFAULT_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            print(firewall)

            return firewall[section]
