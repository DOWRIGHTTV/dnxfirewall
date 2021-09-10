#!/usr/bin/env python3

import os, sys
import shutil
import threading

from array import array

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.file_operations import cfg_read_poller, load_configuration, ConfigurationManager
from dnx_gentools.standard_tools import Initialize
from dnx_sysmods.logging.log_main import LogHandler as Log

FW_CONTROL = 9001
DEF_VERION = 'firewall_pending'
DEF_USR_PATH = 'dnx_system/iptables/usr'
PENDING_RULE_FILE = f'{HOME_DIR}/{DEF_USR_PATH}/firewall_pending.json'
ACTIVE_RULE_FILE  = f'{HOME_DIR}/{DEF_USR_PATH}/firewall_active.json'
COPY_RULE_FILE    = f'{HOME_DIR}/{DEF_USR_PATH}/firewall_copy.json'

ConfigurationManager.set_log_reference(Log)


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

    # store main instance reference here so it be accessed throughout web ui
    cfirewall = None

    versions = ['pending', 'active']
    sections = ['BEFORE', 'MAIN', 'AFTER']

    def __init__(self):
        self.firewall = load_configuration(DEF_VERION, filepath=DEF_USR_PATH)

    def add(self, pos, rule, *, section):
        '''insert or append operation of new firewall rule to the specified section.'''

        # for comparison operators, but will use str as key as required for json.
        pos_int = int(pos)

        with ConfigurationManager(DEF_VERION, file_path=DEF_USR_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # position is at the beginning of the ruleset. this is needed because the slice functions dont work
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

                temp_rules = [*temp_rules[:pos_int], rule, *temp_rules[pos_int+1:]]

                # assigning section with new ruleset
                firewall[section] = {f'{i}': rule for i, rule in enumerate(temp_rules, 1)}

            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

    def remove(self, pos, *, section):

        with ConfigurationManager(DEF_VERION, file_path=DEF_USR_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # this is safe if it fails, because the context will exit
            ruleset.pop(pos)

            firewall[section] = {f'{i}': rule for i, rule in enumerate(ruleset.values(), 1)}

            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

    def modify(self, static_pos, pos, rule, *, section):
        '''send new definition of rule and rule position to underlying firewall to be updated.

            section (rule type): BEFORE, MAIN, AFTER (will likely be an enum)
        '''

        move = True if pos != static_pos else False

        with ConfigurationManager(DEF_VERION, file_path=DEF_USR_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # update rule first using static_pos, then remove from list if it needs to move. cannot call add method from
            # here due to file lock being held by this current context (its not re entrant).
            ruleset[static_pos] = rule
            if (move):
                rule_to_move = ruleset.pop(static_pos)

            # write config even if it needs to move since external functional will handle move operation.
            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

        # now that we are out of the context we can use add method to re insert the rule in specified place
        if (move):
            self.add(pos, rule_to_move, section=section)


    def commit(self):
        '''Copies pending configuration to active, which is being monitored by Control class
        to load into cfirewall.'''

        with ConfigurationManager():
            shutil.copy(PENDING_RULE_FILE, COPY_RULE_FILE)

            os.replace(COPY_RULE_FILE, ACTIVE_RULE_FILE)

    def revert(self):
        '''Copies active configuration to pending, which effectively wipes any uncommitted changes.'''

        with ConfigurationManager():
            shutil.copy(ACTIVE_RULE_FILE, COPY_RULE_FILE)

            os.replace(COPY_RULE_FILE, PENDING_RULE_FILE)

    def view_ruleset(self, section='MAIN', version='pending'):
        '''returns dict of requested ruleset in raw form. additional processing is required for web ui
        or cli formats.

        args:

        section > will change which ruleset is returned.\n
        version > PENDING or ACTIVE rule tables.
        '''

        if (version not in self.versions):
            return None
            # raise ValueError(f'{version} is not a valid version.')

        if (section not in self.sections):
            return None
            # raise ValueError(f'{version} is not a valid section.')

        with ConfigurationManager(f'firewall_{version}', file_path=DEF_USR_PATH) as dnx_fw:
            firewall = dnx_fw.load_configuration()

            return firewall[section]


class FirewallControl:

    __slots__ = (
        'cfirewall', '_initialize',

        # firewall sections (heirarchy)
        # NOTE: these are used primarily to detect config changes to prevent
        # the amount of work/ data conversions that need to be done to load
        # the settings into C data structures.
        'BEFORE', 'MAIN', 'AFTER'
    )

    def __init__(self, *, cfirewall):
        self._initialize = Initialize(Log, 'FirewallControl')

        self.BEFORE = {}
        self.MAIN   = {}
        self.AFTER  = {}

        # reference to extension CFirewall, which handles nfqueue and initial packet rcv.
        # we will use this reference to modify firewall rules which will be internally accessed
        # by the inspection function callbacks
        self.cfirewall = cfirewall

    # threads will be started here. i want to keep the firewall rules here so it can return them easily
    # upon request AND NOTE: we may be able to get away with one way communication to firewall if we manage
    # the current settigs here. the only issue would be if they become unsynced somehow.
    def run(self):

        threading.Thread(target=self.monitor_zones).start()
        threading.Thread(target=self.monitor_rules).start()

        self._initialize.wait_for_threads(count=2)

    @cfg_read_poller('zone_map', alt_path='dnx_system/iptables/usr')
    # zone int values are arbritrary / randomly selected on zone creation.
    # TODO: see why this is making a second iteration
    def monitor_zones(self, fw_rules):
        '''calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython
        side or the Python interpreter will crash. Monitors the firewall zone file for changes and loads updates to
        cfirewall.'''

        dnx_zones = load_configuration(fw_rules, filepath='dnx_system/iptables/usr')

        # converting list to python array, then sending to Cython to modify C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones = array('i', dnx_zones['map'])

        print(f'sending zones to CFirewall: {dnx_zones}')

        # NOTE: gil must be aquired on the other side of this call
        error = self.cfirewall.update_zones(dnx_zones)
        if (error):
            pass # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall_active', alt_path='dnx_system/iptables/usr')
    def monitor_rules(self, fw_rules):
        '''calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython
        side or the Python interpreter will crash. Monitors the active firewall rules file for changes and loads
        updates to cfirewall.'''

        dnx_fw = load_configuration(fw_rules, filepath='dnx_system/iptables/usr')

        # splitting out sections then determine which one has changed. this is to reduce
        # amount of work done on the C side. not for performance, but more for ease of programming.
        for i, section in enumerate(['BEFORE', 'MAIN', 'AFTER']):
            current_section = getattr(self, section)
            new_section = dnx_fw[section]

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, section, new_section)

            # converting dict to list and each rule into a py array. this format is required due to
            # transitioning between python and C. python arrays are compatible in C via memory views
            # and Cython can handle the initial list.
            ruleset = [array('L', rule) for rule in new_section.values()]

            # NOTE: gil must be aquired on the other side of this call
            error = self.cfirewall.update_ruleset(i, ruleset)
            if (error):
                pass # TODO: do something here

        self._initialize.done()
