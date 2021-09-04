#!/usr/bin/env python3

import os, sys
import json
import threading

from array import array
# from socket import socket, AF_INET, SOCK_DGRAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import LOCALHOST
from dnx_configure.dnx_file_operations import cfg_read_poller, load_configuration, ConfigurationManager
from dnx_iptools.dnx_standard_tools import Initialize
from dnx_logging.log_main import LogHandler as Log

FW_CONTROL = 9001

ConfigurationManager.set_log_reference(Log)


class FirewallManage:
    '''intermediary between front end and underlying C firewall code.

    Front end <> FirewallManage <file monitoring> FirewallControl <> CFirewall

    firewall = FirewallManage()
    print(firewall.firewall)

    '''

    __slots__ = (
        'firewall',
    )

    def __init__(self):
        self.firewall = load_configuration('firewall', filepath='dnx_system/iptables')

    def add(self, pos, rule, *, section):
        '''insert or append operation of new firewall rule to the specified section.'''

        with ConfigurationManager('firewall', file_path='dnx_system/iptables') as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            if (pos > len(ruleset) + 1) or (pos < 1):
                raise ValueError(f'position {pos} is out of bounds.')

            # position is after last element so can add to end of dict directly.
            if (pos == len(ruleset) + 1):
                ruleset[pos] = rule

            # position falls somewhere within already allocated memory. using slices to split open position.
            else:
                temp_rules = list(ruleset.values())

                temp_rules = [*temp_rules[:pos], rule, *temp_rules[pos+1:]]

                # assigning section with new ruleset
                firewall[section] = {f'{i}': rule for i, rule in enumerate(temp_rules)}

            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

            return True

        return False

    def remove(self, pos, *, section):

        with ConfigurationManager('firewall', file_path='dnx_system/iptables') as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            if (not ruleset.pop(pos, None)):
                raise ValueError(f'unable to remove position {pos}.')

            firewall[section] = {f'{i}': rule for i, rule in enumerate(ruleset)}

            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

            return True

        return False

    def modify(self, pos, rule, *, section):
        '''send new definition of rule and rule position to underlying firewall to be updated.

            section (rule type): BEFORE, MAIN, AFTER (will likely be an enum)

        returns True if rule has been written to disk. NOTE: this doesnt mean lower system has
        put it into effect yet, only that it should be completed soon.

        '''

        with ConfigurationManager('firewall', file_path='dnx_system/iptables') as dnx_fw:
            firewall = dnx_fw.load_configuration()

            ruleset = firewall[section]

            # doing validation here for now just as a safety mechanism. this can likely be removed
            # later when the framework has matured.
            if (pos not in ruleset):
                raise ValueError(f'rule with position {pos} does not exist.')

            section[pos] = rule

            dnx_fw.write_configuration(firewall)

            # updating instance variable for direct access
            self.firewall = firewall

            return True

        return False


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

    @cfg_read_poller('zone_map', alt_path='dnx_system/iptables')
    # zone int values are arbritrary / randomly selected on zone creation.
    # TODO: see why this is making a second iteration
    def monitor_zones(self, fw_rules):
        '''calls to Cython are made from within this method block. the GIL must be manually
        aquired on the Cython side or the Python interpreter will crash.'''

        dnx_zones = load_configuration(fw_rules, filepath='dnx_system/iptables')

        # converting list to python array, then sending to Cython to modify C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones = array('i', dnx_zones)

        print(f'sending zones to CFirewall: {dnx_zones}')

        # NOTE: gil must be aquired on the other side of this call
        error = self.cfirewall.update_zones(dnx_zones)
        if (error):
            pass # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall', alt_path='dnx_system/iptables')
    def monitor_rules(self, fw_rules):
        '''calls to Cython are made from within this method block. the GIL must be manually
        aquired on the Cython side or the Python interpreter will crash.'''

        dnx_fw = load_configuration(fw_rules, filepath='dnx_system/iptables')

        # splitting out sections then determine which one has changed. this is to reduce
        # amount of work done on the C side. not for performance, but more for ease of programming.
        for i, section in enumerate(['BEFORE', 'MAIN', 'AFTER']):
            current_section = getattr(self, section)
            new_section = dnx_fw[section]

            # unchanged rulesets
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
