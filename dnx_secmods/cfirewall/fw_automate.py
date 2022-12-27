#!/usr/bin/env python3

from __future__ import annotations

import threading

from array import array

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import ppt
from dnx_gentools.standard_tools import Initialize
from dnx_gentools.file_operations import cfg_read_poller, load_configuration

from dnx_routines.logging.log_client import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T
    from dnx_secmods.cfirewall import CFirewall


# =========================================
# AUTOMATE - used within cfirewall process
# =========================================
class FirewallAutomate:
    __slots__ = (
        'log', 'cfirewall', '_initialize',

        # rule sections (hierarchy)
        'SYSTEM',

        'BEFORE', 'MAIN', 'AFTER',

        'PRE_ROUTE', 'POST_ROUTE'
    )

    def __init__(self, log: LogHandler_T, /, *, cfirewall: CFirewall):
        self.log = log

        self._initialize = Initialize(log, 'FirewallControl')

        self.SYSTEM: dict = {}
        self.BEFORE: dict = {}
        self.MAIN:   dict = {}
        self.AFTER:  dict = {}

        # nat rule groups
        self.PRE_ROUTE:  dict = {}
        self.POST_ROUTE: dict = {}

        # reference to extension CFirewall, which handles nfqueue and initial packet rcv. # we will use this
        # reference to modify rules objects which will be internally accessed by the inspection function callbacks
        self.cfirewall: CFirewall = cfirewall

    def print_active_rules(self):

        ppt(self.SYSTEM)
        ppt(self.BEFORE)
        ppt(self.MAIN)
        ppt(self.AFTER)

        # nat rule groups
        ppt(self.PRE_ROUTE)
        ppt(self.POST_ROUTE)

    # threads will be started and other basic setup functions will be done before releasing control back to the
    # inspection context.
    def run(self) -> None:

        threading.Thread(target=self._monitor_zones).start()
        threading.Thread(target=self._monitor_system_rules).start()
        threading.Thread(target=self._monitor_standard_rules).start()
        threading.Thread(target=self._monitor_nat_rules).start()

        self._initialize.wait_for_threads(count=4)

    @cfg_read_poller('zone', ext='firewall', filepath='dnx_profile/iptables')
    # zone int values are arbitrary / randomly selected on zone creation.
    def _monitor_zones(self, loaded_zones: ConfigChain) -> None:
        '''Monitors the firewall zone file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block.
        the GIL must be manually acquired on the Cython side or the Python interpreter will crash.
        '''
        # converting the list to a python array, then sending to Cython to update the C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones: list[list[int, str]] = loaded_zones['map']

        # NOTE: gil must be held on the other side of this call
        error: int = self.cfirewall.update_zones(dnx_zones)
        if (error):
            Log.error('Zone map update failure in CFirewall.')
        else:
            Log.notice('Zone map updated successfully.')

        self._initialize.done()

    @cfg_read_poller('system', ext='firewall', filepath='dnx_profile/iptables')
    def _monitor_system_rules(self, loaded_rules: ConfigChain) -> None:
        # 0-99: system reserved - 1. loopback 10/11. dhcp, 20/21. dns, 30/31. http, 40/41. https, etc
        #   - add loopback to system table
        # 100-1059: zone mgmt rules. 100s place designates interface index
        #   - 0/1: webui, 2: cli, 3: ssh, 4: ping
        #   - NOTE: int index will be used to do zone lookup. if zone changes, these will stop working and will need
        #       to be reset. this is ok for now since we only support builtin zones that can't change.
        # 2000+: system control (proxy bypass prevention)

        system_set = loaded_rules.get_values('BUILTIN')

        # including user configured system rules
        if user_configured := loaded_rules.get_values('USER'):
            system_set.extend(user_configured)

        # updating ruleset to reflect changes
        self.SYSTEM = loaded_rules.get_dict()

        self.log.notice('DNXFIREWALL system rule update job starting.')

        # NOTE: 0 is index of SYSTEM RULES
        table_type = 0

        error = self.cfirewall.update_rules(table_type, 0, system_set)
        if (error):
            Log.error(f'Rules section "SYSTEM" update failure in CFirewall.')
        else:
            Log.notice(f'Rule section "SYSTEM" updated successfully.')

        self._initialize.done()

    @cfg_read_poller('active', ext='firewall', filepath='dnx_profile/iptables')
    def _monitor_standard_rules(self, loaded_rules: ConfigChain) -> None:
        '''Monitors the active firewall rules file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block.
        the GIL must be manually acquired on the Cython side or the Python interpreter will crash.
        '''
        # checking each group for change to reduce C interaction.
        for table_idx, rule_group in enumerate(['BEFORE', 'MAIN', 'AFTER'], 1):

            current_section: dict = getattr(self, rule_group)
            new_section = loaded_rules.get_dict(rule_group)

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, rule_group, new_section)

            # converting section to a list of rules for easier manipulation in C.
            ruleset = [rule for rule in new_section.values()]

            self.log.notice(f'DNXFIREWALL {rule_group} rule update job starting.')

            table_type = 0 # temp

            error = self.cfirewall.update_rules(table_type, table_idx, ruleset)
            if (error):
                Log.error(f'FIREWALL rule group ({rule_group}) failed to update')
            else:
                Log.notice(f'FIREWALL rule group ({rule_group}) updated successfully.')

        self._initialize.done()

    @cfg_read_poller('active', ext='nat', filepath='dnx_profile/iptables')
    def _monitor_nat_rules(self, loaded_rules: ConfigChain) -> None:
        '''Monitors the active firewall rules file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block.
        the GIL must be manually acquired on the Cython side or the Python interpreter will crash.
        '''
        # checking each group for change to reduce C interaction.
        for table_idx, rule_group in enumerate(['PRE_ROUTE', 'POST_ROUTE']):

            current_section: dict = getattr(self, rule_group)
            new_section = loaded_rules.get_dict(rule_group)

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, rule_group, new_section)

            # converting section to a list of rules for easier manipulation in C.
            ruleset = [rule for rule in new_section.values()]

            self.log.notice(f'DNXFIREWALL NAT {rule_group} rule update job starting.')

            table_type = 1 # temp

            # NOTE: gil must be held throughout this call
            error = self.cfirewall.update_rules(table_type, table_idx, ruleset)
            if (error):
                Log.error(f'NAT rule group ({rule_group}) failed to update')
            else:
                Log.notice(f'NAT rule group ({rule_group}) updated successfully.')

        self._initialize.done()
