#!/usr/bin/env python3

from __future__ import annotations

import threading

from array import array

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import MSB, LSB, ppt
from dnx_gentools.standard_tools import Initialize
from dnx_gentools.signature_operations import generate_geolocation
from dnx_gentools.file_operations import cfg_read_poller, load_configuration

from dnx_routines.logging import Log

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

        'NAT'
    )

    def __init__(self, log: LogHandler_T, /, *, cfirewall: CFirewall):
        self.log = log

        self._initialize = Initialize(log, 'FirewallControl')

        self.SYSTEM: dict = {}
        self.BEFORE: dict = {}
        self.MAIN:   dict = {}
        self.AFTER:  dict = {}
        self.NAT:    dict = {}

        # reference to extension CFirewall, which handles nfqueue and initial packet rcv. # we will use this
        # reference to modify rules objects which will be internally accessed by the inspection function callbacks
        self.cfirewall: CFirewall = cfirewall

    def print_active_rules(self):

        ppt(self.SYSTEM)
        ppt(self.BEFORE)
        ppt(self.MAIN)
        ppt(self.AFTER)
        ppt(self.NAT)

    # threads will be started and other basic setup functions will be done before releasing control back to the
    # inspection context.
    def run(self) -> None:

        # generating py_trie for geolocation signatures, cfirewall will initialize the extension natively
        geo_trie: list = generate_geolocation(self.log)

        self.cfirewall.prepare_geolocation(geo_trie, MSB, LSB)

        threading.Thread(target=self._monitor_system_rules).start()
        threading.Thread(target=self._monitor_zones).start()
        threading.Thread(target=self._monitor_standard_rules).start()

        self._initialize.wait_for_threads(count=3)

    @cfg_read_poller('zone', ext='firewall', folder='iptables')
    # zone int values are arbitrary / randomly selected on zone creation.
    def _monitor_zones(self, zone_map: str) -> None:
        '''Monitors the firewall zone file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block.
        the GIL must be manually acquired on the Cython side or the Python interpreter will crash.
        '''
        loaded_zones: ConfigChain = load_configuration(zone_map, ext='firewall', filepath='dnx_system/iptables')

        # converting the list to a python array, then sending to Cython to update the C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones: array[int] = array('i', loaded_zones['map'])

        # NOTE: gil must be held on the other side of this call
        error: int = self.cfirewall.update_zones(dnx_zones)
        if (error):
            Log.error('Zone map update failure in CFirewall.')
        else:
            Log.notice('Zone map updated successfully.')

        self._initialize.done()

    @cfg_read_poller('active', ext='firewall', folder='iptables')
    def _monitor_standard_rules(self, fw_rules: str):
        '''Monitors the active firewall rules file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block.
        the GIL must be manually acquired on the Cython side or the Python interpreter will crash.
        '''
        loaded_rules: ConfigChain = load_configuration(fw_rules, ext='firewall', filepath='dnx_system/iptables')

        # splitting out sections then determine which one has changed.
        # NOTE: index 1 start is needed because SYSTEM rules are held at index 0.
        for i, section in enumerate(['BEFORE', 'MAIN', 'AFTER'], 1):
            current_section: dict = getattr(self, section)
            new_section: dict = loaded_rules.get_dict(section)

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, section, new_section)

            # converting section to a list of rules for easier manipulation in C.
            ruleset: list = [rule for rule in new_section.values()]

            self.log.notice(f'DNXFIREWALL {section} rule update job starting.')

            # NOTE: gil must be held throughout this call
            error = self.cfirewall.update_ruleset(i, ruleset)
            if (error):
                Log.error(f'Rules section "{section}" update failure in CFirewall')
            else:
                Log.notice(f'Rule section "{section}" updated successfully.')

        self._initialize.done()

    @cfg_read_poller('system', ext='firewall', folder='iptables')
    def _monitor_system_rules(self, system_rules: str):
        # 0-99: system reserved - 1. loopback 10/11. dhcp, 20/21. dns, 30/31. http, 40/41. https, etc
        #   - add loopback to system table
        # 100-1059: zone mgmt rules. 100s place designates interface index
        #   - 0/1: webui, 2: cli, 3: ssh, 4: ping
        #   - NOTE: int index will be used to do zone lookup. if zone changes, these will stop working and will need
        #       to be reset. this is ok for now since we only support builtin zones that can't change.
        # 2000+: system control (proxy bypass prevention)

        loaded_rules: ConfigChain = load_configuration(system_rules, ext='firewall', filepath='dnx_system/iptables')

        system_set: list = loaded_rules.get_values('BUILTIN')

        # updating ruleset to reflect changes
        self.SYSTEM = loaded_rules.get_dict()

        self.log.notice('DNXFIREWALL system rule update job starting.')

        # NOTE: gil must be held throughout this call. 0 is index of SYSTEM RULES
        error = self.cfirewall.update_ruleset(0, system_set)
        if (error):
            Log.error(f'Rules section "SYSTEM" update failure in CFirewall.')
        else:
            Log.notice(f'Rule section "SYSTEM" updated successfully.')

        self._initialize.done()
