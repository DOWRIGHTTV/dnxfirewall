#!/usr/bin/env python3

from __future__ import annotations

import threading

from array import array

from dnx_gentools.def_constants import MSB, LSB
from dnx_gentools.def_typing import *

from dnx_gentools.standard_tools import Initialize
from dnx_gentools.signature_operations import generate_geolocation
from dnx_gentools.file_operations import cfg_read_poller, load_configuration

# ========================================
# CONTROL - used within cfirewall process
# ========================================
class FirewallControl:
    __slots__ = (
        'log', 'cfirewall', '_initialize',

        # rules sections (hierarchy)
        # NOTE: these are used primarily to detect config changes to prevent the amount of work/ data conversions that
        #  need to be done to load the settings into C data structures.
        'BEFORE', 'MAIN', 'AFTER'
    )

    def __init__(self, Log: Type[LogHandler], /, *, cfirewall: CFirewall):
        self.log = Log

        self._initialize = Initialize(Log, 'FirewallControl')

        self.BEFORE: dict = {}
        self.MAIN:   dict = {}
        self.AFTER:  dict = {}

        # reference to extension CFirewall, which handles nfqueue and initial packet rcv. # we will use this
        # reference to modify rules objects which will be internally accessed by the inspection function callbacks
        self.cfirewall = cfirewall

    # threads will be started and other basic setup functions will be done before releasing control back to the
    # inspection context.
    def run(self) -> None:

        # generating py_trie for geolocation signatures, cfirewall will initialize the extension natively
        geo_trie: tuple = generate_geolocation(self.log)

        self.cfirewall.prepare_geolocation(geo_trie, MSB, LSB)

        threading.Thread(target=self._monitor_system_rules).start()
        threading.Thread(target=self._monitor_zones).start()
        threading.Thread(target=self._monitor_standard_rules).start()

        self._initialize.wait_for_threads(count=3)

    @cfg_read_poller('zone_map', folder='iptables')
    # zone int values are arbitrary / randomly selected on zone creation.
    def _monitor_zones(self, zone_map: str) -> None:
        '''Monitors the firewall zone file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython side
        or the Python interpreter will crash.'''

        loaded_zones: ConfigChain = load_configuration(zone_map, filepath='dnx_system/iptables')

        # converting list to python array, then sending to Cython to modify C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones: array[int] = array('i', loaded_zones.get_list('map'))

        # NOTE: gil must be held on the other side of this call
        error: int = self.cfirewall.update_zones(dnx_zones)
        if (error):
            pass  # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall_active', folder='iptables')
    def _monitor_standard_rules(self, fw_rules: str):
        '''Monitors the active firewall rules file for changes and loads updates to cfirewall.

        calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython
        side or the Python interpreter will crash. '''

        dnx_fw: ConfigChain = load_configuration(fw_rules, filepath='dnx_system/iptables')

        # splitting out sections then determine which one has changed. this is to reduce amount of work done on the C
        # side. not for performance, but more for ease of programming.
        # NOTE: index 1 start is needed because SYSTEM rules are held at index 0.
        for i, section in enumerate(['BEFORE', 'MAIN', 'AFTER'], 1):
            current_section: dict = getattr(self, section)
            new_section: dict = dnx_fw.get_dict(section)

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, section, new_section)

            # converting section to list of rules for easier manipulation in C.
            ruleset: list = [rule for rule in new_section.values()]

            # NOTE: gil must be held throughout this call
            error = self.cfirewall.update_ruleset(i, ruleset)
            if (error):
                pass  # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall_system', folder='iptables')
    def _monitor_system_rules(self, system_rules: str):
        # 0-99: system reserved - 1. loopback 10/11. dhcp, 20/21. dns, 30/31. http, 40/41. https, etc
        #   - loopback will be left in iptables for now
        # 100-1059: zone mgmt rules. 100s place designates interface index
        #   - 0/1: webui, 2: cli, 3: ssh, 4: ping
        #   - NOTE: int index will be used to do zone lookup. if zone changes, these will stop working and would need
        #       to be reset. this is ok for now since we only support builtin zones that can't change.
        # 2000+: system control (proxy bypass prevention)

        rulesets: ConfigChain = load_configuration(system_rules, filepath='dnx_system/iptables')

        ruleset: list = [rule for rule in rulesets.get_values('BUILTIN')]

        # NOTE: gil must be held throughout this call. 0 is index of SYSTEM RULES
        error = self.cfirewall.update_ruleset(0, ruleset)
        if (error):
            pass  # TODO: do something here

        self._initialize.done()
