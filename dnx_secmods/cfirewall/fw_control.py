#!/usr/bin/env python3

import threading

from array import array

from dnx_gentools.def_constants import MSB, LSB
from dnx_gentools.standard_tools import Initialize
from dnx_gentools.signature_operations import generate_geolocation
from dnx_gentools.file_operations import cfg_read_poller, load_configuration

from dnx_routines.logging.log_client import LogHandler as Log

# ========================================
# CONTROL - used within cfirewall process
# ========================================

class FirewallControl:
    __slots__ = (
        'cfirewall', '_initialize',

        # firewall sections (hierarchy)
        # NOTE: these are used primarily to detect config changes to prevent the amount of work/ data conversions that
        # need to be done to load the settings into C data structures.
        'BEFORE', 'MAIN', 'AFTER'
    )

    def __init__(self, Log, /, *, cfirewall):
        self._initialize = Initialize(Log, 'FirewallControl')

        self.BEFORE = {}
        self.MAIN = {}
        self.AFTER = {}

        # reference to extension CFirewall, which handles nfqueue and initial packet rcv. # we will use this
        # reference to modify firewall objects which will be internally accessed by the inspection function callbacks
        self.cfirewall = cfirewall

    # threads will be started and other basic setup functions will be done before releasing control back to the
    # inspection context.
    def run(self):

        # generating py_trie for geolocation signatures, cfirewall will initialize the extension natively
        geo_trie = generate_geolocation(Log)

        self.cfirewall.prepare_geolocation(geo_trie, MSB, LSB)

        threading.Thread(target=self._monitor_system_rules).start()
        threading.Thread(target=self._monitor_zones).start()
        threading.Thread(target=self._monitor_standard_rules).start()

        self._initialize.wait_for_threads(count=3)

    @cfg_read_poller('zone_map', folder='iptables')
    # zone int values are arbitrary / randomly selected on zone creation.
    def _monitor_zones(self, zone_map):
        '''calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython
        side or the Python interpreter will crash. Monitors the firewall zone file for changes and loads updates to
        cfirewall.'''

        dnx_zones = load_configuration(zone_map, filepath='dnx_system/iptables')

        # converting list to python array, then sending to Cython to modify C array.
        # this format is required due to transitioning between python and C. python arrays are
        # compatible in C via memory views and Cython can handle the initial list.
        dnx_zones = array('i', dnx_zones['map'])

        # NOTE: gil must be held on the other side of this call
        error = self.cfirewall.update_zones(dnx_zones)
        if (error):
            pass  # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall_active', folder='iptables')
    def _monitor_standard_rules(self, fw_rules):
        '''calls to Cython are made from within this method block. the GIL must be manually acquired on the Cython
        side or the Python interpreter will crash. Monitors the active firewall rules file for changes and loads
        updates to cfirewall.'''

        dnx_fw = load_configuration(fw_rules, filepath='dnx_system/iptables')

        # splitting out sections then determine which one has changed. this is to reduce amount of work done on the C
        # side. not for performance, but more for ease of programming.
        # NOTE: index 1 start is needed because SYSTEM rules are held at index 0.
        for i, section in enumerate(['BEFORE', 'MAIN', 'AFTER'], 1):
            current_section = getattr(self, section)
            new_section = dnx_fw[section]

            # unchanged ruleset
            if (current_section == new_section): continue

            # updating ruleset to reflect changes
            setattr(self, section, new_section)

            # converting dict to list and each rule into a list of PyArrays. this format is required due to
            # transitioning between python and C. python arrays are compatible in C via memory views and Cython can
            # handle the initial list.
            # ruleset = self._format_rules(new_section.values())
            ruleset = [rule for rule in new_section.values()]

            # NOTE: gil must be held throughout this call
            error = self.cfirewall.update_ruleset(i, ruleset)
            if (error):
                pass  # TODO: do something here

        self._initialize.done()

    @cfg_read_poller('firewall_system', folder='iptables')
    def _monitor_system_rules(self, system_rules):
        # 0-99: system reserved - 1. loopback 10/11. dhcp, 20/21. dns, 30/31. http, 40/41. https, etc
        #   - loopback will be left in iptables for now
        # 100-1059: zone mgmt rules. 100s place designates interface index
        #   - 0/1: webui, 2: cli, 3: ssh, 4: ping
        #   - NOTE: int index will be used to do zone lookup. if zone changes, these will stop working and would need
        #       to be reset. this is ok for now since we only support builtin zones that can't change.
        # 2000+: system control (proxy bypass prevention)

        ruleset = load_configuration(system_rules, filepath='dnx_system/iptables')['BUILTIN']

        # ruleset = self._format_rules(ruleset.values())
        ruleset = [rule for rule in ruleset.values()]

        # NOTE: gil must be held throughout this call. 0 is index of SYSTEM RULES
        error = self.cfirewall.update_ruleset(0, ruleset)
        if (error):
            pass  # TODO: do something here

        self._initialize.done()
