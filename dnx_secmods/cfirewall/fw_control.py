#!/usr/bin/env python3

import threading

from array import array

from dnx_gentools.def_constants import MSB, LSB
from dnx_gentools.standard_tools import Initialize
from dnx_gentools.signature_operations import generate_geolocation
from dnx_gentools.file_operations import cfg_read_poller, load_configuration

from dnx_routines.logging.log_main import LogHandler as Log

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

    @staticmethod
    # TODO: figure out a way to merge each object to a single PyArray making only 4 needed.
    # TODO: this method is assuming that the fw objects are already converted from id to definition. make sure this
    #  is dealt with somewhere.
    def _format_rules(section_rules, /):
        '''converts dictionary representation of firewall rules to PyArrays. each rule is contained within a list
        with each rule field type having its own PyArray (7 total per rule).'''

        ruleset = []
        ruleset_append = ruleset.append

        for rule in section_rules:
            rule_get = rule.get

            flag_array = array('B', [rule_get(x) for x in ['enabled', 'action', 'log', 'ipp_profile', 'ips_profile']])
            s_zone_array = array('B', [x for x in rule_get('src_zone')])
            d_zone_array = array('B', [x for x in rule_get('dst_zone')])

            s_net_array = array('L')
            for net in rule_get('src_network'):
                s_net_array.extend(net)

            d_net_array = array('L')
            for net in rule_get('dst_network'):
                d_net_array.extend(net)

            s_svc_array = array('H')
            for svc in rule_get('src_service'):
                s_svc_array.extend(svc)

            d_svc_array = array('H')
            for svc in rule_get('dst_service'):
                d_svc_array.extend(svc)

            ruleset_append([
                flag_array,
                s_zone_array, s_net_array, s_svc_array,
                d_zone_array, d_net_array, d_svc_array
            ])

        return ruleset
