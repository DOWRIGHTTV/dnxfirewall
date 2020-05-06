#!/usr/bin/env python3

import os, sys
import json
import time
import threading

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_system_info import Interface
from dnx_iptools.dnx_standard_tools import looper, dynamic_looper, Initialize
from dnx_configure.dnx_file_operations import load_configuration, cfg_read_poller
from dnx_configure.dnx_iptables import IPTableManager
from dnx_ips.dnx_ips_log import Log


class Configuration:
    _setup = False

    def __init__(self, name):
        self.initialize  = Initialize(Log, name)
        self._cfg_change = threading.Event()

    @classmethod
    def setup(cls, IPS):
        if (cls._setup):
            raise RuntimeError('configuration setup should only be called once.')
        cls._setup = True

        self = cls(IPS.__name__)
        self.IPS = IPS

        self._load_interfaces()
        self._manage_ip_tables()
        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._get_open_ports).start()
        threading.Thread(target=self._ip_whitelist).start()
        threading.Thread(target=self._update_system_vars).start()

        self.initialize.wait_for_threads(count=4)

        threading.Thread(target=self._clear_ip_tables).start()

    def _manage_ip_tables(self):
        IPTableManager.purge_proxy_rules(table='mangle', chain='IPS')

    def _load_interfaces(self):
        interface = load_configuration('config.json')

        self.IPS.wan_int = interface['settings']['interfaces']['wan']

        self.IPS.broadcast = Interface.broadcast_address(self.IPS.wan_int['ident'])

    @cfg_read_poller('ips')
    def _get_settings(self, cfg_file):
#        print('[+] Starting: IPS Settings Update Thread.')
        ips = load_configuration(cfg_file)['ips']

        self.IPS.ddos_prevention     = ips['ddos']['enabled']
        self.IPS.portscan_prevention = ips['port_scan']['drop']

        # ddos CPS THRESHHOLD CHECK
        tcp_src_limit  = ips['ddos']['limits']['source']['tcp']
        udp_src_limit  = ips['ddos']['limits']['source']['udp']
        icmp_src_limit = ips['ddos']['limits']['source']['icmp']
        self.IPS.connection_limits = {
            PROTO.ICMP: icmp_src_limit,
            PROTO.TCP: tcp_src_limit,
            PROTO.UDP: udp_src_limit
        }

        ##Checking length(hours) to leave IP Table Rules in place for hosts part of ddos attacks
        self.IPS.block_length = 0
        if (self.IPS.portscan_prevention or self.IPS.ddos_prevention):
            self.IPS.block_length = ips['passive_block_ttl'] * 3600

        ## Reject packet (tcp reset and icmp port unreachable)
        self.IPS.portscan_reject = ips['port_scan']['reject']

        ## whitelist configured dns servers (local instance var)
        self.whitelist_dns_servers = ips['whitelist']['dns_servers']

        self._cfg_change.set()
        self.initialize.done()

    # NOTE: determine whether default sleep timer is acceptible for this method. if not, figure out how to override
    # the setting set in the decorator or remove the decorator entirely.
    @cfg_read_poller('ips')
    def _get_open_ports(self, cfg_file):
        ips_settings = load_configuration(cfg_file)

        ips = ips_settings['ips']
        open_tcp_ports = ips['open_protocols']['tcp']
        open_udp_ports = ips['open_protocols']['udp']
        self.IPS.open_ports = {
            PROTO.TCP: {int(local_port): int(wan_port) for wan_port, local_port in open_tcp_ports.items()},
            PROTO.UDP: {int(local_port): int(wan_port) for wan_port, local_port in open_udp_ports.items()}
        }

        self._cfg_change.set()
        self.initialize.done()

    @cfg_read_poller('ips')
    def _ip_whitelist(self, cfg_file):
        whitelist = load_configuration(cfg_file)

        ip_whitelist = set(whitelist['ips']['whitelist']['ip_whitelist'])
        if (self.whitelist_dns_servers):
            dns_servers_settings = load_configuration('dns_server.json')

            dns_servers = dns_servers_settings['dns_server']
            dns1 = dns_servers['resolvers']['server1']['ip_address']
            dns2 = dns_servers['resolvers']['server2']['ip_address']

            self.IPS.ip_whitelist = ip_whitelist.union({dns1, dns2})
        else:
            self.IPS.ip_whitelist = ip_whitelist

        self._cfg_change.set()
        self.initialize.done()

    @looper(NO_DELAY)
    def _update_system_vars(self):
        # waiting for any thread to report a change in configuration.
        self._cfg_change.wait()

        #resetting the config change event.
        self._cfg_change.clear()

        open_ports = any([self.IPS.open_ports[PROTO.TCP], self.IPS.open_ports[PROTO.UDP]])
        if (self.IPS.ddos_prevention or
                (self.IPS.portscan_prevention and open_ports)):
            self.IPS.ins_engine_enabled = True
        else:
            self.IPS.ins_engine_enabled = False

        if (self.IPS.portscan_prevention and open_ports):
            self.IPS.ps_engine_enabled = True
        else:
            self.IPS.ps_engine_enabled = False

        if (self.IPS.ddos_prevention):
            self.IPS.ddos_engine_enabled = True
        else:
            self.IPS.ddos_engine_enabled = False

        self.initialize.done()

    @dynamic_looper
    def _clear_ip_tables(self):
        ips_to_remove = []
        if (self.IPS.active_ddos or not self.IPS.ddos_prevention): return ONE_MIN

        now = time.time()
        for tracked_ip, rule_info in self.IPS.fw_rules.items():
            time_added = rule_info['timestamp']
            if (now - time_added < self.IPS.block_length): continue

            ips_to_remove.append(tracked_ip)

        if (not ips_to_remove): return FIVE_MIN

        with IPTableManager() as iptables:
            for tracked_ip in ips_to_remove:
                if not self.IPS.fw_rules.pop(tracked_ip, None): continue

                iptables.proxy_del_rule(tracked_ip, table='mangle', chain='IPS')

        return FIVE_MIN
