#!/usr/bin/python3

import os, sys
import time, threading
import json
import traceback
import asyncio

from datetime import datetime
from subprocess import Popen
from types import SimpleNamespace as SName

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_ips.dnx_ips_sniffer import IPSSniffer
from dnx_ips.dnx_ips_response import ScanResponse
from dnx_ips.dnx_ips_automated import Automate
from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_logging.log_main import LogHandler
from dnx_syslog.syl_main import SyslogHandler

LOG_MOD = 'ips'
SYSLOG_MOD = 'IPS'


class IPSProxy:
    def __init__(self):
        self.udp_scan_tracker = {}
        self.tcp_scan_tracker = {}
        self.udp_active_scan = {}
        self.tcp_active_scan = {}

        self.fw_rules = {}
        self.ip_whitelist = {}

        self.tcp_ddos_tracker = {}
        self.udp_ddos_tracker = {}
        self.icmp_ddos_tracker = {}
        self.active_ddos = False
        self.block_length = 0

        self.fw_rule_creation_lock = threading.Lock()
        self.scan_tracker_lock = threading.Lock()
        self.ddos_counter_lock = threading.Lock()

        self.protocol_conversion = {TCP: 'tcp', UDP: 'udp', ICMP: 'icmp'}

        self.ddos_prevention = False
        self.portscan_prevention = False
        self.portscan_reject = False
        self.syslog_enabled = False
        self.icmp_allow = False
        self.logging_level = 0

    def Start(self):
        self.LoadInterfaces()

        self.Automate = Automate(self)
        self.Log = LogHandler(self)
        self.Syslog = SyslogHandler(self)

        Sniffer = IPSSniffer(self)
        # True boolean notifies thread that it was the initial start and to minimize sleep time
        threading.Thread(target=Sniffer.Start, args=(True,)).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    def SignatureCheck(self, packet, connection_type):
        timestamp = time.time()
        add_to_tracker = False

        str_proto = self.protocol_conversion[packet.protocol]
        if (packet.protocol != ICMP):
            open_ports = getattr(self, f'open_{str_proto}_ports')

        ## if source ip is in the whitelist, it will not be added to the DDOS tracker or be check as a potential port scanner
        if (packet.src_ip in self.ip_whitelist or packet.dst_ip in self.ip_whitelist):
            pass

        elif (packet.protocol == ICMP and self.icmp_allow):
            add_to_tracker = True

        elif (connection_type == INITIAL and packet.dst_port in open_ports):
            add_to_tracker = True

        ## if an above condition is met, a counter will be added to corresponsing tracker to determine PPS in another thread
        if (add_to_tracker):
            ddos_tracker = getattr(self, f'{str_proto}_ddos_tracker')
            # lock to ensure packet counts remain accurate between all threads
            with self.ddos_counter_lock:
                tracked = ddos_tracker.get(packet.src_ip, None)
                if (not tracked):
                    ddos_tracker.update({packet.src_ip: {'count': 1, 'timestamp': time.time()}})
                else:
                    count = tracked['count'] + 1
                    ddos_tracker[packet.src_ip].update({'count': count})

        # will prevent packet from being inspected if it is either icmp (no ports to scan) or if an ddos is currently active to
        # give more system resources to dealing with the ddos
        if (not self.active_ddos):
            self.PortScan(packet, connection_type, timestamp)

    def PortScan(self, packet, connection_type, timestamp):
        attack_type = PORTSCAN
        connection_log = False
        scan_detected = False
        active_block = False
        already_blocked = False
        block_status = None

        if (packet.src_ip != self.wan_ip):
            direction = INBOUND
            tracked_ip = packet.src_ip
            tracked_port = packet.src_port
            local_port = packet.dst_port

        elif (packet.src_ip == self.wan_ip):
            direction = OUTBOUND
            tracked_ip = packet.dst_ip
            tracked_port = packet.dst_port
            local_port = packet.src_port

        ## Main Detection Logic
        proto = self.protocol_conversion[packet.protocol]
        active_scan = getattr(self, f'{proto}_active_scan')
        scan_tracker = getattr(self, f'{proto}_scan_tracker')
        if (direction == INBOUND and tracked_ip in active_scan):
            active_scan[tracked_ip] = timestamp
            scan_detected = True
            with self.scan_tracker_lock:
                if (local_port not in scan_tracker[tracked_ip]['target']):
                    scan_tracker[tracked_ip]['target'].update({local_port: False})

        # will match if packet is a tcp syn and the source ip is not the wan ip (iniated from external ip)
        elif (connection_type == INITIAL):
            # if first time the source ip is seen, it will add ip to dictionary
            try:
                count = scan_tracker[tracked_ip]['source'].get(tracked_port, 0) + 1
            except KeyError:
                scan_tracker[tracked_ip] = {'source': {}, 'target': {}}
                count = 1

            scan_tracker[tracked_ip]['source'].update({tracked_port: count})
            scan_tracker[tracked_ip]['target'].update({local_port: False})

            connections = scan_tracker.get(tracked_ip)['target']
            if (count >= 2 or len(connections) >= 3) or (packet.protocol == UDP and not packet.udp_payload):
                active_scan[tracked_ip] = timestamp
                active_block = True
                scan_detected = True

#            print(f'INCREMENTED | {tracked_ip}: {tracked_port} > {count} | {local_port}')

        # will match if wan ip is responding to a tcp stream being initiated
        elif (connection_type == RESPONSE):
            try:
                open_ports = getattr(self, f'open_{proto}_ports')
                if (direction == OUTBOUND and local_port in open_ports):
                    print(f'{proto.upper()} PORT RESPONSE: {timestamp}')
                    scan_tracker[tracked_ip]['target'].update({local_port: True})

            except KeyError:
                # maybe log? seeing stream without seeing the initial connection being established
                pass
            except Exception:
                traceback.print_exc()

        ## Proxy decision logic
        if (self.portscan_prevention):
            ## applying lock on firewall rule dictionary lookup due to the small chance 2 threads check before either
            # can add the key to the dictionary to prevent duplicate rules and timeout method calls
            initial_block = False
            with self.fw_rule_creation_lock:
                if (active_block and tracked_ip not in self.fw_rules):
                    self.fw_rules.update({tracked_ip: timestamp})
                    initial_block = True
            # will mark the scan as dropped on the initial block condition (this will prevent multiple logs being sent)
            if (initial_block):
                Popen(f'sudo iptables -t mangle -A IPS -s {tracked_ip} -j DROP && \
                        sudo iptables -t mangle -A IPS -d {tracked_ip} -j DROP', shell=True)
                print(f'RULE INSERTED: {tracked_ip} > {tracked_port} | {time.time()}')
                ## will create a timeout thread to ensure firewall is removed if no persistence is configured or to remove
                # the ip from the scan tracker as well as the active scan dictionary
                threading.Thread(target=self.ConnectionTimeout, args=(tracked_ip, packet.protocol)).start()

                block_status = self.ResponseTracker(tracked_ip, packet.protocol)

            elif (active_block):
                already_blocked = True

            # if portscan is detected and user configured to reject, corresponding messages will be sent as a response to the scan
            if (self.portscan_reject and scan_detected):
                if (packet.protocol == TCP):
                    TCPPacket = ScanResponse(self.wan_int, packet, protocol=TCP)
                    TCPPacket.Response()
                elif (packet.protocol == UDP):
                    ICMPPacket = ScanResponse(self.wan_int, packet, protocol=UDP)
                    ICMPPacket.Response()

        # logging logic
        if (active_block and block_status == MISSED and self.logging_level >= WARNING):
            action = 'missed'
            connection_log = True

            print(f'MISSED BLOCK: {tracked_ip}')

        elif (active_block and block_status == BLOCKED and self.logging_level >= NOTICE):
            action = 'blocked'
            connection_log = True

            print(f'ACTIVE BLOCK: {tracked_ip}')

        ## add a not already blocked to ensure this doesnt get logged alot
        elif (scan_detected and not already_blocked and self.logging_level >= INFORMATIONAL):
            action = 'logged'
            connection_log = True

        if (connection_log):
            logging_options = {'ip': tracked_ip, 'protocol': packet.protocol,
                                'attack_type': attack_type, 'action': action}
            self.Logging(timestamp, logging_options)

    ## after not seeing a tracked ip for 3 seconds, they will be removed from all trackers and the iptable rule
    # will be removed if the user has not configured a persistant blocking time
    def ConnectionTimeout(self, tracked_ip, protocol):
        proto = self.protocol_conversion[protocol]
        active_scan = getattr(self, f'{proto}_active_scan')
        scan_tracker = getattr(self, f'{proto}_scan_tracker')
        while True:
            now = time.time()
            last_scan = active_scan.get(tracked_ip, None)
            if (last_scan and now - last_scan >= 3):
                scan_tracker.pop(tracked_ip, None)
                active_scan.pop(tracked_ip, None)
                print(f'TIMED OUT SCANNER {tracked_ip}')

                if (self.block_length == 0):
                    Popen(f'sudo iptables -t mangle -D IPS -s {tracked_ip} -j DROP && \
                            sudo iptables -t mangle -D IPS -d {tracked_ip} -j DROP', shell=True)
                    print(f'REMOVED FW RULE FOR {tracked_ip}')
                    self.fw_rules.pop(tracked_ip, None)

                break
            time.sleep(1.6)

    ## this function will wait for 1 second after seeing a local ip respond to a tcp syn. if the tracked ip
    # does not send a subsequent ack within 1 second, they are inserted into the active scan dictionary
    def ResponseTracker(self, tracked_ip, protocol):
        blocked_status = True
        missed_ports = set()
        time.sleep(2)

        protocol = self.protocol_conversion[protocol]
        open_ports = getattr(self, f'open_{protocol}_ports')
        scan_tracker = getattr(self, f'{protocol}_scan_tracker')
        for port in open_ports:
            response = scan_tracker[tracked_ip]['target'].get(port, None)
            if (response):
                missed_ports.add(port)

        if (missed_ports):
            blocked_status = False

        return blocked_status

    def Logging(self, timestamp, logging_options):
        ProxyDB = DBConnector(table='ips')
        ProxyDB.Connect()
        ProxyDB.IPSInput(timestamp, logging_options)
        ProxyDB.Disconnect()

        if (self.syslog_enabled):
            self.AlertSyslog(logging_options)

    def AlertSyslog(self, logging_options):
        opt = SName(**logging_options)

        if (opt.attack_type == DDOS):
            msg_level = ALERT
        elif (opt.attack_type == PORTSCAN):
            if (opt.action == 'logged'):
                msg_level = INFORMATIONAL
            elif (opt.action == 'blocked'):
                msg_level = NOTICE
            elif (opt.action == 'missed'):
                msg_level = WARNING

        message = f'src.ip={opt.ip}; protocol={opt.protocol}; attack_type={opt.attack_type}; action={opt.action}'
        self.Syslog.Message(EVENT, msg_level, message)

    def LoadInterfaces(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)

        self.lan_int = self.setting['settings']['interface']['inside']
        self.wan_int = self.setting['settings']['interface']['outside']

        Int = Interface()
        self.wan_ip = Int.IP(self.wan_int)
        self.broadcast = Int.Broadcast(self.wan_int)

    # AsyncIO method called to gather automated/ continuous methods | this is python 3.7 version of async
    async def Main(self):
        await asyncio.gather(self.Automate.DDOSCalculation(), self.Automate.ClearIPTables(),
                            self.Automate.IPSSettings(), self.Automate.IPWhitelist(),
                            self.Log.Settings(LOG_MOD), self.Syslog.Settings(SYSLOG_MOD))

                            #CALL LOG QUEUE MAYBE. THIS IS A THREADED MODULE

if __name__ == '__main__':
    DNSP = IPSProxy()
    DNSP.Start()
