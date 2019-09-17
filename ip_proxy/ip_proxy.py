#!/usr/bin/python3

import os, sys
import time
import threading
import asyncio
import json

from datetime import datetime
from subprocess import Popen
from types import SimpleNamespace as SName

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from ip_proxy.ip_proxy_sniffer import IPSniffer
from ip_proxy.ip_proxy_timer import IPTimer as TM
from ip_proxy.ip_proxy_automate import Automate
from dnx_configure.dnx_system_info import System, Interface
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_db_connector import DBConnector
from dnx_logging.log_main import LogHandler
from dnx_syslog.syl_main import SyslogHandler

SYSLOG_MOD = 'IPProxy'
LOG_MOD = 'ip_proxy'


class IPProxy:
    def __init__(self):
        self.fw_rules = {}
        self.ip_signatures = {}
        self.open_tcp_ports = set()
        self.open_udp_ports = set()

        self.inbound_session_tracker = {}
        self.outbound_session_tracker = {}

        self.tcp_session_tracker = {}

        self.fw_rule_creation_lock = threading.Lock()

        self.block_settings = {'malware': 'mal_block', 'compromised': 'mal_block',
                                'entry': 'tor_block', 'exit': 'tor_block'}
        self.chain_settings = {'malware': 'MALICIOUS', 'compromised': 'MALICIOUS',
                                'entry': 'TOR', 'exit': 'TOR'}

        # var initialization to give proxy time to load correct settings
        self.tor_entry_block = False
        self.tor_exit_block = False
        self.malware_block = False
        self.compromised_block = False
        self.syslog_enabled = False
        self.logging_level = 0

    def Start(self):
        self.LoadInterfaces()

        self.Log = LogHandler(self)
        self.Syslog = SyslogHandler(self)
        self.Automate = Automate(self)

        ListFile = ListFiles()
        ListFile.CombineIPs()

        self.Timer = TM()
        self.LoadSignatures()

        Sniffer = IPSniffer(self)
        # True boolean notifies thread that it was the initial start and to minimize sleep time
        threading.Thread(target=Sniffer.Start, args=(True,)).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    def SignatureCheck(self, packet):
        timestamp = round(time.time())

        signature_match = False
        active_block = False
        already_blocked = False
        log_connection = False

        direction = None
        category = None

        ## OUTBOUND RULE TCP
        if (packet.dst_ip in self.ip_signatures):
            direction = OUTBOUND
            signature_match = True
            tracked_ip = packet.dst_ip
            local_ip = packet.src_ip

            if (packet.procotol == UDP):
                main_st = self.outbound_session_tracker
                other_st = self.inbound_session_tracker

        ## INBOUND RULE TCP
        elif (packet.dst_port in self.open_tcp_ports and packet.src_ip in self.ip_signatures):
            direction = INBOUND
            signature_match = True
            tracked_ip = packet.src_ip
            local_ip = packet.dst_ip

            if (packet.protocol == UDP):
                main_st = self.inbound_session_tracker
                other_st = self.outbound_session_tracker

        if (packet.protocol == TCP and signature_match):
            ## if new connection, will add to fw_rules dictionary to prevent duplicate iptable rules, then will add to
            ## outbound session tracker and set active block to true to notify code to put ip table rule in
            tcp_st = self.tcp_session_tracker
            category = self.ip_signatures.get(tracked_ip)
            if (packet.tcp_syn and not packet.tcp_ack):
                ## applying lock on dict lookup/ add to protect state between condition and insert
                with self.fw_rule_creation_lock:
                    if (tracked_ip not in self.fw_rules):
                        self.fw_rules.update({tracked_ip: [timestamp, category]})
                        tcp_st[tracked_ip] = {local_ip: 0}
                        active_block = True

            ## will increment packet count of already active connections on responses/acks as a metric of what made it through
            elif (packet.tcp_ack and not packet.tcp_syn):
                count = tcp_st[tracked_ip].get(local_ip, 0) + 1
                tcp_st[tracked_ip].update({local_ip: count})
                print(f'INCREMENTED {tracked_ip}: {count}')

            # if a new connection is seen, but already blocked packet counter will reset to ensure numbers do not inflate
            # can probably remove after more recent changes since we do not see new connections so soon anymore
            elif (packet.tcp_syn and not packet.tcp_ack):
                tcp_st[tracked_ip] = {local_ip: 0}

            ## implementing the block via ip table if user configured to do so based on category and direction
            block_enabled = getattr(self, f'{category}_block')
            block_direction = getattr(self, self.block_settings[category])
            if (block_enabled and active_block) and (block_direction == direction or block_direction == BOTH):
                self.StandardBlock(tracked_ip, local_ip, direction, category)

                # session tracker will check packet counts to add confidence metric, this blocks for 1.5 seconds
                confidence = self.SessionTracker(tracked_ip, local_ip, direction)
                print(f'TRACKED IP: {tracked_ip} | CONFIDENCE: {confidence}')
            # this will prevent the informational log option to log unrelated or already blocked connections
            elif (block_enabled and not active_block):
                already_blocked = True

        ## will match if packet is udp protocol and either source or destination ip matches a proxy signature
        elif (packet.protocol == UDP and signature_match):
            # will match if direction is not already tracked
            category = self.ip_signatures.get(tracked_ip)
            if (tracked_ip not in other_st and tracked_ip not in main_st):
                ## applying lock on dict lookup/ add to protect state between condition and insert
                with self.fw_rule_creation_lock:
                    if (tracked_ip not in self.fw_rules):
                        self.fw_rules.update({tracked_ip: [timestamp, category]})
                        main_st[tracked_ip] = {local_ip: 0}
                        active_block = True

            ## will match if connection is being tracked and increment packet count for confidence metric
            elif (tracked_ip not in other_st and tracked_ip in main_st):
                count = tcp_st[tracked_ip].get(local_ip, 0) + 1
                main_st[tracked_ip].update({local_ip: count})
                print(f'INCREMENTED {packet.dst_ip}: {count}')

            ## implementing the block via ip table if user configured to do so based on category and direction
            block_enabled = getattr(self, f'{category}_block')
            block_direction = getattr(self, self.block_settings[category])
            if (block_enabled and active_block) and (block_direction == direction or block_direction == BOTH):
                self.StandardBlock(tracked_ip, local_ip, direction, category)

                # session tracker will check packet counts to add confidence metric, this blocks for 1.5 seconds
                confidence = self.SessionTracker(tracked_ip, local_ip, direction)
            # this will prevent the informational log option to log unrelated or already blocked connections
            elif (block_enabled and not active_block):
                already_blocked = True

        ## Log to Infected Hosts DB Table if matching malicious type categories ##
        if (category in {'malware'} and direction == OUTBOUND and self.logging_level >= ALERT):

            reason = 'malware'
            table = 'infectedclients'

            logging_options = {'infected_client': packet.src_mac, 'src_ip': packet.src_ip, 'detected_host': packet.dst_ip, 'reason': reason}
            self.TrafficLogging(table, timestamp, logging_options)

        # logs blocked requests that let more than 7 packets through
        if (active_block and confidence == MEDIUM and self.logging_level >= WARNING):
            action = 'blocked'
            log_connection = True

        # logs redirected/blocked requests that blocked within 7 packets
        elif (active_block and confidence in {HIGH, VERY_HIGH} and self.logging_level >= NOTICE):
            action = 'blocked'
            log_connection = True

        # logs all interesting requests if not configured to block and log level is informational
        elif (signature_match) and (not already_blocked and self.logging_level >= INFORMATIONAL):
            action = 'logged'
            confidence = 'n/a'
            log_connection = True

        if (log_connection):
            table = 'ipproxy'
            logging_options = {'src_ip': packet.src_ip, 'dst_ip': packet.dst_ip, 'category': category ,
                                'direction': direction, 'action': action, 'confidence': confidence}

            self.TrafficLogging(table, timestamp, logging_options)

    def StandardBlock(self, blocked_ip, local_ip, direction, category):
        chain = self.chain_settings[category]

        Popen(f'sudo iptables -t mangle -A {chain} -s {blocked_ip} -j DROP && \
                sudo iptables -t mangle -A {chain} -d {blocked_ip} -j DROP', shell=True)

    # applying a wait to give response enough time to come back, if
    # if response is not seen within time, assumes packet was dropped
    def SessionTracker(self, blocked_ip, local_ip, direction):
        time.sleep(1.5)
        count = self.tcp_session_tracker[blocked_ip].get(local_ip)

        if (count <= 3):
            confidence = VERY_HIGH
        elif (3 < count <= 7):
            confidence = HIGH
        else:
            confidence = MEDIUM

        self.tcp_session_tracker[blocked_ip].update({local_ip: 0})

        return confidence

    def TrafficLogging(self, table, timestamp, logging_options):
        ProxyDB = DBConnector(table)
        ProxyDB.Connect()
        if (table in {'ipproxy'}):
            ProxyDB.IPInput(timestamp, logging_options)

            if (self.syslog_enabled):
                self.AlertSyslog(logging_options)
        elif (table in {'infectedclients'}):
            ProxyDB.InfectedInput(timestamp, logging_options)

        ProxyDB.Disconnect()

    def AlertSyslog(self, logging_options):
        opt = SName(logging_options)

        if (opt.category in {'malware'}):
            msg_level = ALERT
        else:
            if (opt.confidence == MEDIUM):
                msg_level = WARNING
            elif (opt.confidence in {HIGH, VERY_HIGH}):
                msg_level = NOTICE
            elif (opt.action == 'logged'):
                msg_level = INFORMATIONAL

        message = f'src.ip={opt.src_ip}; dst.ip={opt.dst_ip}; category={opt.category}; '
        message += f'direction={opt.direction}; action={opt.action}; confidence={opt.confidence}'

        self.Syslog.Message(EVENT, msg_level, message)

    # Loading lists of interesting traffic into sets
    def LoadSignatures(self):
        with open(f'{HOME_DIR}/dnx_iplists/blocked.ips', 'r') as blocked:
            while True:
                line = blocked.readline().strip().split()
                if (not line):
                    break
                if (line != '\n'):
                    host = line[0]
                    category = line[1]
                    self.ip_signatures[host] = category

    def LoadInterfaces(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        self.wan_int = setting['settings']['interface']['outside']
        self.lan_int = setting['settings']['interface']['inside']

    # AsyncIO method called to gather automated/ continuous methods | this is python 3.7 version of async
    async def Main(self):
        await asyncio.gather(self.Timer.Settings(), self.Timer.Start(),
                            self.Automate.Blocking(), self.Automate.ClearIPTables(),
                            self.Automate.OpenPorts(), self.Log.Settings(LOG_MOD),
                            self.Syslog.Settings(SYSLOG_MOD))

                            ## LOG QUEUE? THIS MODULE IS THREADED
if __name__ == "__main__":
    Proxy = IPProxy()
    Proxy.Start()
