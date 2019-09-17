#!/usr/bin/python3

import os, sys
import time
import threading, asyncio
import json

from copy import deepcopy
from types import SimpleNamespace as SName

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *

from dns_proxy.dns_proxy_response import DNSResponse
from dns_proxy.dns_proxy_sniffer import DNSSniffer
from dns_proxy.dns_proxy_relay import DNSRelay, DNSCache
from dns_proxy.dns_proxy_protocols import TLSRelay, UDPRelay
from dns_proxy.dns_proxy_automate import Automate

from dnx_logging.log_main import LogHandler
from dnx_syslog.syl_main import SyslogHandler
from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_iptables import IPTables as IPT

LOG_MOD = 'dns_proxy'
SYSLOG_MOD = 'DNSProxy'

class DNSProxy:
    ''' Main Class for DNS Proxy. This class directly controls the logic regarding the signatures, whether something
        should be blocked or allowed, managing signature updates from user front end configurations. This class also
        serves as a bridge between the DNS Proxy Sniffer and DNS Relay give them a single point to flag traffic and
        identify traffic that should not be relayed/blocked via the class variable "flagged_traffic" dictionary. If
        the Proxy sniffer detects traffic that should be blocked it inputs the connection info into the dictionary
        for the DNS Relay to refer to before relaying the traffic. If the query information matches a dictionary item
        the DNS Relay will not forward the traffic to the configured public resolvers. '''

    def __init__(self):
        self.ip_whitelist = {}
        self.dns_whitelist = {}
        self.dns_blacklist = {}
        self.dns_sigs = {}
        self.dns_records = {}
        self.dns_servers = {}

        self.allowed_request = {}
        self.flagged_request = {}

        self.shared_decision_lock = threading.Lock()
        self.log_queue_lock = threading.Lock()

        self.logging_level = 0
        self.syslog_enabled = False

    ''' Start Method to Initialize All proxy configurations, including cleaning the database tables to the configures
        length. Starting a child thread for DNS Relay and DNS Proxy Sniffer, to handle requests, and doing an AsyncIO
        gather on proxy timer methods in main thread for rule updates '''
    def Start(self):
        self.LoadInterfaces()

        self.Log = LogHandler(self)
        self.Syslog = SyslogHandler(self)
        self.Automate = Automate(self)

        self.DNSCache = DNSCache(self)
        self.TLSRelay = TLSRelay(self)
        self.UDPRelay = UDPRelay(self)
        self.DNSRelay = DNSRelay(self)

        ListFile = ListFiles()
        ListFile.CombineDomains()
        ListFile.CombineKeywords()

        self.LoadKeywords()
        self.LoadTLDs()
        self.LoadSignatures()

        Sniffer = DNSSniffer(self)
        # setting from_proxy arg to True to have the sniffer sleep for 5 seconds while settings can initialize
        threading.Thread(target=Sniffer.Start, args=(True,)).start()
        threading.Thread(target=self.DNSRelay.Start).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.RecurringTasks())

    def SignatureCheck(self, packet):
        timestamp = time.time()

        dns_record = False
        whitelisted_query = False
        redirect = False
        log_connection = False
        category = None

        request_info = {'src_ip': packet.src_ip, 'src_port': packet.src_port, 'request': {1: packet.request, 2: packet.request2}}
        if (packet.request in self.dns_records):
            dns_record = True

        # Whitelist check of FQDN then overall domain ##
        elif (packet.request in self.dns_whitelist or packet.request2 in self.dns_whitelist or packet.src_ip in self.ip_whitelist):
            whitelisted_query = True

        ## will prevent all other checks from being processed if a local dns record is found for domain (for performance)
        if (dns_record):
            self.ApplyDecision(request_info, decision=FLAGGED)

        ## P1. Standard Category blocking of FQDN || if whitelisted, will check to ensure its not a malicious category
        ## before allowing it to continue
        elif (packet.request in self.dns_sigs):
            redirect, reason, category = self.StandardBlock(request_info, whitelisted_query)

        ## P2. Standard Category blocking of overall domain || micro.com if whitelisted, will check to ensure its not
        ## a malicious category before allowing it to continue
        elif (packet.request2 in self.dns_sigs):
            redirect, reason, category = self.StandardBlock(request_info, whitelisted_query, position=2)

        ## P1/P2 Blacklist block of FQDN if not whitelisted ##
        elif (not whitelisted_query) and (packet.request in self.dns_blacklist or packet.request2 in self.dns_blacklist):
            print(f'Blacklist Block: {packet.request}')
            redirect = True
            reason = 'blacklist'
            category = 'time based'

        ## TLD (top level domain) block ##
        elif (packet.request_tld in self.tlds):
            print(f'TLD Block: {packet.request}')
            redirect = True
            category = packet.request_tld
            reason = 'tld filter'

        ## Keyword Search within domain || block if match ##
        else:
            for keyword, cat in self.keywords.items():
                if (keyword in packet.request):
                    redirect = True
                    reason = 'keyword'
                    category = cat
                    break

        ## Redirect to firewall if traffic match/blocked ##
        if (redirect):
            self.ApplyDecision(request_info, decision=FLAGGED)
            DNSResponse(packet, self.lan_int, self.lan_ip).Response()

        ##Redirect to IP Address in local DNS Record (user configurable)
        elif (dns_record):
            record_ip = self.dns_records.get(packet.request)
            DNSResponse(packet, self.lan_int, record_ip).Response()
        else:
            self.ApplyDecision(request_info, decision=ALLOWED)

        ## Log to Infected Clients DB Table if matching malicious type categories
        if (category in {'malicious', 'cryptominer'} and self.logging_level >= ALERT):
            table ='infectedclients'
            if (category in {'malicious'}):
                reason = 'malware'
            elif (category in {'cryptominer'}):
                reason = 'cryptominer'

            logging_options = {'infected_client': packet.src_mac, 'src_ip': packet.src_ip, 'detected_host': packet.request, 'reason': reason}
            self.TrafficLogging(table, timestamp, logging_options)

        # logs redirected/blocked requests
        if (redirect and self.logging_level >= NOTICE):
            action = 'blocked'
            log_connection = True

        # logs all requests, regardless of action of proxy if not already logged
        elif (not redirect and self.logging_level >= INFORMATIONAL):
            category = 'N/A'
            reason = 'logging'
            action = 'allowed'
            log_connection = True

        if (log_connection):
            table = 'dnsproxy'
            logging_options = {'src_ip': packet.src_ip, 'request': packet.request, 'category': category ,
                                'reason': reason, 'action': action}

            self.TrafficLogging(table, timestamp, logging_options)

    def StandardBlock(self, request_info, whitelisted_query, position=1):
        redirect = False
#        print(f'Standard Block: {request}')
        reason = 'category'
        category = self.dns_sigs[request_info['request'][position]]
        if (not whitelisted_query or category in {'malicious', 'cryptominer'}):
            redirect = True

        return redirect, reason, category

    def ApplyDecision(self, request_info, decision):
        info = SName(**request_info)
        request_tracker = getattr(self, f'{decision}_request')
        try:
            request_tracker[info.src_ip].update({info.src_port: info.request[1]})
        except KeyError:
            request_tracker[info.src_ip] = {info.src_port: info.request[1]}
        # else:
            # self.Log.AddtoQueue(f'Client Source port overlap detected: {src_ip}:{src_port}')

    def TrafficLogging(self, table, timestamp, logging_options):
        ProxyDB = DBConnector(table)
        ProxyDB.Connect()
        if (table in {'dnsproxy'}):
            ProxyDB.StandardInput(timestamp, logging_options)

            if (self.syslog_enabled):
                self.AlertSyslog(logging_options)

        elif (table in {'infectedclients'}):
            ProxyDB.InfectedInput(timestamp, logging_options)

        ProxyDB.Disconnect()

    def AlertSyslog(self, logging_options):
        opt = SName(**logging_options)

        if (opt.category in {'malicious', 'cryptominer'}):
            msg_level = ALERT
        else:
            if (opt.action == 'blocked'):
                msg_level = NOTICE
            elif (opt.action == 'allowed'):
                msg_level = INFORMATIONAL

        message = f'src.ip={opt.src_ip}; request={opt.request}; category={opt.category}; '
        message += f'filter={opt.reason}; action={opt.action}'
        self.Syslog.Message(EVENT, msg_level, message)

    def LoadSignatures(self):
        with open(f'{HOME_DIR}/data/whitelist.json', 'r') as whitelists:
            whitelist = json.load(whitelists)
        wl_exceptions = whitelist['whitelists']['exceptions']

        with open(f'{HOME_DIR}/data/blacklist.json', 'r') as blacklists:
            blacklist = json.load(blacklists)
        bl_exceptions = blacklist['blacklists']['exceptions']

        with open(f'{HOME_DIR}/dnx_domainlists/blocked.domains', 'r') as blocked:
            while True:
                line = blocked.readline().strip().split()
                if (not line):
                    break
                if (line != '\n'):
                    domain = line[0]
                    category = line[1]
                    if (domain not in wl_exceptions):
                        self.dns_sigs[domain] = category

            for domain in bl_exceptions:
                self.dns_sigs[domain] = 'blacklist'

    def LoadTLDs(self):
        self.tlds = set()
        with open(f'{HOME_DIR}/data/dns_proxy.json', 'r') as tlds:
            tld = json.load(tlds)
        all_tlds = tld['dns_proxy']['tlds']

        for entry, info in all_tlds.items():
            tld_enabled = info['enabled']
            if (tld_enabled):
                self.tlds.add(entry)

    ## consider making a combine keywords file. this would be in line with ip and domain categories
    def LoadKeywords(self):
        self.keywords = {}

        with open(f'{HOME_DIR}/dnx_domainlists/blocked.keywords', 'r') as blocked:
            while True:
                line = blocked.readline().strip().split()
                if (not line):
                    break
                if (line != '\n'):
                    keyword = line[0]
                    cat = line[1]

                    self.keywords[keyword] = cat

    def LoadInterfaces(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        self.lan_int = setting['settings']['interface']['inside']
        self.wan_int = setting['settings']['interface']['outside']

        Int = Interface()
        self.lan_ip = Int.IP(self.lan_int)
        self.wan_ip = Int.IP(self.wan_int)

    # AsyncIO method called to gather automated/ continuous methods | this is python 3.7 version of async
    async def RecurringTasks(self):
        await asyncio.gather(self.Automate.Settings(), self.Automate.Reachability(),
                            self.Automate.DNSRecords(), self.Automate.UserDefinedLists(),
                            self.Automate.ClearCache(), self.Syslog.Settings(SYSLOG_MOD),
                            self.Log.Settings(LOG_MOD), self.Log.QueueHandler(self.log_queue_lock))


if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
