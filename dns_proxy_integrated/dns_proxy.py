#!/usr/bin/python3

import os, sys
import time
import threading, asyncio
import json

from subprocess import run

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_logging.log_main import LogHandler
from dnx_syslog.syl_main import SyslogHandler
from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_iptables import IPTables as IPT
from dns_proxy.dns_proxy_response import DNSResponse
from dns_proxy.dns_proxy_sniffer import DNSSniffer
from dns_proxy.dns_proxy_relay import DNSRelay as DNSR

LOG_MOD = 'dns_proxy'
SYSLOG_MOD = 'DNSProxy'
EVENT = 14

ALERT = 1
NOTICE = 5
INFORMATIONAL = 6

class DNSProxy:
    ''' Main Class for DNS Proxy. This class directly controls the logic regarding the signatures, whether something
        should be blocked or allowed, managing signature updates from user front end configurations. This class also
        serves as a bridge between the DNS Proxy Sniffer and DNS Relay give them a single point to flag traffic and
        identify traffic that should not be relayed/blocked via the class variable "flagged_traffic" dictionary. If
        the Proxy sniffer detects traffic that should be blocked it inputs the connection info into the dictionary
        for the DNS Relay to refer to before relaying the traffic. If the query information matches a dictionary item
        the DNS Relay will not forward the traffic to the configured public resolvers. '''

    def __init__(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            setting = json.load(settings)
        self.lan_int = setting['settings']['interface']['inside']

        Int = Interface()
        self.lan_ip = Int.IP(self.lan_int)
        self.full_logging = False
        self.ip_whitelist = {}
        self.dns_whitelist = {}
        self.dns_blacklist = {}
        self.dns_sigs = {}
        self.dns_records = {}

        self.flagged_traffic = {}

    ''' Start Method to Initialize All proxy configurations, including cleaning the database tables to the configures
        length. Starting a child thread for DNS Relay and DNS Proxy Sniffer, to handle requests, and doing an AsyncIO
        gather on proxy timer methods in main thread for rule updates '''
    def Start(self):
        self.Log = LogHandler()
        self.Syslog = SyslogHandler(self.lan_ip)

        Sniffer = DNSSniffer(self)
        self.DNSRelay = DNSR(self)

        ListFile = ListFiles()
        ListFile.CombineDomains()
        ListFile.CombineKeywords()

        self.ProxyDB()
        self.LoadKeywords()
        self.LoadTLDs()
        self.LoadSignatures()

        threading.Thread(target=Sniffer.Start).start()
        threading.Thread(target=self.DNSRelay.Start).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    def ProxyDB(self):
        for table in {'DNSProxy', 'PIHosts'}:
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.Cleaner()
            ProxyDB.Disconnect()

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
                category = 'blacklist'
                self.dns_sigs[domain] = category

    def LoadTLDs(self):
        self.tlds = set()
        with open(f'{HOME_DIR}/data/tlds.json', 'r') as tlds:
            tld = json.load(tlds)
        tlds_all = tld['tlds']

        for entry in tlds_all:
            tld_enabled = tld['tlds'][entry]['enabled']
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

    def SignatureCheck(self, packet):
        start = time.time()
        redirect = False
        dns_record = False
        whitelisted_query = False
        timestamp = round(time.time())
        mac = packet.src_mac
        src_ip = packet.src_ip
        src_port = packet.src_port
        req1 = packet.qname.lower() # www.micro.com or micro.com || sd.micro.com
        category = ''
        if ('.' in req1):
            req = req1.split('.')
            req2 = f'{req[-2]}.{req[-1]}' # micro.com or co.uk
            req = req1.split('.')[-1] # .com
            req_tld = f'.{req}'
            request = req1
        else:
            req2 = None
            req_tld = None
            request = req1
        print(f'1 ||| {time.time()} || PROXY RECEIVED: {src_ip}: {src_port}: {req1}')
        if (req1 in self.dns_records):
            dns_record = True
            self.ApplyDNF(src_ip, src_port, request)

        # Whitelist check of FQDN then overall domain ##
        if (req1 in self.dns_whitelist or req2 in self.dns_whitelist or src_ip in self.ip_whitelist):
            whitelisted_query = True

        ## P1. Standard Category blocking of FQDN || if whitelisted, will check to ensure its not a malicious category
        ## before allowing it to continue
        if (req1 in self.dns_sigs):
            redirect, reason, category = self.StandardBlock(src_ip, src_port, req1, whitelisted_query)

        ## P2. Standard Category blocking of overall domain || micro.com if whitelisted, will check to ensure its not
        ## a malicious category before allowing it to continue
        elif (req2 in self.dns_sigs):
            redirect, reason, category = self.StandardBlock(src_ip, src_port, req2, whitelisted_query)

        ## P1. Blacklist block of FQDN if not whitelisted ##
        elif (req1 in self.dns_blacklist and not whitelisted_query):
            if (not whitelisted_query):
                redirect, reason, category = self.BlacklistBlock(src_ip, src_port, req1)

        ## P2. Blacklist block of overall domain if not whitelisted##
        elif (req2 in self.dns_blacklist and not whitelisted_query):
            if (not whitelisted_query):
                redirect, reason, category = self.BlacklistBlock(src_ip, src_port, req2)

        ## TLD (top level domain) block ##
        elif (req_tld in self.tlds):
            print(f'TLD Block: {req1}')
            redirect = True
            category = req_tld
            reason = 'tld filter'

        ## Keyword Search within domain || block if match ##
        else:
            for keyword, cat in self.keywords.items():
                if keyword in req1:
                    redirect = True
                    reason = 'keyword'
                    category = cat
                    self.ApplyDNF(src_ip, src_port, request)
                    break

        ## Redirect to firewall if traffic match/blocked ##
        if (redirect):
            DNS = DNSResponse(self.lan_int, self.lan_ip, packet)
            DNS.Response()

        ##Redirect to IP Address in local DNS Record (user configurable)
        elif (dns_record):
            record_ip = self.dns_records[req1]
            DNS = DNSResponse(self.lan_int, record_ip, packet)
            DNS.Response()

        print(f'TIME TO SEARCH/BLOCK: {time.time() - start}')
        ## Log to Infected Hosts DB Table if matching malicious type categories ##
        if (category in {'malicious', 'cryptominer'} and self.logging_level >= ALERT):
            table ='PIHosts'
            if (category in {'malicious'}):
                reason = 'malware'
            elif (category in {'cryptominer'}):
                reason = 'crypto miner hijack'

            logging_options = {'mac': mac, 'src_ip': src_ip, 'host': request, 'reason': reason}
            self.TrafficLogging(table, timestamp, logging_options)

        # logs redirected/blocked requests
        if (redirect and self.logging_level >= NOTICE):
            table = 'DNSProxy'
            action = 'blocked'

            logging_options = {'src_ip': src_ip, 'request': request, 'category': category ,
                                'reason': reason, 'action': action}
            self.TrafficLogging(table, timestamp, logging_options)

        # logs all requests, regardless of action of proxy.
        elif (not redirect and self.logging_level >= INFORMATIONAL):
            table = 'DNSProxy'
            category = 'N/A'
            reason = 'logging'
            action = 'allowed'

            logging_options = {'src_ip': src_ip, 'request': request, 'category': category ,
                                'reason': reason, 'action': action}
            self.TrafficLogging(table, timestamp, logging_options)

    def BlacklistBlock(self, src_ip, src_port, request):
        print(f'Blacklist Block: {request}')
        redirect = True
        reason = 'blacklist'
        category = 'time based'
        self.ApplyDNF(src_ip, src_port, request)

        return redirect, reason, category

    def StandardBlock(self, src_ip, src_port, request, whitelisted_query):
        redirect = False
#        print(f'Standard Block: {request}')
        reason = 'category'
        category = self.dns_sigs[request]
        if (whitelisted_query and category not in {'malicious', 'cryptominer'}):
            pass
        else:
            redirect = True
            self.ApplyDNF(src_ip, src_port, request)

        return redirect, reason, category

    def ApplyDNF(self, src_ip, src_port, request):
        if (src_ip not in self.flagged_traffic):
            self.flagged_traffic[src_ip] = {src_port: request}
        elif (src_port not in self.flagged_traffic[src_ip]):
            self.flagged_traffic[src_ip].update({src_port: request})
        print(f'DNF APPLIED| {src_ip}: {src_port}: {request}')
        # else:
        #     self.Log.AddtoQueue(f'Client Source port overlap detected: {src_ip}:{src_port}')

    def TrafficLogging(self, table, timestamp, logging_options):
        if (table in {'DNSProxy'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.StandardInput(timestamp, logging_options)
        elif (table in {'PIHosts'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.InfectedInput(timestamp, logging_options)

        ProxyDB.Disconnect()

        if (table in {'DNSProxy'}):
            self.AlertSyslog(logging_options)

    def AlertSyslog(self, logging_options):
        src_ip = logging_options['src_ip']
        request = logging_options['request']
        category = logging_options['category']
        reason = logging_options['reason']
        action = logging_options['action']

        if (category in {'malicious', 'cryptominer'}):
            msg_level = ALERT
        else:
            if (action == 'blocked'):
                msg_level = NOTICE
            elif (action == 'allowed'):
                msg_level = INFORMATIONAL

        message = f'src.ip={src_ip}; request={request}; category={category}; filter={reason}; action={action}'
        self.Syslog.Message(SYSLOG_MOD, EVENT, msg_level, message)

    # AsyncIO method called to gather automated/ continuous methods | this is python 3.7 version of async
    async def Main(self):
        await asyncio.gather(self.CheckLogging(), self.CustomLists(), self.DNSRecords(),
                            self.DNSRelay.CheckSettings(), self.DNSRelay.Reachability(),
                            self.Log.QueueHandler(LOG_MOD), self.Syslog.CheckSettings())

    async def CheckLogging(self):
        while True:
            with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
                setting = json.load(settings)

            self.logging_level = setting['settings']['logging']['level']

            await asyncio.sleep(5*60)

    async def DNSRecords(self):
        while True:
            with open(f'{HOME_DIR}/data/dns_server.json', 'r') as dns_records:
                dns_record = json.load(dns_records)

            self.dns_records = dns_record['dns_server']['records']

            await asyncio.sleep(5*60)

    async def CustomLists(self):
        w_list_remove = set()
        b_list_remove = set()
        while True:
            current_time = time.time()

            ## --------------------------------------------- ##
            ## -- IP WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##
            with open(f'{HOME_DIR}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.ip_whitelist = whitelist['whitelists']['ip_whitelist']

            ## ---------------------------------------------- ##
            ## -- DNS WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##

            wl_check = False
            with open(f'{HOME_DIR}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.dns_whitelist = whitelist['whitelists']['domains']

            for domain in self.dns_whitelist:
                if current_time > self.dns_whitelist[domain]['expire']:
                    w_list_remove.add(domain)
                    wl_check = True

            for domain in w_list_remove:
                self.dns_whitelist.pop(domain, None)

            if wl_check:
                 with open(f'{HOME_DIR}/data/whitelist.json', 'w') as whitelists:
                    json.dump(whitelist, whitelists, indent=4)

                    self.dns_whitelist = whitelist['whitelists']['domains']

            ## -------------------------------------------##
            ## -- BLACKLIST CHECK AND CLEAN/ IF NEEDED -- ##

            bl_check = False
            with open(f'{HOME_DIR}/data/blacklist.json', 'r') as blacklists:
                blacklist = json.load(blacklists)
            self.dns_blacklist = blacklist['blacklists']['domains']

            for domain in self.dns_blacklist:
                if current_time > self.dns_blacklist[domain]['expire']:
                    b_list_remove.add(domain)
                    bl_check = True

            for domain in b_list_remove:
                self.dns_blacklist.pop(domain, None)

            if bl_check:
                 with open(f'{HOME_DIR}/data/blacklist.json', 'w') as blacklists:
                    json.dump(blacklist, blacklists, indent=4)

                    self.dns_blacklist = whitelist['whitelists']['domains']
            print('Updating white/blacklists in memory.')
            await asyncio.sleep(5*60)

if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
