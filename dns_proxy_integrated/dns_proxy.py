#!/usr/bin/python3

import os, sys
import time
import threading, asyncio
import json

from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import System, Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_iptables import IPTables as IPT
from dns_proxy.dns_proxy_response import DNSResponse
from dns_proxy.dns_proxy_sniffer import Sniffer
from dns_proxy.dns_proxy_relay import DNSRelay as DNSR

class DNSProxy:
    ''' Main Class for DNS Proxy. This class directly controls the logic regarding the signatures, whether something
        should be blocked or allowed, managing signature updates from user front end configurations. This class also
        serves as a bridge between the DNS Proxy Sniffer and DNS Relay give them a single point to flag traffic and 
        identify traffic that should not be relayed/blocked via the class variable "flagged_traffic" dictionary. If
        the Proxy sniffer detects traffic that should be blocked it inputs the connection info into the dictionary 
        for the DNS Relay to refer to before relaying the traffic. If the query information matches a dictionary item
        the DNS Relay will not forward the traffic to the configured public resolvers. '''

    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open(f'{self.path}/data/config.json', 'r') as settings:
            setting = json.load(settings)
        self.lan_int = setting['Settings']['Interface']['Inside']

        Int = Interface()
        self.lan_ip = Int.IP(self.lan_int)
        self.DEVNULL = open(os.devnull, 'wb')
        self.full_logging = None
        self.ip_whitelist = None
        self.dns_whitelist = None
        self.dns_blacklist = None
        self.dns_sigs = {}
        self.dns_records = {}
        
        self.ent_logging = True
        self.ent_full = False        
        self.log_supress = set()

        DNSProxy.flagged_traffic = {}

    ''' Start Method to Initialize All proxy configurations, including cleaning the database tables to the configures
        length. Starting a child thread for DNS Relay and DNS Proxy Sniffer, to handle requests, and doing an AsyncIO
        gather on proxy timer methods in main thread for rule updates '''
    def Start(self):
        ListFile = ListFiles()
        ListFile.CombineLists()
        DNSRelay = DNSR(DNSProxy)

        self.ProxyDB()
        self.LoadKeywords()
        self.LoadTLDs()
        self.LoadSignatures()

        threading.Thread(target=DNSRelay.Start).start()
        threading.Thread(target=self.Proxy).start()

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
        with open(f'{self.path}/data/whitelist.json', 'r') as whitelists:
            whitelist = json.load(whitelists)
        wl_exceptions = whitelist['Whitelists']['Exceptions']

        with open(f'{self.path}/data/blacklist.json', 'r') as blacklists:
            blacklist = json.load(blacklists)
        bl_exceptions = blacklist['Blacklists']['Exceptions']

        with open(f'{self.path}/dnx_domainlists/blocked.domains', 'r') as Blocked:
            while True:
                line = Blocked.readline().strip().lower().split()
                if (not line):
                    break
                if ('#' not in line and line != '\n'):
                    domain = line[0]
                    category = line[1]
                    if (domain not in wl_exceptions):
                        self.dns_sigs[domain] = category

            for domain in bl_exceptions:
                category = 'blacklist'
                self.dns_sigs[domain] = category

    def LoadTLDs(self):
        self.tlds = set()
        with open(f'{self.path}/data/tlds.json', 'r') as tlds:
            tld = json.load(tlds)
        tlds_all = tld['TLDs']

        for entry in tlds_all:
            tld_enabled = tld['TLDs'][entry]['Enabled']
            if (tld_enabled):
                self.tlds.add(entry)

    def LoadKeywords(self):
        self.keywords = {}

        with open(f'{self.path}/data/categories.json', 'r') as keywords:
            keyword = json.load(keywords)
        keyword_enabled = keyword['DNSProxy']['Keyword']['Enabled']

        if (keyword_enabled):
            en_cats = set()
            cats = keyword['DNSProxy']['Categories']['Default']
            for cat in cats:
                cat_enabled = cats[cat]['Enabled']
                if (cat_enabled):
                    en_cats.add(cat)

            with open(f'{self.path}/dnx_domainlists/keyword.domains', 'r') as keywords:
                for line in keywords:
                    if ('#' not in line and line != '\n'):
                        line = line.split()
                        keyword = line[0]
                        cat = line[1]
                        if cat.upper() in en_cats:
                            self.keywords[keyword] = cat

    def Proxy(self):

        Proxy = Sniffer(self.lan_int, action=self.SignatureCheck)
        Proxy.Start()

    def SignatureCheck(self, packet):
        redirect = False
        dns_record = False
        whitelisted_query = False
        hit_time = round(time.time())
        mac = packet.smac
        src_ip = packet.src
        src_port = packet.sport
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
            redirect, reason, category = self.StandardBlock(src_ip, src_port, req1, whitelisted_query)

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
            reason = 'TLD Filter'

        ## Keyword Search within domain || block if match ##
        else:
            for keyword, cat in self.keywords.items():
                if keyword in req1:
                    redirect = True
                    reason = 'Keyword'
                    category = cat
                    self.ApplyDNF(src_ip, src_port, request)
                    break

        ## Redirect to firewall if traffic match/blocked ##
        if (redirect):
            DNS = DNSResponse(self.lan_int, self.lan_ip, packet)
            DNS.Response()

        ##Redirect to IP Address in local DNS Record (user configurable)
        if (dns_record):
            record_ip = self.dns_records[req1]
            DNS = DNSResponse(self.lan_int, record_ip, packet)
            DNS.Response()

        ## Log to Infected Hosts DB Table if matching malicious type categories ##
        if (category in {'malicious', 'cryptominer'}):
            if (category in {'malicious'}):
                reason = 'Malware'
            elif (category in {'cryptominer'}):
                reason = 'Crypto Miner Hijack'

            self.TrafficLogging(mac, src_ip, request, reason, hit_time, table='PIHosts')

        # logs redirected/blocked requests
        if (redirect):
            action = 'Blocked'

            self.TrafficLogging(request, hit_time, category, reason, action, table='DNSProxy')
            if (self.ent_logging and req1 not in self.log_supress):
                self.EnterpriseLogging(mac, src_ip, req1, hittime, category, reason, action)

        # logs all requests, regardless of action of proxy.
        elif (self.full_logging and not redirect):
            category = 'N/A'
            reason = 'Logging'
            action = 'Allowed'

            self.TrafficLogging(request, hit_time, category, reason, action, table='DNSProxy')
            if (self.ent_full and req1 not in self.log_supress):
                    self.EnterpriseLogging(mac, src_ip, req1, hittime, category, reason, action)

    def BlacklistBlock(self, src_ip, src_port, request):
        print(f'Blacklist Block: {request}')
        redirect = True
        reason = 'Blacklist'
        category = 'Time Base'
        self.ApplyDNF(src_ip, src_port, request)

        return redirect, reason, category

    def StandardBlock(self, src_ip, src_port, request, whitelisted_query):
        redirect = False
        print(f'Standard Block: {request}')
        reason = 'Category'
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
        else:
            Sys = System()
            Sys.Log(f'Client Source port overlap detected: {src_ip}:{src_port}')
            
    def EnterpriseLogging(self, mac, src_ip, req1, hittime, category, reason, action):
        threading.Thread(target=self.LogSupress, args=(req1,)).start()
        date = datetime.now()
        date = f'{date.year}-{date.month}-{date.day}'
        with open (f'{self.path}/dnx_logs/{date}-DNSProxyLogs.txt', 'a+') as Logs:
            Logs.write(f'{hittime}; src.mac={mac}; src.ip={src_ip}; domain={req1}; category={category}; filter={reason}; action={action}\n'\)
                
    def LogSupress(self, req1):
        self.log_supress.add(req1)
        time.sleep(5)
        self.log_supress.remove(req1)

    def TrafficLogging(self, arg1, arg2, arg3, arg4, arg5, table):
        if (table in {'DNSProxy'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.StandardInput(arg1, arg2, arg3, arg4, arg5)
        elif (table in {'PIHosts'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Disconnect()
            ProxyDB.InfectedInput(arg1, arg2, arg3, arg4, arg5)

        ProxyDB.Disconnect()

    # AsyncIO method called to gather automated/ continuous methods | this is python 3.7 version of async
    async def Main(self):
        await asyncio.gather(self.CheckLogging(), self.CustomLists(), self.DNSRecords())

    async def CheckLogging(self):
        while True:
            with open(f'{self.path}/data/config.json', 'r') as settings:
                setting = json.load(settings)

            self.full_logging = setting['Settings']['Logging']['Enabled']

            await asyncio.sleep(5*60)

    async def DNSRecords(self):
        while True:
            with open(f'{self.path}/data/dns_server.json', 'r') as dns_records:
                dns_record = json.load(dns_records)

            self.dns_records = dns_record['DNSServer']['Records']

            await asyncio.sleep(5*60)

    async def CustomLists(self):
        w_list_remove = set()
        b_list_remove = set()
        while True:
            current_time = time.time()

            ## --------------------------------------------- ##
            ## -- IP WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##
            with open(f'{self.path}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.ip_whitelist = whitelist['Whitelists']['IP Whitelist']

            ## ---------------------------------------------- ##
            ## -- DNS WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##

            wl_check = False
            with open(f'{self.path}/data/whitelist.json', 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.dns_whitelist = whitelist['Whitelists']['Domains']

            for domain in self.dns_whitelist:
                if current_time > self.dns_whitelist[domain]['Expire']:
                    w_list_remove.add(domain)
                    wl_check = True

            for domain in w_list_remove:
                self.dns_whitelist.pop(domain, None)

            if wl_check:
                 with open(f'{self.path}/data/whitelist.json', 'w') as whitelists:
                    json.dump(whitelist, whitelists, indent=4)

                    self.dns_whitelist = whitelist['Whitelists']['Domains']

            ## -------------------------------------------##
            ## -- BLACKLIST CHECK AND CLEAN/ IF NEEDED -- ##

            bl_check = False
            with open(f'{self.path}/data/blacklist.json', 'r') as blacklists:
                blacklist = json.load(blacklists)    
            self.dns_blacklist = blacklist['Blacklists']['Domains']

            for domain in self.dns_blacklist:
                if current_time > self.dns_blacklist[domain]['Expire']:
                    b_list_remove.add(domain)
                    bl_check = True

            for domain in b_list_remove:
                self.dns_blacklist.pop(domain, None)

            if bl_check:
                 with open(f'{self.path}/data/blacklist.json', 'w') as blacklists:
                    json.dump(blacklist, blacklists, indent=4)

                    self.dns_blacklist = whitelist['Whitelists']['Domains']
            print('Updating white/blacklists in memory.')
            await asyncio.sleep(5*60)

if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
