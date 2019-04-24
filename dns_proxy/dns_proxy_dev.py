#!/usr/bin/python3

import os, sys
import time, threading
import json

from datetime import datetime
from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_lists import ListFiles
from dnx_configure.dnx_iptables import IPTables as IPT
from dns_proxy.dns_proxy_response import DNSResponse
from dns_proxy.dns_proxy_sniffer import Sniffer

class DNSProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)
                                
        self.iface = self.setting['Settings']['Interface']['Inside']    
    
        Int = Interface()
        self.insideip = Int.IP(self.iface)
        self.DEVNULL = open(os.devnull, 'wb')
        self.dns_sigs = {}
        self.b_list = {}
        self.ent_logging = True
        self.ent_full = False
        
        self.log_supress = set()
                
    def Start(self):
        ListFile = ListFiles()
        ListFile.CombineLists()
        
        self.ProxyDB()
        self.LoadIPTables()
        self.LoadKeywords()
        self.LoadTLDs()
        self.LoadSignatures()
        
        threading.Thread(target=self.CustomLists).start()
        threading.Thread(target=self.CheckLogging).start()      
        threading.Thread(target=self.Proxy).start()

    def ProxyDB(self):
        for table in {'DNSProxy', 'PIHosts'}:
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.Cleaner()
            ProxyDB.Disconnect()
        
    def LoadSignatures(self):  
        with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
            whitelist = json.load(whitelists)
        wl_exceptions = whitelist['Whitelists']['Exceptions']
        
        with open('{}/data/blacklist.json'.format(self.path), 'r') as blacklists:
            blacklist = json.load(blacklists)
        bl_exceptions = blacklist['Blacklists']['Exceptions']

        try:  
            with open('{}/dnx_domainlists/blocked.domains'.format(self.path), 'r') as Blocked:
                while True:
                    line = Blocked.readline().strip().lower().split()
                    if (not line):
                        break
                    if ('#' not in line):
                        domain = line[0]
                        category = line[1]
                        if (domain not in wl_exceptions and 'www.{}'.format(domain) not in wl_exceptions):
                            self.SplitDomain(domain, category)
                                            
                for domain in bl_exceptions:
                    domain = domain.strip('www.')
                    category = 'Blacklist'
                    self.SplitDomain(domain, category)
                
                print(self.dns_sigs)
        except Exception as E:
            print(E)
                    
    def LoadTLDs(self):
        self.tlds = set()
        with open('{}/data/tlds.json'.format(self.path), 'r') as tlds:
            tld = json.load(tlds)
        tlds_all = tld['TLDs']

        for entry in tlds_all:
            if (tld['TLDs'][entry]['Enabled'] == 1):
                self.tlds.add(entry)

    def LoadKeywords(self):
        self.keywords = {}

        with open('{}/data/categories.json'.format(self.path), 'r') as keywords:
            keyword = json.load(keywords)

        keyword_status = keyword['DNSProxy']['Keyword']['Enabled']

        if (keyword_status == 1):
            en_cats = set()
            cats = keyword['DNSProxy']['Categories']['Default']
            for cat in cats:
                if (cats[cat]['Enabled'] == 1):
                    en_cats.add(cat)

            with open('{}/dnx_domainlists/keyword.domains'.format(self.path), 'r') as keywords:
                for line in keywords:
                    line = line.split()
                    keyword = line[0]
                    cat = line[1]
                    if cat.upper() in en_cats:
                        self.keywords[keyword] = cat
                    
    def SplitDomain(self, domain, category):
        splitdomain = domain.split('.')
        domainHex = ''
        for part in splitdomain:
            if (len(domainHex) == 0):
                domainHex += part
            else:
                domainHex += '|{:02d}|{}'.format(len(part), part)

        self.dns_sigs[domain] = [domainHex, category, 0]
                    
    def Proxy(self):
    
        Proxy = Sniffer(self.iface, action=self.SignatureCheck)
        Proxy.Start()
       
    def SignatureCheck(self, packet):
        try:
            redirect = False
            hittime = round(time.time())
            mac = packet.smac
            src_ip = packet.src
            req1 = packet.qname.lower() # www.micro.com or micro.com || sd.micro.com
            req = req1.split('.')
            req2 = '{}.{}'.format(req[-2], req[-1]) # micro.com or co.uk
            req_tld = '.{}'.format(req1.split('.')[-1]) # .com
            request = req1
            category = ''

            # Whitelist check of FQDN then overall domain ##
            if (req1 in self.w_list or req2 in self.w_list):
                pass

            ## P1. Standard Category blocking of FQDN ##
            elif (req1 in self.dns_sigs):
                redirect, reason, category = self.StandardBlock(req1)

            ## P2. Standard Category blocking of overall domain || micro.com ##
            elif (req2 in self.dns_sigs):
                redirect, reason, category = self.StandardBlock(req2)

            ## P1. Blacklist block of FQDN ##
            elif (req1 in self.b_list):
                redirect, reason, category = self.BlacklistBlock(req1)
            
            ## P2. Blacklist block of overall domain ##                                       
            elif (req2 in self.b_list):
                redirect, reason, category = self.BlacklistBlock(req2)
                
            ## TLD (top level domain) block ##
            elif (req_tld in self.tlds):
                print('TLD Block: {}'.format(req1))
                redirect = True
                category = req_tld
                reason = 'TLD Filter'

            ## Keyword Search within domain || block if match ##
            else:
                for keyword, cat in self.keywords.items():
                    if keyword in req1:
                        redirect = True
                        reason = 'Keyword'
                        if (category in {'malicious', 'cryptominer'}):
                            chain = 'MALICIOUS'
                        else:
                            chain = 'BLACKLIST'
                        run('iptables -I {} -m string --hex-string "{}" --algo bm -j DROP'.format(chain, keyword), shell=True)
                        category = cat
                        break
                    
            if (redirect):
                DNS = DNSResponse(self.iface, self.insideip, packet)
                threading.Thread(target=DNS.Response).start()
                print('Directed {} to Firewall.'.format(req1))

            if (category in {'malicious', 'cryptominer'}):
                if (category in {'malicious'}):
                    reason = 'Malware'
                elif (category in {'cryptominer'}):
                    reason = 'Crypto Miner Hijack'

                self.TrafficLogging(mac, src_ip, req1, reason, hittime, table='PIHosts')
                                       
            # logs redirected/blocked requests
            if (redirect):
                action = 'Blocked'
               
                self.TrafficLogging(req1, hittime, category, reason, action, table='DNSProxy')
                if (self.ent_logging and req1 not in self.log_supress):
                    self.EnterpriseLogging(mac, src_ip, req1, hittime, category, reason, action)

            # logs all requests, regardless of action of proxy.
            if (self.full_logging and not redirect):
                category = ' '
                reason = 'Logging'
                action = 'Allowed'
 
                self.TrafficLogging(req1, hittime, category, reason, action, table='DNSProxy')
                if (self.ent_full and req1 not in self.log_supress):
                    self.EnterpriseLogging(mac, src_ip, req1, hittime, category, reason, action)

        except Exception as E:
            print(E)

    def BlacklistBlock(self, request):
        print('Blacklist Block: {}'.format(request))
        redirect = True
        reason = 'Blacklist'
        category = 'Time Base'

        return redirect, reason, category

    def StandardBlock(self, request):
        print('Standard Block: {}'.format(request))
        redirect = True
        reason = 'Category'
        domainHex = self.dns_sigs[request][0]
        category = self.dns_sigs[request][1]
        if (self.dns_sigs[request][2] == 0):
            self.dns_sigs[request][2] += 1
            if (category in {'malicious', 'cryptominer'}):
                chain = 'MALICIOUS'
            else:
                chain = 'BLACKLIST'
            run('iptables -I {} -m string --hex-string "{}" --algo bm -j DROP'.format(chain, domainHex), shell=True)  

        return redirect, reason, category

    def EnterpriseLogging(self, mac, src_ip, req1, hittime, category, reason, action):
        threading.Thread(target=self.LogSupress, args=(req1,)).start()
        date = datetime.now()
        date = '{}-{}-{}'.format(date.year, date.month, date.day)
        with open ('{}/dnx_logs/{}-DNSProxyLogs.txt'.format(self.path, date), 'a+') as Logs:
            Logs.write('{}; src.mac={}; src.ip={}; domain={}; category={}; filter={}; action={}\n'\
                .format(hittime, mac, src_ip, req1, category, reason, action))
                
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
            ProxyDB.Connect()
            ProxyDB.InfectedInput(arg1, arg2, arg3, arg4, arg5)

        ProxyDB.Disconnect()

    def LoadIPTables(self):
        IPTables = IPT()
#        IPTables.Restore()

    def CheckLogging(self):
        while True:
            with open('{}/data/config.json'.format(self.path), 'r') as logging:
                log = json.load(logging)

            logging = log['Settings']['Logging']['Enabled']
            if (logging == 1):
                self.full_logging = True
            else:
                self.full_logging = False
            time.sleep(5*60)

    def CustomLists(self):
        w_list_remove = set()
        while True:
            current_time = time.time()

            ## -------------------------------------------##
            ## -- WHITELIST CHECK AND CLEAN/ IF NEEDED -- ##

            wl_check = False
            with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.w_list = whitelist['Whitelists']['Domains']

            for domain in self.w_list:
                if current_time > self.w_list[domain]['Expire']:
                    w_list_remove.add(domain)
                    wl_check = True
            
            for domain in w_list_remove:
                self.w_list.pop(domain, None)

            if wl_check:
                 with open('{}/data/whitelist.json'.format(self.path), 'w') as whitelists:
                    json.dump(whitelist, whitelists, indent=4)

                    self.w_list = whitelist['Whitelists']['Domains']

            print('Updated whitelists in memory.')
            time.sleep(5*60)
        
if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
