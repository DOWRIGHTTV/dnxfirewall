#!/usr/bin/python3

import os, sys
import time, threading
import json

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
                
    def Start(self):
#        ListFile = ListFiles()
#        ListFile.CombineList()
        
        self.ProxyDB()
        self.LoadIPTables()
        self.LoadKeywords()
        self.LoadTLDs()
        self.LoadSignatures()
        
        threading.Thread(target=self.CustomLists).start()        
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
            hittime = int(time.time())
            mac = packet.smac
            src_ip = packet.src
            req1 = packet.qname
            req2 = req1.strip('www.')
            req3 = 'www.{}'.format(req2)
            req_tld = '.{}'.format(req1.split('.')[-1])
            category = ''

            if (req1 in self.w_list or req2 in self.w_list or req3 in self.w_list):
                pass

            elif (req1 in self.dns_sigs or req2 in self.dns_sigs or req3 in self.dns_sigs):
                print('Standard Block: {}'.format(req1))
                redirect = True
                reason = 'Category'
                domain = self.dns_sigs[req2][0]
                category = self.dns_sigs[req2][1]
                if (self.dns_sigs[req2][2] == 0):
                    self.dns_sigs[req2][2] += 1
                    if (category in {'malicious', 'cryptominer'}):
                        chain = 'MALICIOUS'
                    else:
                        chain = 'BLACKLIST'
                    run('iptables -I {} -m string --hex-string "{}" --algo bm -j DROP'.format(chain, domain), shell=True)
                                            
            elif (req1 in self.b_list or req2 in self.b_list or req3 in self.b_list):
                print('Blacklist Block: {}'.format(req1))
                redirect = True
                reason = 'Blacklist'
                category = 'Time Base'

            elif req_tld in self.tlds:
                print('TLD Block: {}'.format(req1))
                redirect = True
                category = req_tld
                reason = 'TLD Filter'

            for keyword, cat in self.keywords.items():
                if keyword in req2:
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
                print('Directed {} to Firewall.'.format(req2))

                ProxyDB = DBConnector(table='ProxyBlocks')
                ProxyDB.Connect()
                
                ProxyDB.StandardInput(req2, category, hittime, reason)
                ProxyDB.Disconnect()

            if (category in {'malicious', 'cryptominer'}):
                if (category in {'malicious'}):
                    reason = 'Malware'
                elif (category in {'cryptominer'}):
                    reason = 'Crypto Miner Hijack'
                ProxyDB = DBConnector(table='PIHosts')
                ProxyDB.Connect()

                ProxyDB.InfectedInput(mac, src_ip, domain, reason, hittime)
                ProxyDB.Disconnect()
        
        except Exception as E:
            print(E) 

    def LoadIPTables(self):
        IPTables = IPT()
#        IPTables.Restore()

    def CustomLists(self):
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
                    self.w_list.pop(domain)
                    wl_check = True
            
            if wl_check:
                 with open('{}/data/whitelist.json'.format(self.path), 'w') as whitelists:
                    json.dump(self.w_list, whitelists, indent=4)

            print('Updating whitelists in memory.')
            time.sleep(5*60)
        
if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
