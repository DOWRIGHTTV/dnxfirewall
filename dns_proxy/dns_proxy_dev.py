#!/usr/bin/python3

import os, sys
import time, threading
import json

from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import System, Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_lists import ListFiles
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
                
    def Start(self):
#        ListFile = ListFiles()
#        ListFile.CombineList()
        
        self.ProxyDB()
        self.SignatureLoad()
        
        threading.Thread(target=self.CustomLists).start() 
        threading.Thread(target=self.Proxy).start()

    def ProxyDB(self):
        ProxyDB = DBConnector()
        ProxyDB.Connect()
        ProxyDB.Cleaner()
        
    def SignatureLoad(self):  
        with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
            whitelist = json.load(whitelists)
        wl_exceptions = whitelist['Whitelists']['Exceptions']
        
        with open('{}/data/blacklist.json'.format(self.path), 'r') as blacklists:
            blacklist = json.load(blacklists)
        bl_exceptions = blacklist['Blacklists']['Exceptions']
          
        with open('{}/domainlists/Blocked.domains'.format(self.path), 'r') as Blocked:
            while True:
                line = Blocked.readline().strip().lower().split()
                if (not line):
                    break
                domain = line[0]
                category = line[1]
                if (domain not in wl_exceptions or 'www.{}'.format(domain) not in wl_exceptions):
                    self.SplitDomain(domain, category)
                                        
            for domain in bl_exceptions:
                domain = domain.strip('www.')
                category = 'Blacklist'
                self.SplitDomain(domain, category)
            
#            print(self.dns_sigs)
                    
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
    
        Proxy = Sniffer(self.iface, action=self.url_check)
        Proxy.Start()
       
    def url_check(self, packet):  
        try:
            redirect = False     
            hittime = int(time.time())
            req1 = packet.qname
            req2 = req1.strip('www.')
            req3 = 'www.{}'.format(req2)
                
            if (req1 in self.w_list or req2 in self.w_list or req3 in self.w_list):
                pass
                
            elif (req1 in self.dns_sigs or req2 in self.dns_sigs or req3 in self.dns_sigs):
                print('Standard Block: {}'.format(req1))
                redirect = True
                domain = self.dns_sigs[req2][0]
                category = self.dns_sigs[req2][1]
                if (self.dns_sigs[req2][2] == 0):
                    self.dns_sigs[req2][2] += 1
                    if (self.dns_sigs[req2][1] == 'malicious'):
                        chain = 'MALICIOUS'
                    else:
                        chain = 'BLACKLIST'
                    run('iptables -I {} -m string --hex-string "{}" --algo bm -j DROP'.format(chain, domain), shell=True)
                                            
            elif (req1 in self.b_list or req2 in self.b_list or req3 in self.b_list):
                print('Blacklist Block: {}'.format(req1))
                redirect = True
                category = 'Blacklist'
               
            if (redirect):
                ProxyDB = DBConnector()
                ProxyDB.Connect()

                DNS = DNSResponse(self.iface, self.insideip, packet)
                threading.Thread(target=DNS.Response).start()
                print('Directed {} to Firewall.'.format(req2))
                
                ProxyDB.Input(req2, category, hittime)
                ProxyDB.Disconnect()
        
        except Exception as E:
            print(E) 

    def CustomLists(self):
        while True:
            with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
                whitelist = json.load(whitelists)
            self.w_list = whitelist['Whitelists']['Domains']
                
            with open('{}/data/blacklist.json'.format(self.path), 'r') as blacklists:
                blacklist = json.load(blacklists)
            self.b_list = blacklist['Blacklists']['Domains']

            print('Updating white/blacklists in memory.')
            time.sleep(5*60)

        
if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()