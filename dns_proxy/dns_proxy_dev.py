#!/usr/bin/python3

#from __future__ import print_function
#from scapy.all import *
#from socket import AF_INET, SOCK_DGRAM, socket

import os, sys
import time, threading
import json

from subprocess import run

from dnx_configure.system_info import System, Interface
from dnx_configure.dnx_dbconnector import SQLConnector as DBConnector
from dns_proxy.dns_proxy_response import DNSResponse
from dns_proxy.dns_proxy_sniffer import Sniffer

class DNSProxy:
    def __init__(self):
        self.path = os.getcwd().strip('dns-proxy')
        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)        
                    
        self.iface = self.setting['Settings']['Interface']['Inside']    
    
        Int = Interface()
        self.insideip = Int.IP(self.iface)
        self.DEVNULL = open(os.devnull, 'wb')
        self.urldict = {}
        
    def Start(self):
        self.ProxyDB()
        self.Dictload()
        self.Proxy()
        
    def ProxyDB(self):
        ProxyDB = DBConnector(self.path)
        ProxyDB.Connect()
        ProxyDB.Cleaner()
        ProxyDB.Disconnect()
    
    def Dictload(self):  
        with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
            whitelist = json.load(whitelists)
        exceptions = whitelist['Whitelists']['Exceptions']
          
        with open('{}/domainlists/Blocked.domains'.format(self.path), 'r') as BL:
            while True:
                urlHex = ''
                line = BL.readline().strip().lower()
                if (not line):
                    break
                line = line.split(' ')
                domain = line[0]
                splitdomain = line[0].split('.')
                cat = line[1]
                if (domain in exceptions):
                    pass
                else:
                    for part in splitdomain:
                        if (len(urlHex) == 0):
                            urlHex += part
                        else:
                            urlHex += '|{:02d}|{}'.format(len(part), part)
                    self.urldict[line[0]] = [urlHex, cat, 0]

    def Proxy(self):
    
        Proxy = Sniffer(self.iface, action=self.url_check)
        Proxy.Start()
       
    def url_check(self, packet):
#        hittime = int(time.time())
        ht = time.ctime(time.time())
        ht = ht.split(' ')  
        hittime = '{} {} {}'.format(ht[1], ht[2], ht[3])
        try:
            request = packet.qname
            if ('www' not in request):
                request2 = 'www.{}'.format(request)
            if (request in self.urldict or request2 in self.urldict):
                blockurl = self.WhitelistCheck(request)
                if (blockurl is True):
                    ProxyDB = DBConnector()
                    ProxyDB.Connect()
                    url = self.urldict[request][0]
                    category = self.urldict[request][1]
                    if (self.urldict[request][2] == 0):
                        if (self.urldict[request][1] == 'malicious'):
                            self.urldict[request][2] += 1
                            run('iptables -I MALICIOUS -m string --hex-string "{}" --algo bm -j DROP'.format(url), shell=True)
                        else:
                            self.urldict[request][2] += 1
                            run('iptables -I BLACKLIST -m string --hex-string "{}" --algo bm -j DROP'.format(url), shell=True)                    
    #                    end = time.time()
    #                    print(end - start)
                        DNS = DNSResponse(self.iface, self.insideip, packet)
                        threading.Thread(target=DNS.Response).start()
                        ProxyDB.Input(request, category, hittime)
                        print('Pointing {} to Firewall'.format(request))
                    else:
                        self.urldict[request][2] += 1
                        DNS = DNSResponse(self.iface, self.insideip, packet)
                        threading.Thread(target=DNS.Response).start()
                        ProxyDB.Input(request, category, hittime)
                        print('Pointing {} to Firewall. already blocked.'.format(request))
                    ProxyDB.Disconnect()                
        except Exception as E:
            print(E)
        
    def WhitelistCheck(self, request):
        with open('{}/data/whitelist.json'.format(self.path), 'r') as whitelists:
            whitelist = json.load(whitelists)
        whitelist = whitelist['Whitelists']['Domains']
        try:
            if (request in whitelist):
                return False
            if (request in whitelist[request]['WWW']):
                return False
            return True
        except Exception as E:
            print(E)
            return True    
        
if __name__ == '__main__':
    DNSP = DNSProxy()
    DNSP.Start()
