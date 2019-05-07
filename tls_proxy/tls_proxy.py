#!/usr/bin/env python3

import os, sys
import threading
import json
import re

from time import time
from datetime import datetime
from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from tls_proxy.tls_relay import TLSRelay
from dnx_configure.dnx_db_connector import DBConnector

class TLSProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)                                
        self.iface = self.setting['Settings']['Interface']['Inside'] 

        self.domain_reg = re.compile(
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z]{2,}\.?))', re.IGNORECASE)

        self.self_signed_block = False        
        self.domain_matches = {}
        self.crts = {}
        self.crls = {}

    def Start(self):
        self.LoadSignatures()

        self.Proxy()

    def LoadSignatures(self):
        self.ssl_sigs = {'google.com': 'test', 'dell.com': 'test', 'www.digicert.com' : 'BAD CA'}
#        self.ssl_sigs = {}

    def Proxy(self):
        Proxy = TLSRelay(action=self.SignatureCheck)
        Proxy.Start()

    def SignatureCheck(self, connection, ssl):
        start = time()
        try:
            block = False
            forward = True
            hittime = round(time())
    #        mac = packet.smac
            client_ip = connection['Client']['IP']
            client_port = connection['Client']['Port']
            server_ip = connection['Server']['IP']

            for i, certificate in enumerate(ssl.certificate_chain, 1):
                matches = re.findall(self.domain_reg, certificate.decode('utf-8', 'ignore'))
                for match in matches:
                    match = match.strip().lower()
                    print(f'{i}: {match}')
                    if (match.endswith('.crl')):                      
                        self.crls[match] = i
                    elif (match.endswith('.crt')):
                        self.crts[match] = i
                    else:
                        self.domain_matches[match] = i
            
            for domain in self.domain_matches:
                if (domain in self.ssl_sigs):
                    redirect, reason, category = self.StandardBlock(domain, client_ip, client_port, server_ip)
                    block = True
                    break

            if (self.self_signed_block):
                if (len(ssl) == 1):
                    domain = None
                    redirect, reason, category = self.StandardBlock(domain, client_ip, client_port, server_ip)
                    block = True

            if (block):
                action = 'Blocked'
#                self.TrafficLogging(domain, hittime, category, reason, action, table='TLSProxy')
                print(f'NOT FORWARDING {client_ip} : {domain}')
                forward = False

            return forward
        except Exception as E:
            print(E)
        
        end = time()
        print('%'*30)
        print(end-start)
        print('%'*30)
    def StandardBlock(self, domain, client_ip, client_port, server_ip):
        print('Standard Block: {}'.format(domain))
        block = True
        chain = 'SSL'
        if (domain):
            reason = 'Category'
            category = self.ssl_sigs[domain]
        else:
            reason = 'Policy'
            category = 'Self Signed'

#        run(f'iptables -I {chain} -p tcp -s {src_ip} --sport {src_port} -d {dst_ip} -j REJECT', shell=True)  

        return block, reason, category

    def TrafficLogging(self, arg1, arg2, arg3, arg4, arg5, table):
        if (table in {'TLSProxy'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()       
            ProxyDB.StandardInput(arg1, arg2, arg3, arg4, arg5)
        elif (table in {'PIHosts'}):
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.InfectedInput(arg1, arg2, arg3, arg4, arg5)

if __name__ == '__main__':
    TLSP = TLSProxy()
    TLSP.Start()
