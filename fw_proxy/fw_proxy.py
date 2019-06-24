#!/usr/bin/python3

import os, sys
import time, threading
import json

from datetime import datetime
from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import System, Interface
from dnx_configure.dnx_db_connector import DBConnector
from fw_proxy.fw_proxy_sniffer import Sniffer
from fw_proxy.fw_proxy_timer import Timer as TM

class FWProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        self.DEVNULL = open(os.devnull, 'wb')

        with open(f'{self.path}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)
                                
        self.lan_int = self.setting['Settings']['Interface']['Inside']
    
        self.dns_sigs = {}
        self.session_tracker = {}
                
    def Start(self):
        Timer = TM()
        
        self.ProxyDB()
        self.LoadSignatures()

        threading.Thread(target=Timer.Start).start()
        threading.Thread(target=self.Proxy).start()

    #running cleaning operation on DB for > 30 days logs
    def ProxyDB(self):
        ProxyDB = DBConnector(table='FWProxy')
        ProxyDB.Connect()
        ProxyDB.Cleaner()
        ProxyDB.Disconnect()

    # Loading lists of interesting traffic into sets    
    def LoadSignatures(self):
        self.tor_nodes = {}
        for tor_type in {'Entry', 'Exit'}:
            with open(f'{self.path}/dnx_iplists/tor_{tor_type.lower()}.ips', 'r') as tor_list:
                for node in tor_list:
                    self.tor_nodes[node.strip()] = f'Tor {tor_type}'
        
        ## Load VPN Rules into set ##
        self.vpn_list = set()
                    
    def Proxy(self):
    
        Proxy = Sniffer(self.lan_int, action=self.Threads)
        Proxy.Start()
       
    def Threads(self, packet):
        # Starting thread to ensure non blocking states
        threading.Thread(target=self.SignatureCheck, args=(packet,)).start()

    def SignatureCheck(self, packet):
        #setting variables and filtering out ICMP
        log = False
        hittime = round(time.time())
        dst_ip = packet.dst
        src_ip = packet.src
        dport = packet.dport
        sport = packet.sport
       
        # Catches initial request to interesting traffic, filtering for local host > FW
        if (dst_ip in self.tor_nodes):
            print(f'Detected connection to TOR Node: {dst_ip}')
            self.session_tracker[sport] = src_ip
            category = self.tor_nodes[dst_ip]
            blocked = self.SessionTracker(sport, src_ip)
            if (blocked):
                log = True

        elif (dst_ip in self.vpn_list):
            log = True
            category = 'FW Rule'

        # Catches the response of interesting traffic, filtering for FW > local host#
        if (dport in self.session_tracker):
            if (dst_ip == self.session_tracker[dport]):
                print(f'Detected response from TOR Node: {src_ip}')
                self.session_tracker.pop(dport, None)
                category = self.tor_nodes[src_ip]
                blocked = False
                log = True
                # Reversing src/dst to show initial connection.
                src_ip = packet.dst
                dst_ip = packet.src
        
        # logging to database if filters detect interesting tracking, noting block /allow
        if (log):
            print(f'Logged {dst_ip}: {blocked}')
            ProxyDB = DBConnector(table='FWProxy')
            ProxyDB.Connect()
            
            ProxyDB.FWInput(src_ip, dst_ip, category, blocked, hittime)
            ProxyDB.Disconnect()

    # applying a wait to give response enough time to come back, if
    # if response is not seen within time, assumes packet was dropped
    def SessionTracker(self, sport, src_ip):
        time.sleep(2)
        if (sport in self.session_tracker):
            self.session_tracker.pop(sport, None)
            return True
        else:
            return False

if __name__ == "__main__":
    Proxy = FWProxy()
    Proxy.Start()            
            
            
            
            
                

