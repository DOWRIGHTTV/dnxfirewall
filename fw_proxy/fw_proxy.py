#!/usr/bin/python3

import os, sys
import time, threading
import json

from subprocess import run

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import System, Interface
from dnx_configure.dnx_db_connector import DBConnector
from fw_proxy.fw_proxy_sniffer import Sniffer

class FWProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)
                                
        self.iface = self.setting['Settings']['Interface']['Inside']
        self.wface = self.setting['Settings']['Interface']['Outside']
    
        Int = Interface()
        self.insideip = Int.IP(self.iface)
        self.wanip = Int.IP(self.wface)
        self.DEVNULL = open(os.devnull, 'wb')
        self.dns_sigs = {}

        self.session_tracker = {}
                
    def Start(self):
        self.LoadSignatures()
    
    
        self.Proxy()

    #running cleaning operation on DB for > 30 days logs
    def ProxyDB(self):
        ProxyDB = DBConnector(table='FWBlocks')
        ProxyDB.Connect()
        ProxyDB.Cleaner()
        ProxyDB.Disconnect()

    # Loading lists of interesting traffic into sets    
    def LoadSignatures(self):
        self.tor_nodes = {}
        with open('{}/dnx_iplists/tor_entry.nodes'.format(self.path), 'r') as tor_list:
            for node in tor_list:
                self.tor_nodes[node.strip()] = 'Tor Entry'
#        print(self.tor_entry)
                
        with open('{}/dnx_iplists/tor_exit.nodes'.format(self.path), 'r') as tor_list:
            for node in tor_list:
                self.tor_nodes[node.strip()] = 'Tor Exit'
        
        ## Load FW Rules into set ##
        self.vpn_list = set()
                    
    def Proxy(self):
    
        Proxy = Sniffer(self.iface, action=self.Threads)
        Proxy.Start()
       
    def Threads(self, packet):
        # Starting thread to ensure non blocking states
        threading.Thread(target=self.SignatureCheck, args=(packet,)).start()

    def SignatureCheck(self, packet):
        #setting variables and filtering out ICMP
        log = False
        hittime = int(time.time())
        dst_ip = packet.dst
        print(dst_ip)
        src_ip = packet.src
        if (packet.protocol != 1):
            dport = packet.dport
            sport = packet.sport
       
        # Catches initial request to interesting traffic, filtering for local host > FW
        if (dst_ip in self.tor_nodes):
            print('Detected connection to TOR Node: {}'.format(dst_ip))
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
                print('Detected response from TOR Node: {}'.format(src_ip))
                self.session_tracker.pop(dport, None)
                category = self.tor_nodes[src_ip]
                blocked = False
                log = True
                # Reversing src/dst to show initial connection.
                src_ip = packet.dst
                dst_ip = packet.src
        
        # logging to database if filters detect interesting tracking, noting block /allow
        if (log):
            print('Logged {}: {}'.format(dst_ip, blocked))
            ProxyDB = DBConnector(table='FWBlocks')
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
            
            
            
            
                

