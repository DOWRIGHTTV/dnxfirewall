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
from scan_ddos_detect.scan_ddos_proxy_sniffer import Sniffer
from scan_ddos_detect.scan_ddos_proxy_response import ICMPResponse

class SCANProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open(f'{self.path}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)
                                
        self.lan_int = self.setting['Settings']['Interface']['Inside']
        self.wan_int = self.setting['Settings']['Interface']['Outside']
        self.lan_int = 'eth0'
        self.wan_int = 'eth0'

        Int = Interface()
        self.broadcast = Int.Broadcast(self.lan_int)
        # self.insideip = Int.IP(self.lan_int)
        self.DEVNULL = open(os.devnull, 'wb')

        self.udp_scan_tracker = {}
        self.tcp_scan_tracker = {}

        self.udp_scan_drop = {}
                
    def Start(self):       
        self.ProxyDB()
        
        self.Proxy()

    def ProxyDB(self):
        for table in {'DNSProxy', 'PIHosts'}:
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.Cleaner()
            ProxyDB.Disconnect()
                    
    def Proxy(self):
    
        Proxy = Sniffer(self.lan_int, action=self.SignatureCheck)
        Proxy.Start()
       
    def SignatureCheck(self, packet):
        try:
            scan_detected = False
            udp_scan_filter = False

            src_ip = packet.src_ip
            dst_ip = packet.dst_ip
            src_port = packet.src_port
            dst_port = packet.dst_port
            protocol = packet.protocol 

            if (protocol in {17} and dst_ip != self.broadcast):
                udp_length = packet.udp_length
                if (udp_length == 8):
                    scan_detected = True
                    udp_scan_filter = True
                
                if (src_ip not in self.udp_scan_tracker):
                    self.udp_scan_tracker[src_ip] = {dst_port}
                    threading.Thread(target=self.Timer, args=(src_ip,)).start()
                else:
                    self.udp_scan_tracker[src_ip].update({dst_port})

                if (src_ip in self.udp_scan_tracker and not scan_detected):
                    connections = len(self.udp_scan_tracker.get(src_ip, 0))
                    if (connections >= 3):
                        scan_detected = True
                        udp_scan_filter = True
                        if (src_ip not in self.udp_scan_drop):
                            threading.Thread(target=self.Timeout, args=(src_ip,)).start()
                        else:
                            self.udp_scan_drop[src_ip].update(time.time())

            if (scan_detected):
                print(f'SCAN DETECTED FROM: {src_ip}| PROTOCOL: {protocol} | PORT: {dst_port}')

            if (udp_scan_filter):
                ICMP = ICMPResponse(self.wan_int, packet)
                ICMP.Response()

        except Exception as E:
            print(E)

    def Timer(self, src_ip):
        time.sleep(5)
        self.udp_scan_tracker.pop(src_ip, None)

    def Timeout(self, src_ip)
        self.udp_scan_drop[src_ip] = time.time()
        while True:
            now = time.time()
            last_scan = self.udp_scan_drop.get(src_ip, now)
            if (now - last_scan >= 10):
                self.udp_scan_tracker.pop(src_ip, None))
                self.udp_scan_drop.pop(src_ip, None)
                break


        
if __name__ == '__main__':
    DNSP = SCANProxy()
    DNSP.Start()