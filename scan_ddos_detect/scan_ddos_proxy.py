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
        self.wan_ip = Int.IP(self.wan_int)

        Int = Interface()
        self.broadcast = Int.Broadcast(self.wan_int)
        # self.insideip = Int.IP(self.lan_int)
        self.DEVNULL = open(os.devnull, 'wb')

        self.udp_scan_tracker = {}
        self.tcp_scan_tracker = {}
        self.udp_scan_drop = {}
        self.tcp_scan_drop = {}

        self.open_udp_ports = {6969}
        self.open_tcp_ports = {}

        self.ddos_tracker = {}
        self.active_ddos = {}

        self.ddos_prevention = True
        self.port_scan_logging = True
        self.port_scan_prevention = True
                
    def Start(self):       
        self.ProxyDB()

        if (self.ddos_prevention):
            threading.Thread(target=self.DDOS).start()
        
        if (self.ddos_prevention or self.port_scan_logging):
            self.Proxy()

    def ProxyDB(self):
        for table in {'DNSProxy', 'PIHosts'}:
            ProxyDB = DBConnector(table)
            ProxyDB.Connect()
            ProxyDB.Cleaner()
            ProxyDB.Disconnect()
                    
    def Proxy(self):
    
        Proxy = Sniffer(self.wan_int, self.wan_ip, action=self.SignatureCheck)
        Proxy.Start()
       
    def SignatureCheck(self, packet):
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        dst_port = packet.dst_port
        if (dst_ip == self.wan_ip and packet.protocol in {6} and dst_port in self.open_tcp_ports):
            if (packet.tcp_syn and not packet.tcp_ack):
                count = self.ddos_tracker[dst_ip].get(src_ip, 0)
                count += 1
                self.ddos_tracker[dst_ip].update({src_ip: count})
        elif (dst_ip == self.wan_ip and packet.protocol in {17} and dst_port in self.open_udp_ports):
                count = self.ddos_tracker[dst_ip].get(src_ip, 0)
                count += 1
                self.ddos_tracker[dst_ip].update({src_ip: count})

        if (not self.active_ddos):
            self.PortScan(packet)

    def DDOS(self):
        self.ddos_tracker[self.wan_ip] = {}
        self.source_limit = 100 # Make this configurable
        self.dest_limit = 200 # make this configurable
        while True:
            hosts = self.ddos_tracker[self.wan_ip]
            for host, count in hosts.items():
                if (count/5 > self.source_limit):
                    self.active_ddos = True
                    #BLOCK SOURCE IP WITH IPTABLE?
                elif (count == 0):
                    hosts.pop(host)
                hosts[host] = 0
            else:
                self.active_ddos = False

            time.sleep(5)

    def PortScan(self, packet):
        scan_detected = False
        udp_scan_filter = False
        tcp_scan_filter = False

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_port = packet.src_port
        dst_port = packet.dst_port
        protocol = packet.protocol

        if (protocol in {17} and dst_ip != self.broadcast):
            udp_length = packet.udp_length
            print(f'{src_ip}:{src_port} | UDP | {dst_port}')
            if (udp_length == 8):
                scan_detected = True
                udp_scan_filter = True
            
            if (src_ip not in self.udp_scan_tracker):
                self.udp_scan_tracker[src_ip] = {dst_port}
#                    threading.Thread(target=self.Timer, args=(src_ip,)).start()
            else:
                self.udp_scan_tracker[src_ip].update({dst_port})

            if (src_ip in self.udp_scan_tracker):
                connections = len(self.udp_scan_tracker.get(src_ip, 0))                 
                if (connections >= 3):
                    scan_detected = True
                    udp_scan_filter = True

                if (udp_scan_filter and src_ip not in self.udp_scan_drop):
                    self.udp_scan_drop[src_ip] = time.time()
                    threading.Thread(target=self.UDPTimeout, args=(src_ip,)).start()
                elif (udp_scan_filter and src_ip in self.udp_scan_drop):
                    self.udp_scan_drop.update({src_ip: time.time()})

        elif (protocol in {6} and dst_ip != self.broadcast):
            if (src_ip != self.wan_ip and packet.tcp_syn and not packet.tcp_ack):
                print(f'{src_ip}:{src_port} | SYN | {dst_port}')
                if (src_ip not in self.tcp_scan_tracker):
                    self.tcp_scan_tracker[src_ip] = {src_port: 1, dst_port: {'SYN': True, 'SYN/ACK': False, 'ACK': False}}
                else:
                    count = self.tcp_scan_tracker[src_ip].get(src_port)
                    count += 1
                    self.tcp_scan_tracker[src_ip].update({src_port: count})
                    self.tcp_scan_tracker[src_ip].update({dst_port: {'SYN': True, 'SYN/ACK': False, 'ACK': False}})
            elif (src_ip == self.wan_ip and packet.tcp_syn and packet.tcp_ack):
                print(f'SYN/ACK: {dst_ip}')
                self.tcp_scan_tracker[dst_ip].update({src_port: {'SYN/ACK': True}})
                self.TCPTimer(dst_ip, src_port)
            elif (src_ip != self.wan_ip and not packet.tcp_syn and packet.tcp_ack):
                print(f'ACK: {dst_ip}')
                self.tcp_scan_tracker[src_ip].update({dst_port: {'ACK': True}})

            if (src_ip in self.tcp_scan_tracker):
                count = self.tcp_scan_tracker[src_ip].get(src_port, 0)
                connections = len(self.tcp_scan_tracker.get(src_ip, 0))
                if (count >= 2):
                    scan_detected = True
                    tcp_scan_filter = True
                elif (connections >= 3):
                    scan_detected = True
                    tcp_scan_filter = True
                elif (src_ip in self.tcp_scan_drop):
                    scan_detected = True
                    tcp_scan_filter = True
                
                if (tcp_scan_filter and src_ip not in self.tcp_scan_drop):
                    self.tcp_scan_drop[src_ip] = time.time()
                    threading.Thread(target=self.TCPTimeout, args=(src_ip,)).start()
                elif (tcp_scan_filter and src_ip in self.tcp_scan_drop):
                    self.tcp_scan_drop.update({src_ip: time.time()})

        if (scan_detected):
            print(f'SCAN DETECTED FROM: {src_ip}| PROTOCOL: {protocol} | PORT: {dst_port}')

        if (self.port_scan_prevention or udp_scan_filter and dst_port in self.open_udp_ports):
            ICMP = ICMPResponse(self.wan_int, packet)
            ICMP.Response()
        elif (self.port_scan_prevention or tcp_scan_filter and dst_port in self.open_tcp_ports):
            #TCP = TCPResponse(self.wan_int, packet)
            #TCP.Response()
            pass

    def TCPTimer(self, dst_ip, src_port):
        tcp_syn = self.tcp_scan_tracker[dst_ip][src_port].get('SYN')
        tcp_syn_ack = self.tcp_scan_tracker[dst_ip][src_port].get('SYN/ACK')
        time.sleep(1)
        tcp_ack = self.tcp_scan_tracker[dst_ip][src_port].get('ACK')
        if (tcp_syn and tcp_syn_ack and not tcp_ack):
            self.tcp_scan_drop[dst_ip] = time.time()

    def TCPTimeout(self, src_ip):
        while True:
            now = time.time()
            last_scan = self.tcp_scan_drop.get(src_ip, now)
            if (now - last_scan >= 3):
                self.tcp_scan_tracker.pop(src_ip, None)
                self.tcp_scan_drop.pop(src_ip, None)
                break
            time.sleep(1)

    def UDPTimeout(self, src_ip):
        while True:
            now = time.time()
            last_scan = self.udp_scan_drop.get(src_ip, now)
            if (now - last_scan >= 3):
                self.udp_scan_tracker.pop(src_ip, None)
                self.udp_scan_drop.pop(src_ip, None)
                break
            time.sleep(1)


        
if __name__ == '__main__':
    DNSP = SCANProxy()
    DNSP.Start()