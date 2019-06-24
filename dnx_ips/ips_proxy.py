#!/usr/bin/python3

import os, sys
import time, threading
import json
import traceback

from datetime import datetime
from subprocess import run
from copy import deepcopy

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface
from dnx_configure.dnx_db_connector import DBConnector
from dnx_ips.ips_proxy_sniffer import Sniffer
from dnx_ips.ips_proxy_response import ScanResponse

ICMP = 1
TCP = 6
UDP = 17

class IPSProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open(f'{self.path}/data/config.json', 'r') as settings:
            self.setting = json.load(settings)
                                
        self.lan_int = self.setting['Settings']['Interface']['Inside']
        self.wan_int = self.setting['Settings']['Interface']['Outside']

        Int = Interface()
        self.wan_ip = Int.IP(self.wan_int)
        self.broadcast = Int.Broadcast(self.wan_int)

        self.udp_scan_tracker = {}
        self.tcp_scan_tracker = {}
        self.udp_scan_drop = {}
        self.tcp_scan_drop = {}

        self.scan_mitigation = {}
        self.ddos_tracker = {self.wan_ip: {'TCP': {}, 'UDP': {}, 'ICMP': {}}}
        self.active_ddos = False
                
    def Start(self):
        self.ProxyDB()
        threading.Thread(target=self.LoadSettings).start()
        time.sleep(2)
        threading.Thread(target=self.ClearIPTables).start()
        threading.Thread(target=self.DDOS).start()

        self.Proxy()

    def ProxyDB(self):
        ProxyDB = DBConnector(table='IPS')
        ProxyDB.Connect()
        ProxyDB.Cleaner()
        ProxyDB.Disconnect()

    def LoadSettings(self):
        print('[+] Starting: IPS Settings Update Thread.')
        self.portscan_reject = False
        while True:
            with open(f'{self.path}/data/ips.json', 'r') as ips_settings:
                settings = json.load(ips_settings)

            self.ddos_prevention = settings['IPS']['DDOS']['Enabled']
            self.portscan_logging = settings['IPS']['PortScan']['Logging']
            self.portscan_prevention = settings['IPS']['PortScan']['Mitigation']

            IPSProxy.ddos_prevention = self.ddos_prevention
            IPSProxy.portscan_logging = self.portscan_logging

            # DDOS PPS THRESHHOLD CHECK
            self.tcp_src_limit = settings['IPS']['DDOS']['Limits']['Source']['TCP'] # Make this configurable
            self.udp_src_limit = settings['IPS']['DDOS']['Limits']['Source']['UDP']
            self.icmp_src_limit = settings['IPS']['DDOS']['Limits']['Source']['ICMP']
            self.combined_dst_limit = settings['IPS']['DDOS']['Limits']['Destination']['Combined']

            ##Checking length(hours) to leave IP Table Rules in place for Portscan
            self.mitigation_length = settings['IPS']['PortScan']['Length'] * 3600

            ## OPEN PORTS CHECK - TIED TO PUBLIC > PRIVATE NAT
            self.icmp_allow = settings['IPS']['OpenProtocols']['ICMP']
            self.open_tcp_ports = settings['IPS']['OpenProtocols']['TCP']
            self.open_udp_ports = settings['IPS']['OpenProtocols']['UDP']

            ## DNS SERVER CHECK
            with open(f'{self.path}/data/dns_server.json', 'r') as dns_servers:
                dns_server = json.load(dns_servers)
            dns1 = dns_server['DNSServer']['Resolvers']['Server1']['IP Address']
            dns2 = dns_server['DNSServer']['Resolvers']['Server2']['IP Address']

            self.dns_servers = {dns1, dns2}

            time.sleep(5*60)
                    
    def Proxy(self):
    
        Proxy = Sniffer(IPSProxy, self.wan_int, self.wan_ip, action=self.SignatureCheck)
        Proxy.Start()

    def SignatureCheck(self, packet):
        ddos_tracker = False
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        dst_port = packet.dst_port
        str_dst_port = str(dst_port)

        if (dst_ip == self.wan_ip and packet.protocol == TCP and str_dst_port in self.open_tcp_ports):
            if (packet.tcp_syn and not packet.tcp_ack):
                ddos_tracker = True
                protocol = 'TCP'

        elif (dst_ip == self.wan_ip and packet.protocol == UDP and str_dst_port in self.open_udp_ports):
            ddos_tracker = True
            protocol = 'UDP'

        elif (dst_ip == self.wan_ip and self.icmp_allow):
            ddos_tracker = True
            protocol = 'ICMP'

        if (ddos_tracker):
            count = self.ddos_tracker[dst_ip][protocol].get(src_ip, 0)
            count += 1
            self.ddos_tracker[dst_ip][protocol].update({src_ip: count})

        if (not self.active_ddos and packet.protocol != ICMP):
            self.PortScan(packet)

    def DDOS(self):
        print('[+] Starting: DDOS Detection Thread.')
        while True:
            if (self.ddos_prevention):
                protocols = deepcopy(self.ddos_tracker)
                for ip, tracker in protocols.items():
                    for protocol, connections in tracker.items():
                        for connection, count in connections.items():
                            if (count/5 >= self.tcp_src_limit):
                                self.active_ddos = True
                            elif (count/5 >= self.udp_src_limit):
                                self.active_ddos = True
                            elif (count/5 >= self.icmp_src_limit):
                                self.active_ddos = True

                            if (self.active_ddos):
                                run(f'sudo iptables -A DDOS -p {protocol.lower()} -s {connection} -j DROP', shell=True)
                                
                                timestamp = round(time.time())
                                attack_type = 'DDOS'
                                action = 'Blocked'

                                self.Logging(connection, protocol, attack_type, action, timestamp)

                            if (count != 0):
                                self.ddos_tracker[ip][protocol].update({connection: 0})
                            else:
                                print(self.ddos_tracker[ip][protocol])
                                self.ddos_tracker[ip][protocol].pop(connection, None)
                        else:
                            self.active_ddos = False

                time.sleep(5)
            else:
                time.sleep(5 * 60)

    def PortScan(self, packet):
        logging = False
        scan_detected = False
        attack_type = 'Port Scan'

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_port = packet.src_port
        dst_port = packet.dst_port
        str_dst_port = str(dst_port)
        protocol = packet.protocol

        if (protocol == TCP and dst_ip != self.broadcast):
            if (src_ip != self.wan_ip and packet.tcp_syn and not packet.tcp_ack):
                print(f'{src_ip}:{src_port} | SYN | {dst_port}')
                if (src_ip not in self.tcp_scan_tracker):
                    self.tcp_scan_tracker[src_ip] = {src_port: 1, dst_port: {'SYN': True, 'SYN/ACK': False, 'ACK': False}}
                else:
                    count = self.tcp_scan_tracker[src_ip].get(src_port, 0)
                    count += 1
                    self.tcp_scan_tracker[src_ip].update({src_port: count})
                    self.tcp_scan_tracker[src_ip].update({dst_port: {'SYN': True, 'SYN/ACK': False, 'ACK': False}})
            elif (src_ip == self.wan_ip and packet.tcp_syn and packet.tcp_ack):
#                print(f'SYN/ACK: {dst_ip}')
                self.tcp_scan_tracker[dst_ip][src_port].update({'SYN/ACK': True})
                self.TCPTimer(dst_ip, src_port)
            elif (src_ip != self.wan_ip and not packet.tcp_syn and packet.tcp_ack):
#                print(f'ACK: {dst_ip}')
                self.tcp_scan_tracker[src_ip][dst_port].update({'ACK': True})

            if (src_ip in self.tcp_scan_tracker):
                count = self.tcp_scan_tracker[src_ip].get(src_port, 0)
                connections = len(self.tcp_scan_tracker.get(src_ip, 0))
                if (count >= 2):
                    scan_detected = True

                elif (connections >= 3):
                    scan_detected = True

                elif (src_ip in self.tcp_scan_drop):
                    scan_detected = True
                
                timestamp = round(time.time())
                if (scan_detected and src_ip not in self.tcp_scan_drop):
                    self.tcp_scan_drop[src_ip] = timestamp
                    threading.Thread(target=self.TCPTimeout, args=(src_ip,)).start()
                elif (scan_detected and src_ip in self.tcp_scan_drop):
                    self.tcp_scan_drop[src_ip] = timestamp

        elif (protocol == UDP):
            udp_length = packet.udp_length
#            print(f'{src_ip}:{src_port} | UDP | {dst_port}')
            if (udp_length == 8 and src_ip not in self.dns_servers):
                scan_detected = True
            
            if (src_ip not in self.udp_scan_tracker):
                self.udp_scan_tracker[src_ip] = {dst_port}
            else:
                self.udp_scan_tracker[src_ip].update({dst_port})

            if (src_ip in self.udp_scan_tracker):
                connections = len(self.udp_scan_tracker.get(src_ip, 0))                 
                if (connections >= 3 and src_ip not in self.dns_servers):
                    scan_detected = True

                timestamp = round(time.time())
                if (scan_detected and src_ip not in self.udp_scan_drop):
                    self.udp_scan_drop[src_ip] = timestamp
                    threading.Thread(target=self.UDPTimeout, args=(src_ip,)).start()
                elif (scan_detected and src_ip in self.udp_scan_drop):
                    self.udp_scan_drop.update({src_ip: timestamp})

        if (scan_detected and src_ip not in self.scan_mitigation):
            run(f'sudo iptables -I IPS -s {src_ip} -j DROP', shell=True)
            print(f'ADDING {src_ip} BLOCK.')
            self.scan_mitigation[src_ip] = timestamp

            print(f'SCAN DETECTED FROM: {src_ip}| PROTOCOL: {protocol} | PORT: {dst_port}')

        if (scan_detected and packet.protocol == UDP and str_dst_port in self.open_udp_ports):
            if (self.portscan_logging):
                protocol = 'UDP'
                action = 'Logged'
                logging = True

            if (self.portscan_prevention):
                action = 'Blocked'

            if (self.portscan_reject):
                ICMP = ScanResponse(self.wan_int, packet, protocol=UDP)
                ICMP.Response()

        elif (scan_detected and packet.protocol == TCP and str_dst_port in self.open_tcp_ports):
            if (self.portscan_logging):
                protocol = 'TCP'
                action = 'Logged'
                logging = True

            if (self.portscan_prevention): 
                action = 'Blocked'

            if (self.portscan_reject):
                TCP = ScanResponse(self.wan_int, packet, protocol=TCP)
                TCP.Response()

        if (logging):
            self.Logging(src_ip, protocol, attack_type, action, timestamp)

    def UDPTimeout(self, src_ip):
        while True:
            now = round(time.time())
            last_scan = self.udp_scan_drop.get(src_ip, now)
            if (now - last_scan >= 3):
                self.udp_scan_tracker.pop(src_ip, None)
                self.udp_scan_drop.pop(src_ip, None)
                break
            time.sleep(1)

    def TCPTimer(self, dst_ip, src_port):
        timestamp = round(time.time())
        tcp_syn = self.tcp_scan_tracker[dst_ip][src_port].get('SYN')
        tcp_syn_ack = self.tcp_scan_tracker[dst_ip][src_port].get('SYN/ACK')
        time.sleep(2)
        tcp_ack = self.tcp_scan_tracker[dst_ip][src_port].get('ACK')
        if (tcp_syn and tcp_syn_ack and not tcp_ack):
            action = 'Blocked'
            if (dst_ip in self.tcp_scan_drop):
                action = 'Logged'
            attack_type = 'Port Scan'
            protocol = 'TCP'

            self.tcp_scan_drop[dst_ip] = timestamp
            self.Logging(dst_ip, protocol, attack_type, action, timestamp)

    def TCPTimeout(self, src_ip):
        while True:
            now = round(time.time())
            last_scan = self.tcp_scan_drop.get(src_ip, now-3)
            if (now - last_scan >= 3):
                self.tcp_scan_tracker.pop(src_ip, None)
                self.tcp_scan_drop.pop(src_ip, None)

                if (self.mitigation_length == 0):
                    run(f'sudo iptables -D IPS -s {src_ip} -j DROP', shell=True)
                    print(f'REMOVING {src_ip} BLOCK.')
                    self.scan_mitigation.pop(src_ip, None)
                    
                break
            time.sleep(1)

    def Logging(self, src_ip, protocol, attack_type, action, timestamp):
        ProxyDB = DBConnector(table='IPS')
        ProxyDB.Connect()
        ProxyDB.IPSInput(src_ip, protocol, attack_type, action, timestamp)

    ## TEST THIS, REMOVING ITEM FROM DICT WHILE ITERATING || Should be ok because .items(), might need to copy()
    def ClearIPTables(self):
        print('[+] Starting: IP Tables Removal Thread.')
        while True:
            scan_mitigation = self.scan_mitigation.copy()
            if (self.mitigation_length > 0):
                now = time.time()
                for src_ip, time_added in scan_mitigation.items():
                    if (now - time_added >= self.mitigation_length):
                        run(f'sudo iptables -D IPS -s {src_ip} -j DROP', shell=True)
                        self.scan_mitigation.pop(src_ip, None)
            time.sleep(10 * 60)
        
if __name__ == '__main__':
    DNSP = IPSProxy()
    DNSP.Start()
