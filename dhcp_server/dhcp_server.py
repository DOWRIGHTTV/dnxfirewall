#!/usr/bin/python3

import os, sys, time, subprocess
import threading, asyncio
import struct
import json

from socket import socket, inet_aton, AF_INET, SOCK_DGRAM
from socket import SOL_SOCKET, SO_BROADCAST, SO_BINDTODEVICE, SO_REUSEADDR
from collections import OrderedDict

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_logging.log_main import LogHandler
from dnx_configure.dnx_system_info import Interface as Int
from dhcp_server.dhcp_leases import DHCPLeases
from dhcp_server.dhcp_response import DHCPResponse

LOG_MOD = 'dhcp_server'


class DHCPServer:
    def __init__(self):
        self.Log = LogHandler(LOG_MOD)
        # add configuration check for icmp checks prior to handing out ip.
        self.icmp_check = True
        self.Leases = DHCPLeases(self)

        self.ongoing = {}

        self.handout_lock = threading.Lock()
        self.log_queue_lock = threading.Lock()

    def Start(self):
        self.LoadInterfaces()
        # -- Creating Lease Dictionary -- #
        self.Leases.BuildRange()
        self.Leases.LoadLeases()
        # -- Building Server Options Dictionary -- #
        self.SetServerOptions()
        # -- Creating socket && starting main server thread -- #
        self.CreateSocket()
        threading.Thread(target=self.Server).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    async def Main(self):
        ## -- Starting Server and Timers in Asyncio Gather -- ##
        await asyncio.gather(self.Leases.LeaseTimer(), self.Leases.ReservationTimer(),
                            self.Leases.WritetoFile(), self.Log.QueueHandler(self.log_queue_lock))

    def CreateSocket(self):
        self.s = socket(AF_INET, SOCK_DGRAM)
        self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        self.s.setsockopt(SOL_SOCKET, SO_BROADCAST,1)
        self.s.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self.bind_int)
        self.s.bind(('0.0.0.0', 67))
        print('[+] Listening on Port 67')

    def Server(self):
        while True:
            try:
                Parse = DHCPParser(self.dhcp_server_options)
                rdata = self.s.recv(1024) ## removed recvfrom, dont need since ip of client is identified in packet
                print(rdata)
                response_info, options = Parse.Data(rdata)
                options = Parse.Options(options)
                threading.Thread(target=self.Response, args=(response_info, options)).start()
            except Exception as E:
                print(E)

    def Response(self, response_info, options):
        print('Response Thread')
        mtype, xID, ciaddr, mac_address = response_info
        if (mac_address in self.ongoing and self.ongoing[mac_address] != xID):
            options[53] = [1, DHCP_NAK]
        elif mtype == DHCP_DISCOVER:
            options[53] = [1, DHCP_OFFER]
        elif mtype == DHCP_REQUEST:
            options[53] = [1, DHCP_ACK]
        elif mtype == DHCP_RELEASE:
            self.Leases.Release(ciaddr, mac_address)

        if (mtype != DHCP_RELEASE):
            self.SendResponse(response_info, options)

    def SendResponse(self, response_info, options):
        print('Send Thread')
        mtype, xID, ciaddr, mac_address = response_info
        mtype = options[53][1]
        ## -- Set ongiong request flag, NAK duplicates -- ##
        if (mtype != DHCP_NAK):
            self.ongoing[mac_address] = xID
            threading.Thread(target=self.OngoingTimer, args=(mac_address,)).start()

        ## locking handout method call to ensure checking/setting leases is thread safe
        with self.handout_lock:
            handout_ip = self.Leases.Handout(mac_address)

        response_info =  xID, mac_address, ciaddr, handout_ip, options
        Response = DHCPResponse(response_info)
        sdata = Response.Assemble()
        if (mtype in {DHCP_OFFER, DHCP_ACK, DHCP_NAK} and handout_ip):
            if (ciaddr == '0.0.0.0'):
                print(f'Sent BROADCAST TYPE: {mtype} to 255.255.255.255:68')
                self.s.sendto(sdata, ('255.255.255.255', 68))
            else:
                print(f'Sent UNICAST TYPE: {mtype} to {ciaddr}:68')
                self.s.sendto(sdata, (ciaddr, 68))

        ## -- Remove ongiong request flag, NAK duplicates -- ##
        if (mtype == DHCP_ACK and handout_ip):
            self.ongoing.pop(mac_address, None)

    def SetServerOptions(self):
        print('[+] DHCP: Setting server options.')
        insideip, netmask, broadcast, mtu = self.InterfaceInfo()
        dhcp_server_options = {}

        dhcp_server_options[1] = [4, inet_aton(netmask)]         # OPT 1  | Subnet Mask
        dhcp_server_options[3] = [4, inet_aton(insideip)]        # OPT 3  | Router
        dhcp_server_options[6] = [4, inet_aton(insideip)]        # OPT 6  | DNS Server
        dhcp_server_options[26] = [2, mtu]                       # OPT 26 | MTU
        dhcp_server_options[28] = [4, inet_aton(broadcast)]      # OPT 28 | Broadcast
        dhcp_server_options[51] = [4, 86400]                     # OPT 51 | Lease Time
        dhcp_server_options[54] = [4, inet_aton(insideip)]       # OPT 54 | Server Identity
        dhcp_server_options[58] = [4, 43200]                     # OPT 58 | Renew Time
        dhcp_server_options[59] = [4, 74025]                     # OPT 59 | Rebind Time

        self.dhcp_server_options = dhcp_server_options

    def OngoingTimer(self, mac):
        time.sleep(6)
        self.ongoing.pop(mac, None)

    def InterfaceInfo(self):
        Interface = Int()
        insideip = Interface.IP(self.lan_int)
        netmask = Interface.Netmask(self.lan_int)
        broadcast = Interface.Broadcast(self.lan_int)
        mtu = Interface.MTU(self.lan_int)

        return(insideip, netmask, broadcast, mtu)

    def LoadInterfaces(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        self.lan_int = setting['settings']['interface']['inside']
        self.bind_int = f'{self.lan_int}\0'.encode('utf-8')

class DHCPParser:
    def __init__(self, dhcp_server_options):
        self.dhcp_server_options = dhcp_server_options
        self.mtypeopt = []

    def Options(self, client_options):
        server_options_reponse = OrderedDict()
        server_options_reponse[54] = self.dhcp_server_options[54]
        server_options_reponse[53] = self.mtypeopt
        if (51 not in client_options):
            server_options_reponse[51] = self.dhcp_server_options[51]

        for option in client_options:
            server_option = self.dhcp_server_options.get(option, None)
            if (server_option):
                server_options_reponse[option] = server_option

        return server_options_reponse

    def Data(self, data):
        xID = data[4:8]
        ciaddr = data[12:16]
        mac = data[28:28+6] # MAC ADDR ONLY
        mtype = data[242]

        mac = struct.unpack('!6c', mac)
        mac_address = ''
        for i, byte in enumerate(mac, 1):
            if (i != 1):
                mac_address += ':'
            mac_address += f'{byte.hex()}'

        cia = struct.unpack('!4B', ciaddr)
        ciaddr = f'{cia[0]}.{cia[1]}.{cia[2]}.{cia[3]}'

        options = OrderedDict()
        if mtype != DHCP_RELEASE:
            for b, byte in enumerate(reversed(data), 1):
                if (byte == 55):
                    paramlen = data[-(b-1)]
                    for opt in data[-(b-2):-(b-2) + paramlen]:
                        options[opt] = None
                    break

        return (mtype, xID, ciaddr, mac_address), options

if __name__ == '__main__':
    DHCPServer = DHCPServer()
    DHCPServer.Start()
