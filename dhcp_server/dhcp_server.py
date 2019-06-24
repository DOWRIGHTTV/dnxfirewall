#!/usr/bin/python3

import os, sys, time, subprocess
import threading, asyncio
import struct
import json

from socket import socket, inet_aton, AF_INET, SOCK_DGRAM, \
    SOL_SOCKET, SO_BROADCAST, SO_BINDTODEVICE, SO_REUSEADDR
from collections import OrderedDict

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface
from dhcp_server.dhcp_leases import DHCPLeases
from dhcp_server.dhcp_response import DHCPResponse

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4 # allow better support for this without fully conforming to RFC
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8 # Add support

class DHCPServer:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        # add configuration check for icmp checks prior to handing out ip.
        self.Leases = DHCPLeases(icmp_check=True)

        with open(f'{self.path}/data/config.json', 'r') as settings:
            setting = json.load(settings)

        self.lan_int = setting['Settings']['Interface']['Inside']
        self.bind_int = f'{self.lan_int}\0'.encode('utf-8')
        self.ongoing = {}

    def Start(self):      
        # -- Creating Lease Dictionary -- #
        self.Leases.BuildRange()
        self.Leases.LoadLeases()
        # -- Building Server Options Dictionary -- #
        self.SetServerOptions()
        threading.Thread(target=self.Server).start()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    async def Main(self):
        ## -- Starting Server and Timers in Asyncio Gather -- ##
        await asyncio.gather(self.Leases.LeaseTimer(), self.Leases.ReservationTimer(), 
            self.Leases.WritetoFile())
        
    def Server(self):
        ## -- Creating Sockets -- ##        
        self.s = socket(AF_INET, SOCK_DGRAM)
        self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        self.s.setsockopt(SOL_SOCKET, SO_BROADCAST,1)
        self.s.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self.bind_int)
        self.s.bind(('0.0.0.0', 67))
        print('[+] Listening on Port 67')
        while True:
            try:
                Parse = DHCPParser(self.dhcp_server_options)
                rdata, (self.addr, _) = self.s.recvfrom(1024)

                response_info, options, self.broadcast = Parse.Data(rdata)
                options = Parse.Options(options)
                threading.Thread(target=self.Response, args=(response_info, options)).start()
            except Exception as E:
                print(E)
                
    def Response(self, response_info, options):
        mtype, xID, src_mac, ciaddr, _ = response_info
        if (src_mac in self.ongoing and self.ongoing[src_mac] != xID):
            options[53] = [1, DHCP_NAK]
        elif mtype == DHCP_DISCOVER:
            options[53] = [1, DHCP_OFFER]
        elif mtype == DHCP_REQUEST:
            options[53] = [1, DHCP_ACK]
        elif mtype == DHCP_RELEASE:
            self.Leases.Release(ciaddr, src_mac)

        if (mtype != DHCP_RELEASE):
            self.SendResponse(response_info, options)
                    
    def SendResponse(self, response_info, options):
        mtype, xID, src_mac, ciaddr, chaddr = response_info
        mtype = options[53][1]
        ## -- Set ongiong request flag, NAK duplicates -- ##  
        if (mtype != DHCP_NAK):
            self.ongoing[src_mac] = xID
            threading.Thread(target=self.OngoingTimer, args=(src_mac,)).start()
        
        handout_ip = self.Leases.Handout(src_mac)
        response_info =  xID, ciaddr, chaddr, handout_ip, options
        Response = DHCPResponse(response_info)
        sdata = Response.Assemble()
        if (mtype in {DHCP_OFFER, DHCP_ACK, DHCP_NAK} and handout_ip):
            if (self.broadcast):
#                print(f'Sent BROADCAST TYPE: {mtype} to 255.255.255.255:68')
                self.s.sendto(sdata, ('255.255.255.255', 68))
            else:
#                print(f'Sent UNICAST TYPE: {mtype} to {self.addr}:68')
                self.s.sendto(sdata, (ciaddr, 68))
            
        ## -- Remove ongiong request flag, NAK duplicates -- ##
        if (mtype == DHCP_ACK and handout_ip):
            self.ongoing.pop(src_mac, None)

    def SetServerOptions(self):
        print('[+] DHCP: Setting server options.')
        insideip, netmask, broadcast, mtu = self.InterfaceInfo()
        dhcp_server_options = {}
                
        dhcp_server_options[1] = [4, inet_aton(netmask)]         # OPT 1  | Subnet Mask
        dhcp_server_options[3] = [4, inet_aton(insideip)]        # OPT 3  | Router
        dhcp_server_options[6] = [4, inet_aton(insideip)]        # OPT 6  | DNS Server
        dhcp_server_options[26] = [2, int(mtu)]                  # OPT 26 | MTU
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
        Int = Interface()
        insideip = Int.IP(self.lan_int)
        netmask = Int.Netmask(self.lan_int)
        broadcast = Int.Broadcast(self.lan_int)
        mtu = Int.MTU(self.lan_int)
        
        return(insideip, netmask, broadcast, mtu)

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
        options = OrderedDict()
        
        xID = data[4:8]
        ciaddr = data[12:16]
        mac = data[28:28+6] # MAC ADDR ONLY
        chaddr = data[28:28+16]
        mtype = data[242]     
        
        mac = struct.unpack("!6c", mac)
        m = []
        for byte in mac:
            m.append(byte.hex())

        cia = struct.unpack("!4B", ciaddr)
        
        mac = f'{m[0]}:{m[1]}:{m[2]}:{m[3]}:{m[4]}:{m[5]}'
        ciaddr = f'{cia[0]}.{cia[1]}.{cia[2]}.{cia[3]}'
        
        if mtype != DHCP_RELEASE:
            for b, byte in enumerate(reversed(data), 1):
                if (byte == 55):
                    paramlen = data[-(b-1)]
                    for opt in data[-(b-2):-(b-2) + paramlen]:
                        options[opt] = None
                    break
        
        if (data[10] & 1 << 7): # broadcast
            broadcast = True
        else:
            broadcast = False
        
        return (mtype, xID, mac, ciaddr, chaddr), options, broadcast
        
if __name__ == '__main__':
    DHCPServer = DHCPServer()
    DHCPServer.Start()
