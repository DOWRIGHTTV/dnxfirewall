#!/usr/bin/python3

import os, sys, time, subprocess
import threading, asyncio
import struct

from socket import inet_aton

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_system_info import Interface

class DHCPResponse:
    def __init__(self, response_info):
        xID, ciaddr, chaddr, handout_ip, options = response_info

        self.xID = xID
        self.ciaddr = ciaddr
        self.chaddr = chaddr
        self.yiaddr = handout_ip
        self.server_options = options

        self.inside_ip = options.get(54)[1] # already A TO N :)

    def Assemble(self):
        self.CreateDHCP()
        self.AssembleDHCP()
        self.AssembleOptions()
        
        self.dhcp_response += self.options
        
        return self.dhcp_response
                
    def AssembleOptions(self):
        self.options = b''
        for option in self.server_options:
            optlen = self.server_options[option][0]
            opt = self.server_options[option][1]
            if (option in {53}):
                self.options += struct.pack('!3B', option, optlen, opt)
            elif (option in {1,3,6,28,54}):
                self.options += struct.pack('!2B', option, optlen) + opt
            elif (option in {26}):
                self.options += struct.pack('!2BH', option, optlen, opt)
            elif (option in {51,58,59}):
                self.options += struct.pack('!2BL', option, optlen, opt)

        self.options += b'\xFF\x00'
        
    def CreateDHCP(self):
        self.op         = 2
        self.htype      = 1
        self.hlen       = 6
        self.hops       = 0
        self.xid        = self.xID
        self.secs       = 0
        self.flags      = 0
        self.ciaddr     = inet_aton(self.ciaddr)
        self.yiaddr     = inet_aton(self.yiaddr)
        self.siaddr     = self.inside_ip
        self.giaddr     = inet_aton('0.0.0.0')
        
        self.chaddr     = self.chaddr
        self.dnx        = struct.pack('!12s', b'DNX FIREWALL')
        self.dnxpad     = struct.pack('!52s', b'\x00' * 52)                         
        self.sname      = self.dnx + self.dnxpad
        self.filename     = struct.pack('!128s', b'\x00' * 128)
        self.mcookie    = struct.pack('!4B', 99, 130, 83, 99)                   

    def AssembleDHCP(self):
        self.dhcp_response = struct.pack('!4B' ,
        self.op,
        self.htype,
        self.hlen,
        self.hops
        )
        self.dhcp_response += self.xid
        self.dhcp_response += struct.pack('2H4s4s4s4s',
        self.secs,
        self.flags,
        self.ciaddr,
        self.yiaddr,
        self.siaddr,
        self.giaddr
        )
        self.dhcp_response += self.chaddr + self.sname + self.filename + self.mcookie
    