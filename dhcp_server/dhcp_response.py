#!/usr/bin/python3

import os, sys, time, subprocess
import threading, asyncio
import struct

from socket import *
from dnx_configure.system_info import Interface

class DHCPResponse:
    def __init__(self, insideint, xid, mac, ciaddr, chaddr, options, Leases):
        Int = Interface()
        self.insideip = Int.IP(insideint)

        self.Leases = Leases

        self.xID = xid
        self.chaddr = chaddr
        self.ciaddr = ciaddr
        self.serveroptions = options

        self.yiaddr = self.Leases.Handout(mac)
        print('Handing Out: {}'.format(self.yiaddr))

    def Assemble(self):
        self.create_dhcp_packet()
        self.assemble_dhcp_packet()
        self.AssembleOptions()
        
        self.dhcp += self.options
        
        return self.dhcp
                
    def AssembleOptions(self):
        self.options = b''
        for option in self.serveroptions:
            optlen = self.serveroptions[option][0]
            opt = self.serveroptions[option][1]
            if (option in {53}):
                self.options += struct.pack('!3B', option, optlen, opt)
            elif (option in {1,3,6,28,54}):
                self.options += struct.pack('!2B', option, optlen) + opt
            elif (option == 26):
                self.options += struct.pack('!2BH', option, optlen, opt)
            elif (option in {51,58,59}):
                self.options += struct.pack('!2BL', option, optlen, opt)
            else:
                pass
        self.options += b'\xFF\x00'
        
    def create_dhcp_packet(self):
        self.op         = 2
        self.htype      = 1
        self.hlen       = 6
        self.hops       = 0
        self.xid        = self.xID
        self.secs       = 0
        self.flags      = 0
        self.ciaddr     = inet_aton(self.ciaddr)
        self.yiaddr     = inet_aton(self.yiaddr)
        self.siaddr     = inet_aton(self.insideip)
        self.giaddr     = inet_aton('0.0.0.0')
        
        self.chaddr     = self.chaddr
        self.dnx        = struct.pack('!12s', b'DNX FIREWALL')
        self.dnxpad     = struct.pack('!52s', b'\x00' * 52)                         
        self.sname      = self.dnx + self.dnxpad
        self.filename     = struct.pack('!128s', b'\x00' * 128)
        self.mcookie    = struct.pack('!4B', 99, 130, 83, 99)                   

    def assemble_dhcp_packet(self):
        self.dhcp = struct.pack('!4B' ,
        self.op,
        self.htype,
        self.hlen,
        self.hops
        )
        self.dhcp += self.xid
        self.dhcp += struct.pack('2H4s4s4s4s',
        self.secs,
        self.flags,
        self.ciaddr,
        self.yiaddr,
        self.siaddr,
        self.giaddr
        )
        self.dhcp += self.chaddr + self.sname + self.filename + self.mcookie
    
