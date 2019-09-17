#!/usr/bin/python3

import os, sys, time, subprocess
import threading, asyncio
import struct, binascii

from socket import inet_aton

class DHCPResponse:
    def __init__(self, response_info):
        xID, mac_address, ciaddr, handout_ip, options = response_info

        self.xID = xID
        self.mac_address = mac_address.replace(':', '')
        self.ciaddr = ciaddr
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
        for option_number, options in self.server_options.items():
            option_length, option_value = options
            if (option_number in {53}):
                self.options += struct.pack('!3B', option_number, option_length, option_value)
            elif (option_number in {1,3,6,28,54}):
                self.options += struct.pack('!2B', option_number, option_length) + option_value
            elif (option_number in {26}):
                self.options += struct.pack('!2BH', option_number, option_length, option_value)
            elif (option_number in {51,58,59}):
                self.options += struct.pack('!2BL', option_number, option_length, option_value)

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

        self.chaddr     = binascii.unhexlify(self.mac_address) + b'\x00' * 10
        self.dnx        = b'DNX FIREWALL'
        self.dnxpad     = b'\x00' * 52
        self.sname      = self.dnx + self.dnxpad
        self.filename   = b'\x00' * 128
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
        self.dhcp_response += struct.pack('!16s',
        self.chaddr
        )
        self.dhcp_response += struct.pack('!64s',
        self.sname
        )
        self.dhcp_response += struct.pack('!128s',
        self.filename
        )
        self.dhcp_response += self.mcookie
