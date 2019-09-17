#!/usr/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_system_info import System as Sys

class SyslogFormat:
    def __init__(self):
        self.System = Sys()

    def Message(self, system_ip, module, msg_type, msg_level, message):
        epoch = time.time()

        date = self.Date()
        timestamp = self.System.FormatTime(epoch)
        msg_type = self.ReturnType(msg_type)
        msg_level = self.ReturnLevel(msg_level)

        #add time offset??
        #20140624|19:08:15|EVENT|DNSProxy:Informational|192.168.83.1|src.mac={}; src.ip={}; domain={}; category={}; filter={}; action={}
        message = f'{date}|{timestamp}|{msg_type}|{module}:{msg_level}|{system_ip}|{message}'

        return message

    def ReturnType(self, msg_type):
        # T3 = System Daemons | T14 = Event/Log Alert
        if (msg_type == 3):
            msg_type = 'SYSTEM'
        elif (msg_type == 14):
            msg_type = 'EVENT'

        return msg_type

    def Date(self):
        d = self.System.Date()
        date = f'{d[0]}{d[1]}{d[2]}'

        return date

    def ReturnLevel(self, level):
        log_levels = {
            0 : 'Emergency', # system is unusable
            1 : 'Alert', #action must be taken immediately
            2 : 'Critical', # critical conditions
            3 : 'Error', # error conditions
            4 : 'Warning', # warning conditions
            5 : 'Notice', # normal but significant condition
            6 : 'Informational', # informational messages
            7 : 'Debug', # debug-level messages
        }

        return log_levels[level]
