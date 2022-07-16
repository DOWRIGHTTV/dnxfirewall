#!/usr/bin/env python3

from __future__ import annotations

import time

from dnx_gentools.system_info import System


class SyslogFormat:
    def message(self, system_ip, module, msg_type, msg_level, message):
        epoch = time.time()

        date = ''.join(self.System.date())
        timestamp = System.format_time(epoch)
        msg_type  = self._convert_type(msg_type)
        msg_level = self._convert_level(msg_level)

        # using system/UTC time
        # 20140624|19:08:15|EVENT|DNSProxy:Informational|192.168.83.1|*MESSAGE*
        message = f'{date}|{timestamp}|{msg_type}|{module}:{msg_level}|{system_ip}|{message}'

        return message.encode('utf-8')

    def return_type(self, msg_type):
        # T3 = System Daemons | T14 = Event/Log Alert
        if (msg_type == 3):
            msg_type = 'system'
        elif (msg_type == 14):
            msg_type = 'event'

        return msg_type

    def return_level(self, level):
        '''converts log level as integer to string. valid input: 0-7'''
        log_levels = {
            0 : 'emergency',      # system is unusable
            1 : 'alert',          # action must be taken immediately
            2 : 'critical',       # critical conditions
            3 : 'error',          # error conditions
            4 : 'warning',        # warning conditions
            5 : 'notice',         # normal but significant condition
            6 : 'informational',  # informational messages
            7 : 'debug',          # debug-level messages
        }

        return log_levels[level]
