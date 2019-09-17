#!/usr/bin/env python3

import os, sys
import time
import json
import asyncio
import shutil

from collections import deque

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_db_connector import DBConnector
from dnx_configure.dnx_system_info import System as Sys


class LogService:
    def __init__(self):
        self.System = Sys()

    def Start(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(self.Main())

    async def Main(self):
        await asyncio.gather(self.Settings, self.Organize(), self.CleanDBTables())

    # Recurring logic to gather all log files and add the mto a signle file (combined logs) every 5 minutes
    async def Organize(self):
        log_entries = []
        date = self.System.Date()
        log_modules = ['dhcp_server', 'dns_proxy', 'ip_proxy', 'ips', 'syslog', 'system', 'update']
        while True:
            for module in log_modules:
                module_entries = await self.CombineLogs(module, date)
                if (module_entries):
                    log_entries.extend(module_entries)

            sorted_log_entries = sorted(log_entries)
            if (sorted_log_entries):
                await self.WriteCombinedLogs(sorted_log_entries, date)

            await asyncio.sleep(SETTINGS_TIMER)

    # grabbing the log from the sent in module, splitting the lines, and returning a list
    async def CombineLogs(self, module, date):
        try:
            with open(f'{HOME_DIR}/dnx_system/log/{module}/{date[0]}{date[1]}{date[2]}-{module}.log', 'r') as log_file:
                log_entries = log_file.read().strip().split('\n')

            return log_entries
        except FileNotFoundError:
            pass

    # writing the log entries to the combined log
    async def WriteCombinedLogs(self, sorted_log_entries, date):
        with open(f'{HOME_DIR}/dnx_system/log/combined_log/{date[0]}{date[1]}{date[2]}-combined.log', 'w+') as system_log:
            for log in sorted_log_entries:
                system_log.write(f'{log}\n')

    async def CleanDBTables(self):
        while True:
            for table in {'dnsproxy', 'ipproxy' , 'ips', 'infectedclients'}:
                Database = DBConnector(table)
                Database.Connect()
                Database.Cleaner(self.log_length)
                Database.Disconnect()

            #running on system startup and every 24 hours thereafter
            await asyncio.sleep(EXTRA_LONG_TIMER)

    async def Settings(self):
        while True:
            with open(f'{HOME_DIR}/data/config.json', 'r') as logging:
                log = json.load(logging)

            self.log_length = log['settings']['logging']['length']

            await asyncio.sleep(SETTINGS_TIMER)


class LogHandler:
    def __init__(self, process, module=None):
        self.process = process
        self.System = Sys()

        self.log_queue = deque()

        if (module):
            self.module = module

    async def Settings(self, module):
        print('[+] Starting: Log Settings Update Thread.')
        self.module = module
        while True:
            with open(f'{HOME_DIR}/data/config.json', 'r') as settings:
                setting = json.load(settings)

            self.process.logging_level = setting['settings']['logging']['level']

            await asyncio.sleep(SETTINGS_TIMER)

    ## this is the message input for threadsafe/sequential modules
    def Message(self, message):
        timestamp = time.time()
        timestamp = self.System.FormatTime(timestamp)
        d = self.System.Date()
        with open(f'{HOME_DIR}/dnx_system/log/{self.module}/{d[0]}{d[1]}{d[2]}-{self.module}.log', 'a+') as Log:
            Log.write(f'{timestamp}: {message}\n')

        ## make sure this works. should be fine, but front end might do something weird to chmod???
        user_id = os.geteuid()
        if (user_id == 0):
            file_path = f'{HOME_DIR}/dnx_system/log/{self.module}/{d[0]}{d[1]}{d[2]}-{self.module}.log'
            shutil.chown(file_path, user=USER, group=GROUP)
            os.chmod(file_path, 0o660)

            ## REPLACED THESE WITH CODE ABOVE. REMOVE AFTER TESTING AND VALIDATING CHANGES WORK
#            run(f'chown dnx:dnx {file_path}', shell=True)
#            run(f'chmod 660 {file_path}', shell=True)

    def AddtoQueue(self, message, log_queue_lock):
        timestamp = time.time()
        with log_queue_lock:
            self.log_queue.append((timestamp, message))

    ## This is the message handler for ensure thread safety in multi threaded or asynchronous tasks
    async def QueueHandler(self, log_queue_lock):
        while True:
            d = self.System.Date()
            if (not self.log_queue):
                # waiting 1 second before checking queue again for idle perf
                await asyncio.sleep(SHORT_POLL)
                continue

            with open(f'{HOME_DIR}/dnx_system/log/{self.module}/{d[0]}{d[1]}{d[2]}-{self.module}.log', 'a+') as Log:
                with log_queue_lock:
                    while self.log_queue:
                        full_message = self.log_queue.popleft()
                        timestamp = full_message[0]
                        message = full_message[1]

                        Log.write(f'{timestamp}: {message}\n')

            user_id = os.geteuid()
            if (user_id == 0):
                file_path = f'{HOME_DIR}/dnx_system/log/{self.module}/{d[0]}{d[1]}{d[2]}-{self.module}.log'
                shutil.chown(file_path, user=USER, group=GROUP)
                os.chmod(file_path, 0o660)

            ## REPLACED THESE WITH CODE ABOVE. REMOVE AFTER TESTING AND VALIDATING CHANGES WORK
#            run(f'chown dnx:dnx {file_path}', shell=True)
#            run(f'chmod 660 {file_path}', shell=True)
