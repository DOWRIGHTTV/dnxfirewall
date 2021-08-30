#!/usr/bin/env python3

import os, sys
import time
import threading
import shutil
import json


from functools import wraps
from collections import deque
from socket import socket, AF_INET, SOCK_DGRAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_standard_tools import looper, classproperty, dnx_queue, Initialize
from dnx_configure.dnx_file_operations import load_configuration, cfg_read_poller, change_file_owner
from dnx_database.ddb_connector_sqlite import DBConnector
from dnx_configure.dnx_system_info import System

LOG_NAME = 'system'

EXCLUDED_MODULES = ['combined', 'syslog']


class LogService:
    _log_modules = [
            x for x in os.listdir(f'{HOME_DIR}/dnx_system/log') if x not in EXCLUDED_MODULES
        ]

    __slots__ = (
        'log_length', 'log_level', '_initialize'
    )

    def __init__(self):
        self._initialize = Initialize(Log, 'LogService')

    @classmethod
    def run(cls):
        self = cls()

        threading.Thread(target=self.get_settings).start()

        self._initialize.wait_for_threads(count=1)

        threading.Thread(target=self.organize).start()
        threading.Thread(target=self.clean_db_tables).start()
        threading.Thread(target=self.clean_blocked_table).start()

    # Recurring logic to gather all log files and add the mto a signle file (combined logs) every 5 minutes
    @looper(THREE_MIN)
    def organize(self):
        # print('[+] Starting organize operation.')
        log_entries = []

        date = str_join(System.date())
        for module in self._log_modules:
            module_entries = self.combine_logs(module, date)
            if (module_entries):
                log_entries.extend(module_entries)

        sorted_log_entries = sorted(log_entries)
        if (sorted_log_entries):
            self.write_combined_logs(sorted_log_entries, date)

        log_entries = None # overwriting var to regain system memory

    # grabbing the log from the sent in module, splitting the lines, and returning a list
    # TODO: see if we can load file as generator
    def combine_logs(self, module, date):
        file_entries = []

        if not os.path.isfile(f'{HOME_DIR}/dnx_system/log/{module}/{date}-{module}.log'):
            return None

        with open(f'{HOME_DIR}/dnx_system/log/{module}/{date}-{module}.log', 'r') as log_file:
            for _ in range(20):
                line = log_file.readline().strip()
                if not line: break

                file_entries.append(line)

        return file_entries

    # writing the log entries to the combined log
    def write_combined_logs(self, sorted_log_entries, date):
        with open(f'{HOME_DIR}/dnx_system/log/combined/{date}-combined.log', 'w+') as system_log:
#            print(f'writing {HOME_DIR}/dnx_system/log/combined/{date[0]}{date[1]}{date[2]}-combined.log')
            for log in sorted_log_entries:
                system_log.write(f'{log}\n')

    @looper(ONE_DAY)
    def clean_db_tables(self):
        # print('[+] Starting general DB table cleaner.')
        with DBConnector(Log) as FirewallDB:
            for table in ['dnsproxy', 'ipproxy' , 'ips', 'infectedclients']:
                FirewallDB.table_cleaner(self.log_length, table=table)

        # NOTE: consider moving this into the DBConnector so it can report if no exc are raised.
        Log.notice('completed daily database cleaning')

    @looper(THREE_MIN)
    def clean_blocked_table(self):
        # print('[+] Starting DB blocked table cleaner.')
        with DBConnector(Log) as FirewallDB:
            FirewallDB.blocked_cleaner(table='blocked')

        # NOTE: consider moving this into the DBConnector so it can report if no exc are raised.
        Log.debug('completed blocked database cleaning')

    @cfg_read_poller('logging_client')
    def get_settings(self, cfg_file):
#        print('[+] Starting settings update poller.')
        log_settings = load_configuration(cfg_file)

        self.log_length = log_settings['logging']['length']
        self.log_level = log_settings['logging']['level']

        self._initialize.done()

# LOG HANDLING PARENT CLASS

# TODO: create a function that can be used to write logs for system errors that happen prior to log
# handler being intitialized.
class LogHandler:
    _LEVEL   = 0
    _initialized = False
    _syslog  = False
    _running = False

    _path    = f'{HOME_DIR}/dnx_system/log/'
    _db_sock = socket()
    _syslog_sock = socket()

    @classmethod
    def run(cls, *, name, console=True):
        '''
        initializes log handler settings and monitors system configs for changes
        with log/syslog settings.

        set console=True to enable Log.console outputs in terminal.
        '''
        if (cls.is_running):
            raise RuntimeWarning('the log handler has already been started.')

        cls.name     = name
        cls._console = console # NOTE: _ is a must. without it, it overlaps with method of same name
        cls._running = True

        cls._path += f'{name}'

        threading.Thread(target=cls._log_settings).start()
        threading.Thread(target=cls._slog_settings).start()

        # passing cls as arg because this is going through a generic decorator that strips the cls reference
        threading.Thread(target=cls._write_to_disk, args=(cls,)).start()

        # waiting for log settings and methods to initialize before returning to caller
        while not cls._initialized:
            fast_sleep(ONE_SEC)

    @classproperty
    def is_root(cls): # pylint: disable=no-self-argument
        '''return True is process is running as root/ userid=0.'''
        return True if not os.geteuid() else False

    @classproperty
    def is_running(cls): # pylint: disable=no-self-argument
        '''return True if run method has been called.'''
        return cls._running

    @classproperty
    def current_lvl(cls): # pylint: disable=no-self-argument
        '''returns current system log settings level.'''
        return cls._LEVEL

    @classproperty
    def syslog_enabled(cls): # pylint: disable=no-self-argument
        '''returns True if syslog is configured in the system else False.'''
        return cls._syslog

    def emergency(self):
        '''system is unusable.'''
        pass

    def alert(self):
        '''action must be taken immediately.'''
        pass

    def critical(self):
        '''critical conditions.'''
        pass

    def error(self):
        '''error conditions.'''
        pass

    def warning(self):
        '''warning conditions.'''
        pass

    def notice(self):
        '''normal but significant condition.'''
        pass

    def informational(self):
        '''informational messages.'''
        pass

    def debug(self):
        '''debug-level messages.'''
        pass

    @classmethod
    def console(cls, message):
        '''print message to console. this is for all important console only events. use dprint for
        non essential console output set by DEBUG log level.'''
        if (cls._console):
            write_log(f'{message}\n')

    @classmethod
    def dprint(cls, message):
        '''print function alternative to supress/show terminal output.'''
        if (LOG.DEBUG):
            write_log(f'{message}\n')

    @staticmethod
    def simple_write(m_name, level_name, message):
        '''alternate system log method. this can be used to override global module log name if needed.'''

        path = f'{HOME_DIR}/dnx_system/log/{m_name}/{System.date(string=True)}-{m_name}.log'
        with open(path, 'a+') as log:
            log.write(f'{int(fast_time())}|{m_name}|{level_name}|{message}\n')

        if (ROOT):
            change_file_owner(path)

    @dnx_queue(None, name='LogHandler')
    def _write_to_disk(cls, job): # pylint: disable=no-self-argument
        path = f'{cls._path}/{System.date(string=True)}-{cls.name}.log'

        with open(path, 'a+') as log:
            log.write(job)

        if (ROOT):
            change_file_owner(path)

    @classmethod
    def event_log(cls, timestamp, log, method):
        '''log security events to database. uses local socket controlled by log service
        to aggregate messages across all modules.

        Do not override.

        '''

        log_data = Format.db_message(timestamp, log, method)
        for _ in range(2):
            try:
                cls._db_sock.send(log_data)
            except OSError:
                cls._create_db_sock()
            else:
                break

    @classmethod
    def slog_log(cls, mtype, level, message):
        return # NOTE: to not mess up decorator

        # message = Format.message(cls_name, mtype, level, message)
        # for attempt in range(2):
        #     try:
        #         cls._syslog_sock.send(message)
        #     except OSError:
        #         cls._create_syslog_sock()
        #     else:
        #         # NOTE: should log to front end
        #         break

    @classmethod
    def _add_logging_methods(cls):
        '''dynamicly overrides default log level methods depending on current log settings.'''

        mapping = Format.convert_level()

        for level_number, level_name in mapping.items():
            cls._update_log_method(level_number, level_name)

    @classmethod
    def _update_log_method(cls, level_num, level_info):
        level_name, desc = level_info # pylint disable=unused-variable # NOTE: for future use
        # if debug/verbose is enabled all entries will be logged and printed to terminal
        if (cls._LEVEL == LOG.DEBUG):
            @classmethod
            def log_method(cls, message):
                message = f'{round(fast_time())}|{cls.name}|{level_name}|{message}\n'

                write_log(message)

                cls._write_to_disk.add(message)

        # entry will be logged to file
        elif (level_num <= cls._LEVEL):
            @classmethod
            def log_method(cls, message):
                cls._write_to_disk.add(f'{round(fast_time())}|{cls.name}|{level_name}|{message}\n')

        # log level is disabled
        else:
            @classmethod
            def log_method(*args):
                pass

        setattr(cls, level_name, log_method)

    @cfg_read_poller('logging_client', class_method=True)
    def _log_settings(cls, cfg_file):  # pylint: disable=no-self-argument
        logging = load_configuration(cfg_file)

        cls._LEVEL = logging['logging']['level']

        cls._add_logging_methods()

        # used to inform run method that it can return to caller. This is is only relevant on initial start.
        cls._initialized = True

    @cfg_read_poller('syslog_client', class_method=True)
    def _slog_settings(cls, cfg_file):  # pylint: disable=no-self-argument
        syslog = load_configuration(cfg_file)

        cls._syslog = syslog['enabled']

    @classmethod
    def _create_syslog_sock(cls):
        cls._syslog_sock = socket(AF_INET, SOCK_DGRAM)
        cls._syslog_sock.connect((f'{LOCALHOST}', SYSLOG_SOCKET))

    @classmethod
    def _create_db_sock(cls):
        cls._db_sock = socket(AF_INET, SOCK_DGRAM)
        cls._db_sock.connect((f'{LOCALHOST}', DATABASE_SOCKET))


class Format:
    '''log formatting class used by log handler. system time/UTC will be used.'''

    @classmethod
    def message(cls, mod_name, mtype, level, message):
        date = System.date(string=True)
        timestamp = System.format_time(fast_time())
        level = cls.convert_level(level)

        system_ip = None

        # using system/UTC time
        # 20140624|19:08:15|EVENT|DNSProxy:Informational|192.168.83.1|*MESSAGE*
        message = f'{date}|{timestamp}|{mtype.name}|{mod_name}:{level}|{system_ip}|{message}'

        return message.encode('utf-8')

    @staticmethod
    def db_message(timestamp, log, method):
        log_data = {
            'method': method,
            'timestamp': timestamp,
            'log': log
        }

        return json.dumps(log_data).encode('utf-8')

    @staticmethod
    def convert_level(level=None):
        '''converts log level as integer to string. valid input: 0-7. if level is None the entire
        dict will be returned.'''

        levels = {
            0 : ['emergency', 'system is unusable'],
            1 : ['alert', 'action must be taken immediately'],
            2 : ['critical', 'critical conditions'],
            3 : ['error', 'error conditions'],
            4 : ['warning', 'warning conditions'],
            5 : ['notice', 'normal but significant condition'],
            6 : ['informational', 'informational messages'],
            7 : ['debug', 'debug-level messages']
        }

        if (level is None):
            return levels

        return levels[level][0]

if __name__ == '__main__':
    # aliasing to keep log service conventions the same as other modules
    Log = LogHandler
    Log.run(
        name=LOG_NAME
    )

    LogService.run()
