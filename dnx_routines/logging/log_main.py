#!/usr/bin/env python3

if (__name__ == '__main__'):
    import __init__

import os
import threading

from socket import socket, AF_UNIX, SOCK_DGRAM, SOL_SOCKET, SCM_CREDENTIALS  #, SO_PASSCREDS
from json import dumps

from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import looper, classproperty, dnx_queue, Initialize
from dnx_gentools.file_operations import load_configuration, cfg_read_poller, change_file_owner
from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.configure.system_info import System

LOG_NAME = 'system'

EXCLUDED_MODULES = ['combined', 'syslog']

_system_date = System.date
_format_time = System.format_time


class LogService:
    _log_modules = [
            x for x in os.listdir(f'{HOME_DIR}/dnx_system/log') if x not in EXCLUDED_MODULES
        ]

    __slots__ = (
        'log_length', 'log_level', '_initialize'
    )

    @classmethod
    def run(cls):
        self = cls()

        self.organize()

    def __init__(self):
        self._initialize = Initialize(Log, 'LogService')

        threading.Thread(target=self.get_settings).start()

        self._initialize.wait_for_threads(count=1)

        threading.Thread(target=self.clean_db_tables).start()
        threading.Thread(target=self.clean_blocked_table).start()

    @looper(THREE_MIN)
    def organize(self):
        log_entries = []

        date = str_join(_system_date())
        for module in self._log_modules:

            log_entries.extend(self._pull_recent_logs(module, date))

        if (not log_entries): return

        with open(f'{HOME_DIR}/dnx_system/log/combined/{date}-combined.log', 'w+') as system_log:
            system_log.write('\n'.join(sorted(log_entries)))

        del log_entries # to reclaim system memory

    @staticmethod
    def _pull_recent_logs(module, date):
        log_path = f'{HOME_DIR}/dnx_system/log/{module}/{date}-{module}.log'

        if not os.path.isfile(log_path):
            return []

        with open(log_path, 'r') as log_file:
            return [x.strip() for x in log_file.readlines(2048)[:20]]

    @looper(ONE_DAY)
    def clean_db_tables(self):
        with DBConnector(Log) as FirewallDB:
            for table in ['dnsproxy', 'ipproxy', 'ips', 'infectedclients']:
                FirewallDB.table_cleaner(self.log_length, table=table)

        # NOTE: consider moving this into the DBConnector so it can report if no exc are raised.
        Log.notice('completed daily database cleaning')

    @looper(THREE_MIN)
    def clean_blocked_table(self):
        with DBConnector(Log) as FirewallDB:
            FirewallDB.blocked_cleaner(table='blocked')

        # NOTE: consider moving this into the DBConnector so it can report if no exc are raised.
        Log.debug('completed blocked database cleaning')

    @cfg_read_poller('logging_client')
    def get_settings(self, cfg_file):
        log_settings = load_configuration(cfg_file)

        self.log_length = log_settings['logging']['length']
        self.log_level = log_settings['logging']['level']

        self._initialize.done()

# =============================================
# GENERIC LIGHTWEIGHT FUNCTIONS
# =============================================

def direct_log(m_name, level_name, message, int=int):
    '''alternate system log method. this can be used to override global module log name if needed and does not
    require LogHandler initialization.'''

    path = f'{HOME_DIR}/dnx_system/log/{m_name}/{_system_date(string=True)}-{m_name}.log'
    with open(path, 'a+') as log:
        log.write(f'{int(fast_time())}|{m_name}|{level_name}|{message}\n')

    if (ROOT):
        change_file_owner(path)

# system time/UTC will be used.
def message(mod_name, mtype, level, log_msg):
    date = _system_date(string=True)
    timestamp = _format_time(fast_time())
    level = convert_level(level)

    system_ip = None

    # using system/UTC time
    # 20140624|19:08:15|EVENT|DNSProxy:Informational|192.168.83.1|*MESSAGE*
    return f'{date}|{timestamp}|{mtype.name}|{mod_name}:{level}|{system_ip}|{log_msg}'.encode('utf-8')

def db_message(timestamp, log_msg, method):
    log_data = {
        'method': method,
        'timestamp': timestamp,
        'log': log_msg
    }

    return dumps(log_data).encode('utf-8')

def convert_level(level=None):
    '''converts log level as integer to string. valid input: 0-7. if level is None the entire
    dict will be returned.'''

    levels = {
        0: ['emergency', 'system is unusable'],
        1: ['alert', 'action must be taken immediately'],
        2: ['critical', 'critical conditions'],
        3: ['error', 'error conditions'],
        4: ['warning', 'warning conditions'],
        5: ['notice', 'normal but significant condition'],
        6: ['informational', 'informational messages'],
        7: ['debug', 'debug-level messages']
    }

    return levels if level is None else levels[level][0]

# =================================
# LOG HANDLING CLASS FACTORY
# =================================
# process wide "instance" of LogHandler class, which can be used directly or subclassed.

def _log_handler():

    _LEVEL = 0
    _name = None
    _console = False

    _path = f'{HOME_DIR}/dnx_system/log/'

    _initialized = False
    _syslog = False

    # _syslog_sock = socket()

    # ==============================
    # DB SERVICE SOCKET CONNECT
    # ==============================
    _db_client = socket(AF_UNIX, SOCK_DGRAM)
    try:
        _db_client.connect(DATABASE_SOCKET)
    except FileNotFoundError:
        print('db socket conn failed.')

    _db_sendmsg = _db_client.sendmsg

    # ==============================
    # STANDARD FUNCTIONS
    # ==============================
    # TODO: consider having this offloaded so the security modules don't have to waste cycles on writing to disk.
    #  also, check to see how often they even log, it might not be often after first startup.
    @dnx_queue(None, name='LogHandler')
    def _write_to_disk(job):

        path = f'{_path}/{_system_date(string=True)}-{_name}.log'

        with open(_path, 'a+') as log:
            log.write(job)

        if (ROOT):
            change_file_owner(path)

    def _add_logging_methods(cls):
        '''dynamically overrides default log level methods depending on current log settings.'''

        _round = round
        _queue_write = _write_to_disk.add

        for level_number, level_info in convert_level().items():

            level_name, _ = level_info

            # all entries will be logged and printed to terminal
            if (_LEVEL is LOG.DEBUG):

                @staticmethod
                def log_method(log_msg):
                    log_msg = f'{_round(fast_time())}|{_name}|{level_name}|{log_msg}\n'

                    console_log(log_msg)

                    _queue_write(log_msg)

            # entry will be logged to file
            elif (level_number <= _LEVEL):

                @staticmethod
                def log_method(log_msg):

                    _queue_write(f'{_round(fast_time())}|{_name}|{level_name}|{log_msg}\n')

            # log level is disabled
            else:
                @staticmethod
                def log_method(*_):
                    pass

            setattr(cls, level_name, log_method)

    @cfg_read_poller('logging_client')
    def _log_settings(cfg_file):
        nonlocal _LEVEL, _initialized

        logging = load_configuration(cfg_file)

        _LEVEL = logging['logging']['level']

        _add_logging_methods(Handler)

        # after initial load, this dones nothing
        _initialized = True

    @cfg_read_poller('syslog_client', class_method=True)
    def _slog_settings(cfg_file):
        nonlocal _syslog

        syslog = load_configuration(cfg_file)

        _syslog = syslog['enabled']

    # TODO: create function to write logs for system errors that happen prior to log handler being initialized.
    class Handler:

        @classmethod
        def run(cls, *, name, console=False):
            '''
            initializes log handler settings and monitors system configs for changes
            with log/syslog settings.

            set console=True to enable Log.console outputs in terminal.
            '''

            nonlocal _name, _console, _path

            if (_initialized):
                raise RuntimeError('the log handler has already been started.')

            _name = name
            _console = console
            _path += name

            threading.Thread(target=_log_settings).start()
            threading.Thread(target=_slog_settings).start()

            threading.Thread(target=_write_to_disk).start()

            # waiting for log settings and methods to initialize before returning to caller
            while not _initialized:
                fast_sleep(ONE_SEC)

        @staticmethod
        def current_lvl():
            '''returns current system log settings level.'''
            return _LEVEL

        @staticmethod
        def syslog_enabled():
            '''returns True if syslog is configured in the system else False.'''
            return _syslog

        @staticmethod
        def emergency(log_msg):
            '''system is unusable.'''
            return

        @staticmethod
        def alert(log_msg):
            '''action must be taken immediately.'''
            return

        @staticmethod
        def critical(log_msg):
            '''critical conditions.'''
            return

        @staticmethod
        def error(log_msg):
            '''error conditions.'''
            return

        @staticmethod
        def warning(log_msg):
            '''warning conditions.'''
            return

        @staticmethod
        def notice(log_msg):
            '''normal but significant condition.'''
            return

        @staticmethod
        def informational(log_msg):
            '''informational messages.'''
            return

        @staticmethod
        def debug(log_msg):
            '''debug-level messages.'''
            return

        @staticmethod
        def console(log_msg):
            '''print message to console. this is for all important console only events.'''
            if (_console):
                console_log(f'{log_msg}\n')

        @staticmethod
        def event_log(timestamp, log, method):
            '''log security events to database. uses local socket controlled by log service
            to aggregate messages across all modules.

            Do not override.

            '''

            log_data = [db_message(timestamp, log, method)]

            _db_sendmsg(log_data, [(SOL_SOCKET, SCM_CREDENTIALS, DNX_AUTHENTICATION)])

        @staticmethod
        def slog_log(mtype, level, log_msg):
            return  # NOTE: to not mess up decorator

            # message = Format.message(cls_name, mtype, level, message)
            # for attempt in range(2):
            #     try:
            #         cls._syslog_sock.send(message)
            #     except OSError:
            #         cls._create_syslog_sock()
            #     else:
            #         # NOTE: should log to front end
            #         break

        # @classmethod
        # def _create_syslog_sock(cls):
        #     cls._syslog_sock = socket(AF_INET, SOCK_DGRAM)
        #     cls._syslog_sock.connect((f'{LOCALHOST}', SYSLOG_SOCKET))

    return Handler

LogHandler = _log_handler()

if (__name__ == '__main__'):
    # aliasing to keep log service conventions the same as other modules
    Log = LogHandler()
    Log.run(name=LOG_NAME)

    LogService.run()
