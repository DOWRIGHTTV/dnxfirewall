#!/usr/bin/env python3

from __future__ import annotations

import threading

from json import dumps
from socket import socket, AF_UNIX, SOCK_DGRAM, SOL_SOCKET, SCM_CREDENTIALS

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import LOG
from dnx_gentools.standard_tools import classproperty, dnx_queue, Initialize
from dnx_gentools.file_operations import change_file_owner, cfg_read_poller

from dnx_gentools.system_info import System

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


__all__ = (
    'LogHandler', 'Log',

    'direct_log', 'message', 'db_message', 'convert_level',

    'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug', 'cli',
)

_system_date = System.date
_format_time = System.format_time


# ==============================
# GENERIC LIGHTWEIGHT FUNCTIONS
# ==============================
def direct_log(m_name: str, message_level: LOG, msg: str, *, cli: bool = False) -> None:
    '''alternate system log method.

    used to override global module log name if needed.
    does not require LogHandler initialization.
    '''
    if (message_level > Log.current_lvl):
        return

    log_path = f'{HOME_DIR}/dnx_profile/log/{m_name}/{_system_date(string=True)}-{m_name}.log'
    with open(log_path, 'a+') as log_file:
        log_file.write(f'{fast_time()}|{m_name}|{message_level.name.lower()}|{msg}\n')

    if (cli and not Log.suppress_output):
        console_log(msg)

    if (ROOT):
        change_file_owner(log_path)

# system time/UTC will be used.
def message(mod_name: str, mtype: LOG, level: LOG, log_msg: str) -> bytes:
    date = _system_date(string=True)
    timestamp = _format_time(fast_time())
    level = convert_level(level)

    system_ip = None

    # using system/UTC time
    # 20140624|19:08:15|EVENT|DNSProxy:Informational|192.168.83.1|*MESSAGE*
    return f'{date}|{timestamp}|{mtype.name}|{mod_name}:{level}|{system_ip}|{log_msg}'.encode('utf-8')

def db_message(timestamp: int, log_msg: tuple, method: str) -> bytes:
    log_data = {
        'method': method,
        'timestamp': timestamp,
        'log': log_msg
    }

    return dumps(log_data).encode('utf-8')

def convert_level(level: Optional[LOG] = None) -> Union[dict[int, list[str, str]], str]:
    '''converts log level as integer to string.

    valid input: 0-7.

    if level is None the entire dict will be returned.
    '''
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

# ===========================
# LOG HANDLING CLASS FACTORY
# ===========================
# process wide "instance" of LogHandler class, which can be used directly or subclassed.
def _log_handler() -> LogHandler:

    logging_level: int = 0
    handler_name: str = ''
    cli_output: bool = False
    system_action_audit: bool = False

    log_path: str = f'{HOME_DIR}/dnx_profile/log/'

    initializer: list[int] = []
    syslog: bool = False

    # keeping file open for performance.
    # using explicit buffer flush logic to provide more consistent writes to disk
    _log_buf: TextIO = open('/dev/null')
    _log_buf_date: str = ''
    _log_write_ct: int = 0

    # this will get immediately overloaded by user setting
    # this limit signifies the interval for flushing file buffer
    line_buf_limit = 5

    # _syslog_sock = socket()

    # ------------------
    # DB SERVICE SOCKET
    # ------------------
    db_client: Socket = socket(AF_UNIX, SOCK_DGRAM)

    db_sendmsg = db_client.sendmsg

    # TODO: create function to write log for system errors that happen prior to log handler being initialized.
    class _LogHandler:

        _init_one: ClassVar[Initialize] = Initialize()
        suppress_output: ClassVar[bool] = False

        @classmethod
        def run(cls, *, name: str, console_output: bool = False, suppress_output: bool = False):
            '''
            initialize log handler settings and monitor system configs for changes with log/syslog settings.

            set console_output=True to enable "Log.cli" outputs in terminal.
            '''
            nonlocal handler_name, cli_output, log_path, db_client

            if (initializer is None):
                raise RuntimeError('the log handler has already been started.')

            handler_name = name
            cli_output = console_output
            log_path += name

            cls.suppress_output = suppress_output

            # need to get log level before initialization direct log or else it will be set to 0
            threading.Thread(target=log_settings).start()
            threading.Thread(target=slog_settings).start()

            cls._init_one.wait_for_threads(count=2)

            direct_log(handler_name, LOG.INFO, 'LogHandler initialization started.', cli=True)
            threading.Thread(target=write_to_disk).start()
            direct_log(handler_name, LOG.NOTICE, 'LogHandler initialization complete.', cli=True)

        @classproperty
        def current_lvl(_) -> int:
            '''returns current system log settings level.
            '''
            return logging_level

        @classproperty
        def control_audit(_) -> int:
            '''returns current state of system action (control) auditing setting.
            '''
            return system_action_audit

        @classproperty
        def syslog_enabled(_) -> bool:
            '''returns True if syslog is configured in the system else False.
            '''
            return syslog

        @staticmethod
        def emergency(log_msg: str):
            '''L0. system is unusable.
            '''
            return

        @staticmethod
        def alert(log_msg: str):
            '''L1. action must be taken immediately.
            '''
            return

        @staticmethod
        def critical(log_msg: str):
            '''L2. critical conditions.
            '''
            return

        @staticmethod
        def error(log_msg: str):
            '''L3. error conditions.
            '''
            return

        @staticmethod
        def warning(log_msg: str):
            '''L4. warning conditions.
            '''
            return

        @staticmethod
        def notice(log_msg: str):
            '''L5. normal but significant condition.
            '''
            return

        @staticmethod
        def informational(log_msg: str):
            '''L6. informational messages.
            '''
            return

        @staticmethod
        def debug(log_msg: str):
            '''L7. debug-level messages.
            '''
            return

        @staticmethod
        def cli(log_msg: str):
            '''print a message to console. this is for all important console only events.
            '''
            if (cli_output):
                console_log(log_msg)

        @staticmethod
        # TODO: figure out a nice way to alert on excessive amounts of dropped events. maybe store dropped events
        #  to a backlog file that can be loaded into db when available.
        def event_log(timestamp: int, log: tuple, method: str):
            '''log security events to database.

            sends over local socket controlled by database service to aggregate events from all modules.
            if the database socket is not available, the log message will be silently dropped.
            '''
            try:
                db_sendmsg(
                    [db_message(timestamp, log, method)],
                    [(SOL_SOCKET, SCM_CREDENTIALS, DNX_AUTHENTICATION)],
                    0, DATABASE_SOCKET
                )
            except (PermissionError, FileNotFoundError):
                pass

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

        @classmethod
        def _create_syslog_sock(cls):
            return

            # cls._syslog_sock = socket(AF_INET, SOCK_DGRAM)
            # cls._syslog_sock.connect((f'{LOCALHOST}', SYSLOG_SOCKET))

    # ==============================
    # STANDARD FUNCTIONS
    # ==============================
    # TODO: consider having this offloaded so the security modules don't have to waste cycles on writing to disk.
    #  also, check to see how often they even log, it might not be often after first startup.
    @dnx_queue(_LogHandler, name='LogHandler')
    def write_to_disk(job):

        nonlocal _log_buf, _log_buf_date, _log_write_ct

        current_date = _system_date(string=True)
        # if the dates are different, then the day has changed.
        # we close the previous days log file, then open a new file with current date.
        # for processes running as root, we will modify the file's owner to dnx so webui can read them.
        if (current_date != _log_buf_date):
            _log_buf.close()

            file_path = f'{log_path}/{current_date}-{handler_name}.log'

            _log_buf = open(file_path, 'a')
            _log_buf_date = current_date

            if (ROOT):
                change_file_owner(file_path)

        # WRITING LOG ENTRY TO FILE BUFFER
        _log_buf.write(job)

        # increments counter then checks currently configured limit. resets counter if limit reached.
        _log_write_ct += 1
        if (_log_write_ct == line_buf_limit):
            _log_buf.flush()
            _log_write_ct = 0

    def add_logging_methods(cls) -> None:
        '''dynamically overrides default log level methods depending on current log settings.
        '''
        queue_write = write_to_disk.add

        direct_log(handler_name, LOG.DEBUG, f'configuring logger => {logging_level}')

        for level_number, level_info in convert_level().items():

            level_name, _ = level_info

            # all entries will be logged and printed to the terminal
            if (logging_level is LOG.DEBUG):

                def log_method(log_msg, info=f'{handler_name}|{level_name}'):
                    log_msg = f'{fast_time()}|{info}|{log_msg}'

                    console_log(log_msg)

                    queue_write(f'{log_msg}\n')

            # entry will be logged to file
            elif (level_number <= logging_level):

                def log_method(log_msg, info=f'{handler_name}|{level_name}'):

                    queue_write(f'{fast_time()}|{info}|{log_msg}\n')

            # log level is disabled
            else:

                def log_method(*_):
                    pass

            log_method = staticmethod(log_method)

            setattr(cls, level_name, log_method)

        direct_log(handler_name, LOG.NOTICE, f'logger successfully configured => {logging_level}', cli=True)

    @cfg_read_poller('logging_client', cfg_type='global')
    def log_settings(logger_settings: ConfigChain) -> None:
        nonlocal logging_level, line_buf_limit

        logging_level  = LOG(logger_settings['logging->level'])
        line_buf_limit = logger_settings['logging->line_buffer']

        add_logging_methods(_LogHandler)

        # abusing property to overload reference after the initial load.
        _LogHandler._init_one.done2

    @cfg_read_poller('syslog_client', cfg_type='global')
    def slog_settings(syslog_settings: ConfigChain) -> None:
        nonlocal syslog

        syslog = syslog_settings['enabled']

        _LogHandler._init_one.done2

    return _LogHandler


LogHandler = _log_handler()
Log: LogHandler_T = LogHandler  # alias

# ========================
# DIRECT ACCESS FUNCTIONS
# ========================
# TODO: test direct access functions after a log level is changed and methods are reset.
#  - im pretty sure this reference will change so it will not work unless we setattr on the globals
LogLevel = Callable[[str], None]

emergency: LogLevel = LogHandler.emergency
alert: LogLevel = LogHandler.alert
critical: LogLevel = LogHandler.critical
error: LogLevel = LogHandler.error
warning: LogLevel = LogHandler.warning
notice: LogLevel = LogHandler.notice
informational: LogLevel = LogHandler.informational
debug: LogLevel = LogHandler.debug
cli: LogLevel = LogHandler.cli
