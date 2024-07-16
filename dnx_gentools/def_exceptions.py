#!/usr/bin/env python3

from __future__ import annotations

import os as _os
from functools import wraps, partial

from dnx_gentools.def_constants import module_import_callout

module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, console_log, fast_time
from dnx_gentools.def_enums import LOG as _LOG
from dnx_gentools.system_info import System as _System
from dnx_gentools.file_operations import acquire_lock as _acquire_lock, release_lock as _release_lock

from dnx_routines.logging.log_client import Log

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional
    from dnx_gentools.def_typing import ErrorReportsLock

    from dnx_routines.logging import LogHandler_T

# =====================
# PROCESS EXIT + CODES
# =====================
SUCCESS = 0
IMPORT_FAILURE = 1
UNHANDLED_EXCEPTION = 69

def hardout(msg: Optional[str] = None) -> None:
    '''exit the application with SUCCESS (0) exit code.

    guarantees all threads and processes are not left dangling, but skips "finally" blocks.
    '''
    if (msg):
        console_log(msg)

    _os._exit(SUCCESS)

def hardout_errno(errno: int, msg: Optional[str] = None) -> None:
    '''exit the application with a specified exit code.

    guarantees all threads and processes are not left dangling, but skips "finally" blocks.
    '''
    if (msg):
        console_log(msg)

    _os._exit(errno)

class DNXSignal(Exception):
    '''Base exception for all other DNXFIREWALL signals.'''

class ModuleReload(DNXSignal):
    '''Signal to reload the module and rerun.'''

class TerminateSignal(DNXSignal):
    '''SigTerm will be sent by and received from systemd

    alternative to KeyboardInterrupt for when running as a service
    '''

class DNXError(Exception):
    '''Base exception for all other DNXFIREWALL errors.'''

    @property
    def message(self) -> Optional[str]:
        return self.args[0]

class ControlError(DNXError):
    '''System Action (control) failure. This is reraised and a functional alias to other Exceptions.'''

class ProtocolError(DNXError):
    '''Malformed network protocol.'''

class ParseError(DNXError):
    '''Failure to convert string to python object.'''

# FILE OPERATIONS
class ConfigurationError(DNXError):
    '''System configuration context manager processing failure while in context.'''

# WEBUI VALIDATION
class ValidationError(DNXError):
    '''Webui processing failure or invalid user input.'''

def err_as_value(exc_type):
    '''converts try/catch semantic of the specified exception class to a return error by value.

    func(*args, **kwargs) -> Optional[ExceptionClass]

    manually returning exceptions as values is also supported.
    '''
    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exc_type as exc:
                return exc

        return wrapper

    return decorator


def dnx_assert(condition: bool, message: str, *, logger: LogHandler_T = None) -> None:
    '''DNX assertion function.

    If an assertion fails and a logger is provided, the message is logged prior to raising the exception.
    '''
    if (condition): return

    if (logger):
        logger.emergency(message)

    # todo: figure out how or what to do for the module name in the direct log.
    #  for now we will use "system" as catch all if no logger is provided.
    else:
        from dnx_routines.logging.log_client import direct_log

        direct_log('system', _LOG.EMERGENCY, message)

    raise AssertionError(message)

# ========================
# EXCEPTION HOOKS
# ========================
import sys as _sys
import traceback as _tb
import threading as _threading

_err_report_path = f'{HOME_DIR}/dnx_profile/log/_err_reports'
_err_report_lock_file: ErrorReportsLock = f'{_err_report_path}/_err_reports.lock'  # type issue is fine

log_opener = partial(_os.open, mode=0o640)

def _dump_to_file(path: str, msg: str) -> None:
    _err_report_lock = _acquire_lock(_err_report_lock_file)

    with open(path, 'a+', opener=log_opener) as log_file:
        log_file.write(msg)

    _release_lock(_err_report_lock)

# Process hook -> called if an unhandled exception occurs in the Main thread or within the Thread exception hook.
def _handle_unhandled_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        hardout(f'Process [{__file__.split("/", 3)[3]}] terminated by Keyboard Interrupt.')

    if issubclass(exc_type, TerminateSignal):
        console_log(f'SIGTERM on unhandled exception handler. Process [{__file__.split("/", 3)[3]}] terminated.')

    err_report = _format_output(exc_type, exc_value, exc_traceback)
    err_file = f'{_err_report_path}/{_System.date(string=True)}_err.log'

    _dump_to_file(err_file, err_report)

    # checking for Log handler initialization to prevent additional errors on early runtime exceptions
    if (Log.is_running):
        Log.alert(f'{str(exc_type).split()[1][:-1]} -> {exc_value} :: see {err_file}')

    else:
        console_log(f'{str(exc_type).split()[1][:-1]} -> {exc_value} :: see {err_file}')

    hardout_errno(UNHANDLED_EXCEPTION)

_sys.excepthook = _handle_unhandled_exception


# Threads hook
def _handle_unhandled_thread_exception(args, /):
    ''' args = exc_type, exc_value, exc_traceback, thread
    '''
    err_report = _format_output(args.exc_type, args.exc_value, args.exc_traceback)
    err_file = f'{_err_report_path}/{_System.date(string=True)}_err.log'

    _dump_to_file(err_file, err_report)

    # checking for Log handler initialization to prevent additional errors on early runtime thread exceptions
    if (Log.is_running):
        Log.critical(f'{str(args.exc_type).split()[1][:-1]} -> {args.exc_value} :: see {err_file}')

    else:
        console_log(f'{str(args.exc_type).split()[1][:-1]} -> {args.exc_value} :: see {err_file}')

_threading.excepthook = _handle_unhandled_thread_exception


# UTILITY FUNCTIONS
def _format_output(exc_type, exc_value, exc_traceback) -> str:
    str_builder = [
        _format_threads(),
        f'{str(exc_type).split()[1][:-1]} -> {exc_value}\n',
        '-' * 36,
        ''.join(_tb.format_tb(exc_traceback)),
        '-' * 36,
        ''
    ]

    return '\n'.join(str_builder)

def _format_threads() -> str:
    active_threads = _threading.enumerate()

    str_builder = [
        '=' * 36,
        f'active: {len(active_threads)} time={fast_time()}',
        '=' * 36
    ]

    for i, t in enumerate(_threading.enumerate(), 1):

        if t is _threading.main_thread():
            status = 'M'

        elif t is _threading.current_thread():
            status = '!'

        else:
            status = 'R'

        str_builder.append(f'[{status}] {t}')

    str_builder.append('-' * 36)

    return '\n'.join(str_builder)
