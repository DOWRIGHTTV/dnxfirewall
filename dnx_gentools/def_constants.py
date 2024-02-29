#!/usr/bin/env python3

from __future__ import annotations

import time as _time
import os as _os
import sys as _sys
import pwd as _pwd

from functools import partial as _partial
from itertools import repeat as _repeat
from subprocess import run as _run, DEVNULL as _DEVNULL
from pprint import PrettyPrinter as _PrettyPrinter

from typing import Callable as _Callable, Iterator as _Iterator, Iterable as _Iterable
from typing import Optional as _Optional, Union as _Union, Any as _Any

from dnx_iptools.def_structs import scm_creds_pack as _scm_creds_pack

# =====================================================
# PYTHON PATH MODIFICATION
# =====================================================
# lib dir is not in system path by default for all distros
#
# this assumes any module that would need the library files
# imports this file first for module initialization. if this
# is not the case, the lib dir will need to be added locally
# to the module or this file should be imported first.
_sys.path.append('/usr/local/lib')

# =====================================================
# MODULE INITIALIZATION CONTROL - set by shell command
# =====================================================
# module startup code will run if. values are stored as strings
def INITIALIZE_MODULE(log_name: str):
    '''returns True if the calling module functions should start.
    '''
    init_module: str = _os.environ.get('INIT_MODULE', '')

    return True if init_module == log_name.replace('_', '-') else False
# =====================================================


ppt: _Callable[[_Any], None] = _PrettyPrinter(sort_dicts=False).pprint

console_log: _Callable[[str], None] = _partial(print, flush=True)
shell: _Callable[..., None] = _partial(_run, shell=True, stdout=_DEVNULL, stderr=_DEVNULL)

RUN_FOREVER: _Iterator[int] = _repeat(1)
fast_sleep: _Callable[[_Union[int, float]], None] = _time.sleep
ftime = _time.time

def fast_time(_int=int, _time=_time.time) -> int: return _int(_time())
def hardout(msg: _Optional[str] = None) -> None:
    '''exit the application.

    guarantees all threads and processes are not left dangling.
    '''
    if (msg):
        console_log(msg)

    _os._exit(1)


# used by socket sender loops
ATTEMPTS: tuple[int, int] = (0, 1)
LAST_ATTEMPT: int = 1

byte_join:  _Callable[[_Iterable[bytes]], bytes] = b''.join
str_join:   _Callable[[_Iterable[str]], str] = ''.join
dot_join:   _Callable[[_Iterable[str]], str] = '.'.join
space_join: _Callable[[_Iterable[str]], str] = ' '.join
comma_join: _Callable[[_Iterable[str]], str] = ', '.join

# USER, GROUP, HOME_DIR - user set dynamically for development convenience (DNX user used in production deployment)
__usr = _pwd.getpwuid(_os.getuid())

# USER, GROUP = (__usr.pw_name, __usr.pw_name)
USER, GROUP = ('dnx', 'dnx') if any(['dnx' == u.pw_name for u in _pwd.getpwall()]) else ('free', 'free')
ROOT: bool = not __usr.pw_uid

# HOME_DIR:   str = f'{__usr.pw_dir}/dnxfirewall'
HOME_DIR: str = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))
SYSTEM_DIR: str = 'dnx_profile/data/system'
USER_DIR:   str = 'dnx_profile/data/usr'

# Certificate authority store file
CERTIFICATE_STORE: str = '/etc/ssl/certs/ca-certificates.crt'

LOG_LEVELS: list = [
    'EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG'
]

# timers
ONE_DAY:    int = 86400  # 1 day
ONE_HOUR:   int = 3600   # one hour
THIRTY_MIN: int = 1800   # 30 minutes
TEN_MIN:    int = 600    # 10 minutes
FIVE_MIN:   int = 300    # 5 minutes
THREE_MIN:  int = 180    # 3 minutes
ONE_MIN:    int = 60     # 1 minute
THIRTY_SEC: int = 30
TEN_SEC:    int = 10
FIVE_SEC:   int = 5
THREE_SEC:  int = 3
ONE_SEC:    int = 1
MSEC:     float = .001   # one millisecond
NO_DELAY:   int = 0

# ip addresses
NULL_ADDR:  tuple[str, int] = ('', -1)
INADDR_ANY: int = 0
LOCALHOST:  int = 2130706433
BROADCAST:  int = 4294967295

# definitions for ip proxy data structures. most/least significant bit
MSB: int = 0b11111111111110000000000000000000
LSB: int = 0b00000000000001111111111111111111
UINT16_MAX: int = 0b1111111111111111
UINT32_MAX: int = 0b11111111111111111111111111111111

OK: bool = True
ERR: bool = False
INSPECT_PACKET: bool = True
DONT_INSPECT_PACKET: bool = False

WAN_IN: int = 10  # used for limiting certain internal functions from applying to wan > inside traffic
LAN_IN: int = 11  # used for management access traffic matching
DMZ_IN: int = 12  # used for management access traffic matching

# ============================
# LOCAL SOCKET DEFINITIONS
# ============================
# process, user, group
CONTROL_AUTHENTICATION: tuple[int, int, int] = (_os.getpid(), _pwd.getpwnam(USER).pw_uid, _pwd.getpwnam(USER).pw_gid)
DNX_AUTHENTICATION: bytes = _scm_creds_pack(_os.getpid(), _pwd.getpwnam(USER).pw_uid, _pwd.getpwnam(USER).pw_gid)

# SYSLOG_TLS_PORT = 6514
# SYSLOG_SOCKET   = 6970
CONTROL_SOCKET: tuple[str, int] = ('127.0.0.1', 6969)
# DATABASE_SOCKET: tuple[str, int] = ('127.0.0.1', 6970)
# CONTROL_SOCKET:  str = f'{HOME_DIR}/dnx_profile/control.sock'
DATABASE_SOCKET: str = f'{HOME_DIR}/dnx_routines/database/ddb.sock'

# ================================
# DNS PROXY DEFS (CONSIDER MOVING)
# ================================
CONNECT_TIMEOUT: int = 2
RELAY_TIMEOUT:   int = 30

MAX_A_RECORD_COUNT: int = 3
# MINIMUM_TTL: int = 300
DEFAULT_TTL: int = 300

TOP_DOMAIN_COUNT: int = 20
HEARTBEAT_FAIL_LIMIT: int = 3
KEEP_ALIVE_DOMAIN: str = 'dnxfirewall.com'

# used when loading geolocation settings to implicitly include private ip space as a category
RFC1918: tuple[str, int] = ('rfc1918', 0)
