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
from typing import Optional as _Optional, Union as _Union

from dnx_iptools.cprotocol_tools import iptoi as _iptoi
from dnx_iptools.def_structs import scm_creds_pack as _scm_creds_pack

ppt = _PrettyPrinter(sort_dicts=False).pprint

# if set, module code dependencies will run. values are stored as strings
INIT_MODULE: bool = bool(_os.environ.get('INIT_MODULE', False))

console_log: _Callable[[str], None] = _partial(print, flush=True)
shell: _Callable[[str], None] = _partial(_run, shell=True, stdout=_DEVNULL, stderr=_DEVNULL)

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

byte_join:  _Callable[[_Iterable[bytes]], bytes] = b''.join
str_join:   _Callable[[_Iterable[str]], str] = ''.join
dot_join:   _Callable[[_Iterable[str]], str] = '.'.join
space_join: _Callable[[_Iterable[str]], str] = ' '.join
comma_join: _Callable[[_Iterable[str]], str] = ', '.join

HOME_DIR: str = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))

# dnx user/group + dev helper to when switching between appliance and dev box
__usr: str = _run('whoami', shell=True, text=True, capture_output=True).stdout.strip()

USER, GROUP = ('dnx', 'dnx') if __usr != 'free' else ('free', 'free')
ROOT: bool = not _os.getuid()

# globally sets which sql to use | sqlite3 = 0, psql = 1
SQL_VERSION: int = 0

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
NULL_ADDR: tuple[int, int] = (-1, -1)
INADDR_ANY: int = _iptoi('0.0.0.0')
LOCALHOST:  int = _iptoi('127.0.0.1')
BROADCAST:  int = _iptoi('255.255.255.255')
# definitions for ip proxy data structures. most/least significant bit
MSB: int = 0b11111111111110000000000000000000
LSB: int = 0b00000000000001111111111111111111

# NFQUEUE packet actions | marking packet, so it can be matched by next rules in order of operations
WAN_IN: int = 10  # used for limiting certain internal functions from applying to wan > inside traffic
LAN_IN: int = 11  # used for management access traffic matching
DMZ_IN: int = 12  # used for management access traffic matching

DNS_BIN_OFFSET: int = 4  # NOTE: 4 seems to be a good compromise of len(bins) vs len(buckets)

# ============================
# LOCAL SOCKET DEFINITIONS
# ============================
# process, user, group
DNX_AUTHENTICATION: bytes = _scm_creds_pack(_os.getpid(), _pwd.getpwnam(USER).pw_uid, _pwd.getpwnam(USER).pw_gid)

# SYSLOG_TLS_PORT = 6514
# SYSLOG_SOCKET   = 6970
CONTROL_SOCKET:  str = f'{HOME_DIR}/dnx_routines/dnx_system/control_sock'
DATABASE_SOCKET: str = f'{HOME_DIR}/dnx_routines/database/ddb_sock'

# ================================
# DNS PROXY DEFS (CONSIDER MOVING)
# ================================
CONNECT_TIMEOUT: int = 2
RELAY_TIMEOUT:   int = 30

MAX_A_RECORD_COUNT: int = 3
MINIMUM_TTL: int = 300
DEFAULT_TTL: int = 300

TOP_DOMAIN_COUNT: int = 20
HEARTBEAT_FAIL_LIMIT: int = 3
KEEP_ALIVE_DOMAIN: str = 'dnxfirewall.com'

# used when loading geolocation settings to implicitly include private ip space as a category
RFC1918: dict[str, int] = {'rfc1918': 1}

# TODO: consider moving to web_validate
INVALID_FORM: str = 'Invalid form data.'
