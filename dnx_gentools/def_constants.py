#!/usr/bin/env python3

import time as _time
import os as _os
import pwd as _pwd

from functools import partial as _partial
from itertools import repeat as _repeat
from subprocess import run as _run, DEVNULL as _DEVNULL
from ipaddress import IPv4Address as _IPv4Address

from dnx_iptools.def_structs import scm_creds_pack as _scm_creds_pack

# if set, module code dependendies will run
INIT_MODULE = _os.environ.get('INIT_MODULE', False)


fast_time  = _time.time
fast_sleep = _time.sleep

hard_out = _partial(_os._exit, 1)
console_log = _partial(print, flush=True)
shell = _partial(_run, shell=True, stdout=_DEVNULL, stderr=_DEVNULL)

RUN_FOREVER = _partial(_repeat, 1)

# used by socket sender loops
ATTEMPTS = (0, 1)

byte_join = b''.join
str_join = ''.join
dot_join = '.'.join
space_join = ' '.join
comma_join = ', '.join

HOME_DIR = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))

# dnx user/group + dev helper to when switching between appliance and dev box
__usr = _run('whoami', shell=True, text=True, capture_output=True).stdout.strip()

USER, GROUP = ('dnx', 'dnx') if __usr != 'free' else ('free', 'free')
ROOT = not _os.getuid()

# globally sets which sql to use | sqlite3 = 0, psql = 1
SQL_VERSION = 0

# Certificate authority store file
CERTIFICATE_STORE = '/etc/ssl/certs/ca-certificates.crt'

LOG_LEVELS = [
    'EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG'
]

# timers
ONE_DAY    = 86400 # 1 day
ONE_HOUR   = 3600 # one hour
THIRTY_MIN = 1800 # 30 minutes
TEN_MIN    = 600 # 10 minutes
FIVE_MIN   = 300 # 5 minutes
THREE_MIN  = 180 # 3 minutes
ONE_MIN    = 60 # 1 minute
THIRTY_SEC = 30
TEN_SEC    = 10
FIVE_SEC   = 5
THREE_SEC  = 3
ONE_SEC    = 1
MSEC       = .001 # one millisecond
NO_DELAY   = 0

# ip addresses
NULL_ADDR = (None, None)
LOCALHOST  = _IPv4Address('127.0.0.1')
INADDR_ANY = _IPv4Address('0.0.0.0')
BROADCAST  = _IPv4Address('255.255.255.255')

# definitions for ip proxy data structures. most/least significant bit
MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111

# NFQUEUE packet actions | marking packet, so it can be matched by next rules in order of operations
WAN_IN = 10  # used for limiting certain internal functions from applying to wan > inside traffic
LAN_IN = 11  # used for management access traffic matching
DMZ_IN = 12  # used for management access traffic matching

DNS_BIN_OFFSET = 4  # NOTE: 4 seems to be a good compromise of len(bins) vs len(buckets)

# ============================
# LOCAL SOCKET DEFINITIONS
# ============================
# process, user, group
DNX_AUTHENTICATION = _scm_creds_pack(_os.getpid(), _pwd.getpwnam(USER).pw_uid, _pwd.getpwnam(USER).pw_gid)

# SYSLOG_TLS_PORT = 6514
# SYSLOG_SOCKET   = 6970 # LOCAL SOCKET
CONTROL_SOCKET  = bytes(f'{HOME_DIR}/dnx_routines/dnx_system/control_sock', 'utf-8')  # LOCAL SOCKET
DATABASE_SOCKET = bytes(f'{HOME_DIR}/dnx_routines/database/ddb_sock', 'utf-8')  # LOCAL SOCKET

# ================================
# DNS PROXY DEFS (CONSIDER MOVING)
# ================================
CONNECT_TIMEOUT = 2
RELAY_TIMEOUT   = 30

MAX_A_RECORD_COUNT = 3
MINIMUM_TTL        = 300
DEFAULT_TTL        = 300

TOP_DOMAIN_COUNT = 20
HEARTBEAT_FAIL_LIMIT = 3
KEEP_ALIVE_DOMAIN = 'dnxfirewall.com'

# used when loading geolocation settings to implicitly include private ip space as a category
RFC1918 = {'rfc1918': 1}

# TODO: consider moving to web_validate
INVALID_FORM = 'Invalid form data.'
