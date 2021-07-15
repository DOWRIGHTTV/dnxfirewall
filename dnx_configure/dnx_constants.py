#!/usr/bin/env python3

import time as _time
import os as _os
import sys as _sys

from enum import Enum as _Enum, IntEnum as _IntEnum
from ipaddress import IPv4Address as _IPv4Address

fast_time  = _time.time
fast_sleep = _time.sleep
def write_log(entry):
    _sys.stdout.write(f'{entry}\n')
    _sys.stdout.flush()

byte_join = b''.join
str_join = ''.join

ROOT = True if not _os.getuid() else False

# globally sets which sql to use | sqlite3 = 0, psql = 1
SQL_VERSION = 0

INVALID_FORM = 'Invalid form data.'
class DATA(_IntEnum):
    INVALID = -1
    MISSING = -2

#interface bandwidth
INT_BANDWIDTH_TIMER = 5

# general settings
FILE_POLL_TIMER = 10

# dnx user/group
USER  = 'dnx'
GROUP = 'dnx'

# Certificate authority store file
CERTIFICATE_STORE = '/etc/ssl/certs/ca-certificates.crt'

#front end domain height counts
DF_DOMAIN_HEIGHT = 6
UD_DOMAIN_HEIGHT = 3
TLD_HEIGHT       = 4

#dnx shell
SHELL_SPACE = 30

# ip addresses
LOCALHOST  = _IPv4Address('127.0.0.1')
INADDR_ANY = _IPv4Address('0.0.0.0')
BROADCAST  = _IPv4Address('255.255.255.255')

MAC_TEMPLATE = b'\x00\x00\x00\x00\x00\x00'
L2_PROTO = 0x0800

#CFG
class CFG(_IntEnum):
    DEL = 0
    ADD = 1
    ADD_DEL = 2

#protocols
class DNX(_IntEnum):
    INIT  = 0
    CONT  = 1
    RESP  = 2
    VT1   = 1
    VT2   = 2
    RCODE = 3
    JSON  = 4

class SOCK(_IntEnum):
    RAW = 1
    TCP = 6
    UDP = 17

class PROTO(_IntEnum):
    NOT_SET  = 0
    ICMP     = 1
    TCP      = 6
    UDP      = 17
    DNS      = 53
    DHCP_SVR = 67
    HTTPS    = 443
    DNS_TLS  = 853

SYSLOG_TLS_PORT = 6514
SYSLOG_SOCKET   = 6969 # LOCAL SOCKET
DATABASE_SOCKET = 6970 # LOCAL SOCKET

#syslog/logging
class LOG(_IntEnum):
    SYSTEM  = 3
    EVENT   = 14
    NONE      = -1
    EMERGENCY = 0
    ALERT     = 1
    CRITICAL  = 2
    ERROR     = 3
    WARNING   = 4
    NOTICE    = 5
    INFO      = 6
    DEBUG     = 7

LOG_LEVELS = [
    'EMERGENCY',
    'ALERT',
    'CRITICAL',
    'ERROR',
    'WARNING',
    'NOTICE',
    'INFO',
    'DEBUG'
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

# dns record related values
MAX_A_RECORD_COUNT = 3
MINIMUM_TTL        = 300
DEFAULT_TTL        = 300
NOT_VALID          = -1

TOP_DOMAIN_COUNT = 20
HEARTBEAT_FAIL_LIMIT = 3
KEEP_ALIVE_DOMAIN = 'dnxfirewall.com'

NULL_ADDR = (None,None)

class DNS(_IntEnum):
    #dns relay decisions
    ALLOWED    = -1
    FLAGGED    = -2
    TIMED_OUT  = -3
    NO_NOTICE  = -4
    WAIT_COUNT = 7 # NEW 1ms*i in range(WAIT_COUNT)  | OLD:wait for decision * interval(1ms)
    # module identifiers
    SERVER = 0
    PROXY  = 1
    #dns query types
    QUERY     = 0
    RESPONSE  = 1
    KEEPALIVE = 69
    #dns record types
    LOCAL = 0
    ROOT  = 0
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    AAAA  = 28
    OPT   = 41

class ICMP(_IntEnum):
    ECHO = 8

class TLS(_IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE  = 11
    SERVER_HELLO_DONE = 14

# ips detection engines
# return status of detected portscans
class IPS(_Enum):
    DISABLED = 0
    DDOS     = 1
    PORTSCAN = 2
    BOTH     = 3
    BLOCKED  = 4
    FILTERED = 5
    MISSED   = 6
    LOGGED   = 7

# traffic direction / type
class DIR(_Enum):
    DISABLED = 0
    OUTBOUND = 1
    INBOUND  = 2
    BOTH     = 3

class CONN(_Enum):
    INITIAL    = 1
    RETRANSMIT = 2
    RESPONSE   = 3
    FINAL      = 4
    # decisions
    DROP   = 5
    ACCEPT = 6

#dhcp server message types
class DHCP(_IntEnum):
    NOT_SET  = 0
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4 # allow better support for this without fully conforming to RFC
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8 # Add support
    DROP     = 9
    # dhcp lease types | these are required ints
    AVAILABLE   = -1
    RESERVATION = -2
    OFFERED     = -3
    LEASED      = -4
    # dhcp request types
    SELECTING   = 11
    INIT_REBOOT = 12
    RENEWING    = 13
    REBINDING   = 14
    # option type
    END = 255

# NFQUEUE packet actions | marking packet so it can be matched by next rules in order of operations
LAN_IN = 10
WAN_IN = 11
DMZ_IN = 12

SEND_TO_IPS      = 20
IP_PROXY_DROP    = 25
SEND_TO_FIREWALL = 30

DNS_BIN_OFFSET = 4 # NOTE: 4 seems to be a good compromise of len(bins) vs len(buckets)
class DNS_CAT(_IntEnum):
    NONE = 0

    doh = -30
    time_based = -5

    malicious   = 10
    cryptominer = 11
    telemetry   = 20
    ads = 30
    vpn = 40
    mature = 50
    pornography = 60
    drugs   = 70
    weapons = 80
    socialmedia = 90
    dyndns = 100
    p2p    = 110
    gambling    = 120
    videogames  = 130
    purchases   = 140
    remotelogin = 150
    downloads   = 160
    teentop50   = 1000

class TLD_CAT(_IntEnum):
    NONE = 0

    ru = 1
    cn = 2
    xxx = 3
    porn = 4
    adult = 5
    ads = 6
    click = 7
    download = 8
    top = 9
    loan = 10
    work = 11
    men = 12
    cf = 13
    gq = 14
    ml = 15
    ga = 16

class IPP_CAT(_IntEnum):
    NONE = 0
    COMPROMISED = 10
    COMPROMISED_HOST = 11
    MALICIOUS   = 20
    MALICIOUS_HOST  = 21
    COMMAND_CONTROL = 22
    TOR       = 30
    TOR_ENTRY = 31
    TOR_EXIT  = 32

class GEO(_IntEnum):
    NONE   = 0
    BRAZIL = 76
    CHINA  = 156
    INDIA  = 356
    IRAN   = 364
    JAPAN  = 392
    N_KOREA = 408
    S_KOREA = 410
    NETHERLANDS = 528
    RUSSIA = 643
    SPAIN  = 724
    THAILAND = 764
    TURKEY = 792
    VENEZUELA = 862
