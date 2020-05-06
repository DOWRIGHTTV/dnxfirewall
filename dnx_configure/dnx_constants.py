#!/usr/bin/env python3

import time as _time
import os as _os

from enum import Enum as _Enum, IntEnum as _IntEnum
from ipaddress import IPv4Address as _IPv4Address


FTIME = _time.time # fast call for epoch timestamp
fast_time = _time.time

VERBOSE = True
ROOT = True if not _os.getuid() else False

#interface bandwidth
INT_BANDWIDTH_TIMER = 5

# general settings
FILE_POLL_TIMER = 10

# dnx user/group
USER  = 'dnx'
GROUP = 'dnx'

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
    DNS_TLS  = 853

#MDNS_PORT       = 5353
SYSLOG_TLS_PORT = 6514
SYSLOG_SOCKET   = 6969 # LOCAL SOCKET
DATABASE_SOCKET = 6970 # LOCAL SOCKET

#syslog/logging
SYSTEM = 3
EVENT  = 14

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

MAX_A_RECORD_COUNT = 3
MINIMUM_TTL        = 300
DEFAULT_TTL        = 300
NOT_VALID          = -1

NULL_ADDR = (None,None)

TOP_DOMAIN_COUNT = 20
HEARTBEAT_FAIL_LIMIT = 3
KEEP_ALIVE_DOMAIN = 'duckduckgo.com'

class DNS(_IntEnum):
    #dns relay decisions
    ALLOWED    = -1
    FLAGGED    = -2
    TIMED_OUT  = -3
    NO_NOTICE  = -4
    WAIT_COUNT = 7 # NEW 1ms*i in range(7)  | OLD:wait for decision * interval(1ms)
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
    OPT   = 41
    AAAA  = 128

class ICMP(_IntEnum):
    ECHO = 8

# ips detection engines
# return status of detected portscans
class IPS(_Enum):
    DDOS     = 1
    PORTSCAN = 2
    BLOCKED  = 3
    MISSED   = 4
    LOGGED   = 5

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
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4 # allow better support for this without fully conforming to RFC
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8 # Add support
    DROP     = 9
    # dhcp lease types
    AVAILABLE   =  0
    RESERVATION = -1
    OFFERED     = -2
    LEASED      = -3
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

LAN_TO_WAN       = 10
WAN_TO_LAN       = 11
SEND_TO_IPS      = 20
IP_PROXY_DROP    = 25
SEND_TO_FIREWALL = 30

DNS_BIN_OFFSET = 4 # NOTE: 4 seems to be a good compromise of len(bins) vs len(buckets)
class DNS_CAT(_IntEnum):
    doh = -30
    whitelist = -20
    blacklist = -10

    malicious   = 10
    cryptominer = 11
    ads = 30

class IPP_CAT(_IntEnum):
    COMPROMISED = 10
    COMPROMISED_HOST = 11
    MALICIOUS   = 20
    MALICIOUS_HOST  = 21
    COMMAND_CONTROL = 22
    TOR       = 30
    TOR_ENTRY = 31
    TOR_EXIT  = 32

class GEO(_IntEnum):
    Brazil = 76
    China  = 156
    India  = 356
    Iran   = 364
    Japan  = 392
    NKorea = 408
    SKorea = 410
    Netherlands = 528
    Russia = 643
    Spain  = 724
    Thailand = 764
    Turkey = 792
    Venezuela = 862
