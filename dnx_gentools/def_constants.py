#!/usr/bin/env python3

import time as _time
import os as _os

from functools import partial as _partial
from subprocess import run as _run, DEVNULL as _DEVNULL
from enum import Enum as _Enum, IntEnum as _IntEnum, Flag as _Flag
from ipaddress import IPv4Address as _IPv4Address

fast_time  = _time.time
fast_sleep = _time.sleep

hard_out = _partial(_os._exit, 1)
write_log = _partial(print, flush=True)
shell = _partial(_run, shell=True, stdout=_DEVNULL, stderr=_DEVNULL)

byte_join = b''.join
str_join = ''.join

# this is a dev helper to when switching between appliance and dev box
__current_user = _run('whoami', shell=True, text=True, capture_output=True).stdout.strip()
# dnx user/group
if (__current_user == 'free'):
    USER  = 'free'
    GROUP = 'free'
else:
    USER  = 'dnx'
    GROUP = 'dnx'

ROOT = True if not _os.getuid() else False

HOME_DIR = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))

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

# definitions for ip proxy data structures. most/least significant bit
MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111

MAC_TEMPLATE = b'\x00\x00\x00\x00\x00\x00'
L2_PROTO = 0x0800

#CFG
class CFG(_IntEnum):
    DEL = 0
    ADD = 1
    ADD_DEL = 2
    RESTORE = 3

#interface states
class INTF(_IntEnum):
    STATIC = 0
    DHCP   = 1

    BUILTINS = 69
    EXTENDED = 70

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
    ANY      = 0 # alias
    ICMP     = 1
    TCP      = 6
    UDP      = 17
    DNS      = 53
    DHCP_SVR = 67
    HTTPS    = 443
    DNS_TLS  = 853

SYSLOG_TLS_PORT = 6514
CONTROL_SOCKET  = 6969 # LOCAL SOCKET
SYSLOG_SOCKET   = 6970 # LOCAL SOCKET
DATABASE_SOCKET = 6971 # LOCAL SOCKET

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
class DIR(_Flag):
    DISABLED = 0
    OUTBOUND = 1
    INBOUND  = 2
    BOTH     = 3

class CONN(_Enum):
    # decisions
    REJECT  = -2
    INSPECT = -1 # drop with full inspection
    DROP    = 0
    ACCEPT  = 1

# dhcp server message types
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

# QUEUE NUMBERS
class Queue(_IntEnum):
    IP_PROXY  = 1
    IPS_IDS   = 2
    CFIREWALL = 69

# NFQUEUE packet actions | marking packet so it can be matched by next rules in order of operations
WAN_IN = 10 # used for limiting certain internal functions from applying to wan > inside traffic
LAN_IN = 11 # used for management access traffic matching
DMZ_IN = 12 # used for management access traffic matching

SEND_TO_IPS = 20 # INPUT chain wan forward to IPS/IDS

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

class REP(_IntEnum):
    DNL = -1 # did not look due to being geo filtered
    NONE = 0
    COMPROMISED = 10
    COMPROMISED_HOST = 11
    MALICIOUS   = 20
    MALICIOUS_HOST  = 21
    COMMAND_CONTROL = 22
    TOR       = 30
    TOR_ENTRY = 31
    TOR_EXIT  = 32

# used when loading geolocation settings to include implicitly include private ip space as a category
RFC1918 = {'rfc1918': 1}

_GEO_LIST = [
    'NONE',
    'RFC1918',
    'AFGHANISTAN',
    'ALAND_ISLANDS',
    'ALBANIA',
    'ALGERIA',
    'AMERICAN_SAMOA',
    'ANDORRA',
    'ANGOLA',
    'ANGUILLA',
    'ANTARCTICA',
    'ANTIGUA_AND_BARBUDA',
    'ARGENTINA',
    'ARMENIA',
    'ARUBA',
    'AUSTRALIA',
    'AUSTRIA',
    'AZERBAIJAN',
    'BAHAMAS',
    'BAHRAIN',
    'BANGLADESH',
    'BARBADOS',
    'BELARUS',
    'BELGIUM',
    'BELIZE',
    'BENIN',
    'BERMUDA',
    'BHUTAN',
    'BOLIVIA',
    'BOSNIA_AND_HERZEGOVINA',
    'BOTSWANA',
    'BOUVET_ISLAND',
    'BRAZIL',
    'BRITISH_VIRGIN_ISLANDS',
    'BRITISH_INDIAN_OCEAN_TERRITORY',
    'BRUNEI_DARUSSALAM',
    'BULGARIA',
    'BURKINA_FASO',
    'BURUNDI',
    'CAMBODIA',
    'CAMEROON',
    'CANADA',
    'CAPE_VERDE',
    'CAYMAN_ISLANDS',
    'CENTRAL_AFRICAN_REPUBLIC',
    'CHAD',
    'CHILE',
    'CHINA',
    'HONG_KONG',
    'MACAO',
    'CHRISTMAS_ISLAND',
    'COCOS_ISLANDS',
    'COLOMBIA',
    'COMOROS',
    'CONGO_BRAZZAVILLE',
    'CONGO_KINSHASA_',
    'COOK_ISLANDS',
    'COSTA_RICA',
    'COTE_DIVOIRE',
    'CROATIA',
    'CUBA',
    'CYPRUS',
    'CZECH_REPUBLIC',
    'DENMARK',
    'DJIBOUTI',
    'DOMINICA',
    'DOMINICAN_REPUBLIC',
    'ECUADOR',
    'EGYPT',
    'EL_SALVADOR',
    'EQUATORIAL_GUINEA',
    'ERITREA',
    'ESTONIA',
    'ETHIOPIA',
    'FALKLAND_ISLANDS',
    'FAROE_ISLANDS',
    'FIJI',
    'FINLAND',
    'FRANCE',
    'FRENCH_GUIANA',
    'FRENCH_POLYNESIA',
    'FRENCH_SOUTHERN_TERRITORIES',
    'GABON',
    'GAMBIA',
    'GEORGIA',
    'GERMANY',
    'GHANA',
    'GIBRALTAR',
    'GREECE',
    'GREENLAND',
    'GRENADA',
    'GUADELOUPE',
    'GUAM',
    'GUATEMALA',
    'GUERNSEY',
    'GUINEA',
    'GUINEA_BISSAU',
    'GUYANA',
    'HAITI',
    'HEARD_AND_MCDONALD_ISLANDS',
    'HOLY_SEE',
    'HONDURAS',
    'HUNGARY',
    'ICELAND',
    'INDIA',
    'INDONESIA',
    'IRAN',
    'IRAQ',
    'IRELAND',
    'ISLE_OF_MAN',
    'ISRAEL',
    'ITALY',
    'JAMAICA',
    'JAPAN',
    'JERSEY',
    'JORDAN',
    'KAZAKHSTAN',
    'KENYA',
    'KIRIBATI',
    'NORTH_KOREA',
    'SOUTH_KOREA',
    'KUWAIT',
    'KYRGYZSTAN',
    'LAOS',
    'LATVIA',
    'LEBANON',
    'LESOTHO',
    'LIBERIA',
    'LIBYA',
    'LIECHTENSTEIN',
    'LITHUANIA',
    'LUXEMBOURG',
    'MACEDONIA',
    'MADAGASCAR',
    'MALAWI',
    'MALAYSIA',
    'MALDIVES',
    'MALI',
    'MALTA',
    'MARSHALL_ISLANDS',
    'MARTINIQUE',
    'MAURITANIA',
    'MAURITIUS',
    'MAYOTTE',
    'MEXICO',
    'MICRONESIA',
    'MOLDOVA',
    'MONACO',
    'MONGOLIA',
    'MONTENEGRO',
    'MONTSERRAT',
    'MOROCCO',
    'MOZAMBIQUE',
    'MYANMAR',
    'NAMIBIA',
    'NAURU',
    'NEPAL',
    'NETHERLANDS',
    'NETHERLANDS_ANTILLES',
    'NEW_CALEDONIA',
    'NEW_ZEALAND',
    'NICARAGUA',
    'NIGER',
    'NIGERIA',
    'NIUE',
    'NORFOLK_ISLAND',
    'NORTHERN_MARIANA_ISLANDS',
    'NORWAY',
    'OMAN',
    'PAKISTAN',
    'PALAU',
    'PALESTINE',
    'PANAMA',
    'PAPUA_NEW_GUINEA',
    'PARAGUAY',
    'PERU',
    'PHILIPPINES',
    'PITCAIRN',
    'POLAND',
    'PORTUGAL',
    'PUERTO_RICO',
    'QATAR',
    'REUNION',
    'ROMANIA',
    'RUSSIAN_FEDERATION',
    'RWANDA',
    'SAINT_BARTHELEMY',
    'SAINT_HELENA',
    'SAINT_KITTS_AND_NEVIS',
    'SAINT_LUCIA',
    'SAINT_MARTIN',
    'SAINT_PIERRE_AND_MIQUELON',
    'SAINT_VINCENT_AND_GRENADINES',
    'SAMOA',
    'SAN_MARINO',
    'SAO_TOME_AND_PRINCIPE',
    'SAUDI_ARABIA',
    'SENEGAL',
    'SERBIA',
    'SEYCHELLES',
    'SIERRA_LEONE',
    'SINGAPORE',
    'SLOVAKIA',
    'SLOVENIA',
    'SOLOMON_ISLANDS',
    'SOMALIA',
    'SOUTH_AFRICA',
    'SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS',
    'SOUTH_SUDAN',
    'SPAIN',
    'SRI_LANKA',
    'SUDAN',
    'SURINAME',
    'SVALBARD_AND_JAN_MAYEN_ISLANDS',
    'SWAZILAND',
    'SWEDEN',
    'SWITZERLAND',
    'SYRIA',
    'TAIWAN',
    'TAJIKISTAN',
    'TANZANIA',
    'THAILAND',
    'TIMOR_LESTE',
    'TOGO',
    'TOKELAU',
    'TONGA',
    'TRINIDAD_AND_TOBAGO',
    'TUNISIA',
    'TURKEY',
    'TURKMENISTAN',
    'TURKS_AND_CAICOS_ISLANDS',
    'TUVALU',
    'UGANDA',
    'UKRAINE',
    'UNITED_ARAB_EMIRATES',
    'UNITED_KINGDOM',
    'UNITED_STATES',
    'US_MINOR_OUTLYING_ISLANDS',
    'URUGUAY',
    'UZBEKISTAN',
    'VANUATU',
    'VENEZUELA',
    'VIETNAM',
    'VIRGIN_ISLANDS',
    'WALLIS_AND_FUTUNA_ISLANDS',
    'WESTERN_SAHARA',
    'YEMEN',
    'ZAMBIA',
    'ZIMBABWE'
]

GEO = _IntEnum('GEO', _GEO_LIST)