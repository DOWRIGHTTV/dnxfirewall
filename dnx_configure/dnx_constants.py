#!/usr/bin/env python3

import time as _time
import os as _os
import sys as _sys

from functools import partial as _partial
from subprocess import run as _run, DEVNULL as _DEVNULL
from enum import Enum as _Enum, IntEnum as _IntEnum
from ipaddress import IPv4Address as _IPv4Address

fast_time  = _time.time
fast_sleep = _time.sleep

write_log = _partial(print, flush=True)
shell = _partial(_run, shell=True, stdout=_DEVNULL, stderr=_DEVNULL)

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
    DHCP = 1

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

# QUEUE NUMBERS
class Queue(_IntEnum):
    IP_PROXY = 1
    IPS_IDS  = 2

# =====================
# NOTE: FUTURE USE
class Module(_IntEnum):
    IP_PROXY = 10
    IPS = 20
    FIREWALL = 30

# ZONES
class Zone(_IntEnum):
    NONE = 0
    LAN  = 1
    WAN  = 2
    DMZ  = 3

# mark = (Module.IPS << 8 | Zone.LAN)
# =====================

# NFQUEUE packet actions | marking packet so it can be matched by next rules in order of operations
LAN_IN = 10
WAN_IN = 11
DMZ_IN = 12

SEND_TO_IPS   = 21 # only inspecting wan, so set to wan identifier
IP_PROXY_DROP = 25

LAN_ZONE_FIREWALL = 30
WAN_ZONE_FIREWALL = 31
DMZ_ZONE_FIREWALL = 32

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

class GEO(_IntEnum):
    NONE = 0
    AFGHANISTAN = 4
    ALAND_ISLANDS = 248
    ALBANIA = 8
    ALGERIA = 12
    AMERICAN_SAMOA = 16
    ANDORRA = 20
    ANGOLA = 24
    ANGUILLA = 660
    ANTARCTICA = 10
    ANTIGUA_AND_BARBUDA = 28
    ARGENTINA = 32
    ARMENIA = 51
    ARUBA = 533
    AUSTRALIA = 36
    AUSTRIA = 40
    AZERBAIJAN = 31
    BAHAMAS = 44
    BAHRAIN = 48
    BANGLADESH = 50
    BARBADOS = 52
    BELARUS = 112
    BELGIUM = 56
    BELIZE = 84
    BENIN = 204
    BERMUDA = 60
    BHUTAN = 64
    BOLIVIA = 68
    BOSNIA_AND_HERZEGOVINA = 70
    BOTSWANA = 72
    BOUVET_ISLAND = 74
    BRAZIL = 76
    BRITISH_VIRGIN_ISLANDS = 92
    BRITISH_INDIAN_OCEAN_TERRITORY = 86
    BRUNEI_DARUSSALAM = 96
    BULGARIA = 100
    BURKINA_FASO = 854
    BURUNDI = 108
    CAMBODIA = 116
    CAMEROON = 120
    CANADA = 124
    CAPE_VERDE = 132
    CAYMAN_ISLANDS = 136
    CENTRAL_AFRICAN_REPUBLIC = 140
    CHAD = 148
    CHILE = 152
    CHINA = 156
    HONG_KONG = 344
    MACAO = 446
    CHRISTMAS_ISLAND = 162
    COCOS_ISLANDS = 166
    COLOMBIA = 170
    COMOROS = 174
    CONGO_BRAZZAVILLE = 178
    CONGO_KINSHASA_ = 180
    COOK_ISLANDS = 184
    COSTA_RICA = 188
    COTE_DIVOIRE = 384
    CROATIA = 191
    CUBA = 192
    CYPRUS = 196
    CZECH_REPUBLIC = 203
    DENMARK = 208
    DJIBOUTI = 262
    DOMINICA = 212
    DOMINICAN_REPUBLIC = 214
    ECUADOR = 218
    EGYPT = 818
    EL_SALVADOR = 222
    EQUATORIAL_GUINEA = 226
    ERITREA = 232
    ESTONIA = 233
    ETHIOPIA = 231
    FALKLAND_ISLANDS = 238
    FAROE_ISLANDS = 234
    FIJI = 242
    FINLAND = 246
    FRANCE = 250
    FRENCH_GUIANA = 254
    FRENCH_POLYNESIA = 258
    FRENCH_SOUTHERN_TERRITORIES = 260
    GABON = 266
    GAMBIA = 270
    GEORGIA = 268
    GERMANY = 276
    GHANA = 288
    GIBRALTAR = 292
    GREECE = 300
    GREENLAND = 304
    GRENADA = 308
    GUADELOUPE = 312
    GUAM = 316
    GUATEMALA = 320
    GUERNSEY = 831
    GUINEA = 324
    GUINEA_BISSAU = 624
    GUYANA = 328
    HAITI = 332
    HEARD_AND_MCDONALD_ISLANDS = 334
    HOLY_SEE = 336
    HONDURAS = 340
    HUNGARY = 348
    ICELAND = 352
    INDIA = 356
    INDONESIA = 360
    IRAN = 364
    IRAQ = 368
    IRELAND = 372
    ISLE_OF_MAN = 833
    ISRAEL = 376
    ITALY = 380
    JAMAICA = 388
    JAPAN = 392
    JERSEY = 832
    JORDAN = 400
    KAZAKHSTAN = 398
    KENYA = 404
    KIRIBATI = 296
    NORTH_KOREA = 408
    SOUTH_KOREA = 410
    KUWAIT = 414
    KYRGYZSTAN = 417
    LAOS = 418
    LATVIA = 428
    LEBANON = 422
    LESOTHO = 426
    LIBERIA = 430
    LIBYA = 434
    LIECHTENSTEIN = 438
    LITHUANIA = 440
    LUXEMBOURG = 442
    MACEDONIA = 807
    MADAGASCAR = 450
    MALAWI = 454
    MALAYSIA = 458
    MALDIVES = 462
    MALI = 466
    MALTA = 470
    MARSHALL_ISLANDS = 584
    MARTINIQUE = 474
    MAURITANIA = 478
    MAURITIUS = 480
    MAYOTTE = 175
    MEXICO = 484
    MICRONESIA = 583
    MOLDOVA = 498
    MONACO = 492
    MONGOLIA = 496
    MONTENEGRO = 499
    MONTSERRAT = 500
    MOROCCO = 504
    MOZAMBIQUE = 508
    MYANMAR = 104
    NAMIBIA = 516
    NAURU = 520
    NEPAL = 524
    NETHERLANDS = 528
    NETHERLANDS_ANTILLES = 530
    NEW_CALEDONIA = 540
    NEW_ZEALAND = 554
    NICARAGUA = 558
    NIGER = 562
    NIGERIA = 566
    NIUE = 570
    NORFOLK_ISLAND = 574
    NORTHERN_MARIANA_ISLANDS = 580
    NORWAY = 578
    OMAN = 512
    PAKISTAN = 586
    PALAU = 585
    PALESTINE = 275
    PANAMA = 591
    PAPUA_NEW_GUINEA = 598
    PARAGUAY = 600
    PERU = 604
    PHILIPPINES = 608
    PITCAIRN = 612
    POLAND = 616
    PORTUGAL = 620
    PUERTO_RICO = 630
    QATAR = 634
    REUNION = 638
    ROMANIA = 642
    RUSSIAN_FEDERATION = 643
    RWANDA = 646
    SAINT_BARTHELEMY = 652
    SAINT_HELENA = 654
    SAINT_KITTS_AND_NEVIS = 659
    SAINT_LUCIA = 662
    SAINT_MARTIN = 663
    SAINT_PIERRE_AND_MIQUELON = 666
    SAINT_VINCENT_AND_GRENADINES = 670
    SAMOA = 882
    SAN_MARINO = 674
    SAO_TOME_AND_PRINCIPE = 678
    SAUDI_ARABIA = 682
    SENEGAL = 686
    SERBIA = 688
    SEYCHELLES = 690
    SIERRA_LEONE = 694
    SINGAPORE = 702
    SLOVAKIA = 703
    SLOVENIA = 705
    SOLOMON_ISLANDS = 90
    SOMALIA = 706
    SOUTH_AFRICA = 710
    SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS = 239
    SOUTH_SUDAN = 728
    SPAIN = 724
    SRI_LANKA = 144
    SUDAN = 736
    SURINAME = 740
    SVALBARD_AND_JAN_MAYEN_ISLANDS = 744
    SWAZILAND = 748
    SWEDEN = 752
    SWITZERLAND = 756
    SYRIA = 760
    TAIWAN = 158
    TAJIKISTAN = 762
    TANZANIA = 834
    THAILAND = 764
    TIMOR_LESTE = 626
    TOGO = 768
    TOKELAU = 772
    TONGA = 776
    TRINIDAD_AND_TOBAGO = 780
    TUNISIA = 788
    TURKEY = 792
    TURKMENISTAN = 795
    TURKS_AND_CAICOS_ISLANDS = 796
    TUVALU = 798
    UGANDA = 800
    UKRAINE = 804
    UNITED_ARAB_EMIRATES = 784
    UNITED_KINGDOM = 826
    UNITED_STATES = 840
    US_MINOR_OUTLYING_ISLANDS = 581
    URUGUAY = 858
    UZBEKISTAN = 860
    VANUATU = 548
    VENEZUELA = 862
    VIETNAM = 704
    VIRGIN_ISLANDS = 850
    WALLIS_AND_FUTUNA_ISLANDS = 876
    WESTERN_SAHARA = 732
    YEMEN = 887
    ZAMBIA = 894
    ZIMBABWE = 716
