#!/usr/bin/env python3

from __future__ import annotations

from enum import Enum as _Enum, Flag as _Flag, IntEnum as _IntEnum, IntFlag as _IntFlag


class DATA(_IntEnum):
    INVALID = -1
    MISSING = -2

# interface states
class INTF(_IntEnum):
    STATIC = 0
    DHCP   = 1

    BUILTINS = 69
    EXTENDED = 70

# enum replacement for socket constants
class SOCK(_IntEnum):
    RAW = 1
    TCP = 6
    UDP = 17

class PROTO(_IntEnum):
    NOT_SET = 0

    # IP
    ANY     = 0  # alias
    ICMP    = 1
    TCP     = 6
    UDP     = 17

    # TCP/UDP
    DNS      = 53
    DHCP_SVR = 67
    HTTPS    = 443
    DNS_TLS  = 853

# syslog/logging
class LOG(_IntEnum):
    SYSTEM = 3
    EVENT  = 14

    NONE = -1

    EMERGENCY = 0
    ALERT     = 1
    CRITICAL  = 2
    ERROR     = 3
    WARNING   = 4
    NOTICE    = 5
    INFO      = 6
    DEBUG     = 7

class PROFILE_MASK(_IntFlag):
    pass

class DNS(_IntEnum):
    # dns relay decisions
    ALLOWED   = -1
    FLAGGED   = -2
    TIMED_OUT = -3
    NO_NOTICE = -4

    # module identifiers
    SERVER = 0
    PROXY  = 1
    # dns query types
    QUERY     = 0
    RESPONSE  = 1
    KEEPALIVE = 69
    # dns record types
    LOCAL = 0
    ROOT  = 0
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    AAAA  = 28
    OPT   = 41

class DNS_MASK(_IntFlag):
    QR = 0b1000000000000000
    OP = 0b0111100000000000
    AA = 0b0000010000000000
    TC = 0b0000001000000000
    RD = 0b0000000100000000
    RA = 0b0000000010000000
    ZZ = 0b0000000001000000
    AD = 0b0000000000100000
    CD = 0b0000000000010000
    RC = 0b0000000000001111

class DHCP_MASK(_IntFlag):
    BCAST = 0b1000000000000000

class ICMP(_IntEnum):
    ECHO = 8

# ips detection engines
class IPS(_Enum):
    DISABLED = 0
    DDOS     = 1
    PORTSCAN = 2
    BOTH     = 3

    BLOCKED  = 4
    REJECTED = 5
    FILTERED = 6
    MISSED   = 7
    LOGGED   = 8

# traffic direction / type
class DIR(_Flag):
    DISABLED = 0
    OUTBOUND = 1
    INBOUND  = 2
    BOTH     = 3

class CONN(_IntEnum):
    # decisions
    REJECT  = -2
    INSPECT = -1  # drop with full inspection
    DROP    = 0
    ACCEPT  = 1

# dhcp server message types
class DHCP(_IntEnum):
    NOT_SET  = 0
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4  # allow better support for this without fully conforming to RFC
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8  # Add support
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
    DNS_PROXY = 2
    IPS_IDS   = 3
    CFIREWALL = 69

class DNS_CAT(_IntEnum):
    NONE = 0

    doh = 900  # system
    time_based = 990  # system

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

class REP(_IntEnum):
    DNL  = -1  # did not look due to being geo filtered
    NONE = 0

    COMPROMISED      = 10
    COMPROMISED_HOST = 11

    MALICIOUS       = 20
    MALICIOUS_HOST  = 21
    COMMAND_CONTROL = 22

    TOR       = 30
    TOR_ENTRY = 31
    TOR_EXIT  = 32


# TODO: make this a flag if possible. pretty sure it is.
CFG = _IntEnum('CFG', ['RESTORE', 'DEL', 'ADD', 'ADD_DEL'], start=0)

_TLD_LIST = [
    'NONE', 'ru', 'cn', 'xxx', 'porn', 'adult', 'ads', 'click', 'download',
    'top', 'loan', 'work', 'men', 'cf', 'gq', 'ml', 'ga'
]
TLD_CAT = _IntEnum('TLS_CAT', _TLD_LIST, start=0)

_GEO_LIST = [
    'NONE', 'RFC1918',
    'AFGHANISTAN', 'ALBANIA', 'ALGERIA', 'AMERICAN_SAMOA', 'ANDORRA', 'ANGOLA', 'ANGUILLA', 'ANTARCTICA',
    'ANTIGUA_AND_BARBUDA', 'ARGENTINA', 'ARMENIA', 'ARUBA', 'AUSTRALIA', 'AUSTRIA', 'AZERBAIJAN', 'BAHAMAS', 'BAHRAIN',
    'BANGLADESH', 'BARBADOS', 'BELARUS', 'BELGIUM', 'BELIZE', 'BENIN', 'BERMUDA', 'BHUTAN', 'BOLIVIA',
    'BOSNIA_AND_HERZEGOVINA', 'BOTSWANA', 'BOUVET_ISLAND', 'BRAZIL', 'BRITISH_INDIAN_OCEAN_TERRITORY',
    'BRITISH_VIRGIN_ISLANDS', 'BULGARIA', 'BURKINA_FASO', 'BURUNDI', 'CAMBODIA', 'CAMEROON', 'CANADA',
    'CAYMAN_ISLANDS', 'CENTRAL_AFRICAN_REPUBLIC', 'CHAD', 'CHILE', 'CHINA', 'CHRISTMAS_ISLAND', 'COCOS_ISLANDS',
    'COLOMBIA', 'COMOROS', 'COOK_ISLANDS', 'COSTA_RICA', 'CROATIA', 'CUBA', 'CYPRUS', 'DENMARK', 'DJIBOUTI',
    'DOMINICA', 'DOMINICAN_REPUBLIC', 'ECUADOR', 'EGYPT', 'EL_SALVADOR', 'EQUATORIAL_GUINEA', 'ERITREA', 'ESTONIA',
    'ETHIOPIA', 'FALKLAND_ISLANDS', 'FAROE_ISLANDS', 'FIJI', 'FINLAND', 'FRANCE', 'FRENCH_GUIANA', 'FRENCH_POLYNESIA',
    'FRENCH_SOUTHERN_TERRITORIES', 'GABON', 'GAMBIA', 'GEORGIA', 'GERMANY', 'GHANA', 'GIBRALTAR', 'GREECE',
    'GREENLAND', 'GRENADA', 'GUADELOUPE', 'GUAM', 'GUATEMALA', 'GUERNSEY', 'GUINEA', 'GUYANA', 'HAITI', 'HONDURAS',
    'HONG_KONG', 'HUNGARY', 'ICELAND', 'INDIA', 'INDONESIA', 'IRAN', 'IRAQ', 'IRELAND', 'ISLE_OF_MAN', 'ISRAEL',
    'ITALY', 'JAMAICA', 'JAPAN', 'JERSEY', 'JORDAN', 'KAZAKHSTAN', 'KENYA', 'KIRIBATI', 'KUWAIT', 'KYRGYZSTAN', 'LAOS',
    'LATVIA', 'LEBANON', 'LESOTHO', 'LIBERIA', 'LIBYA', 'LIECHTENSTEIN', 'LITHUANIA', 'LUXEMBOURG', 'MACAO',
    'MADAGASCAR', 'MALAWI', 'MALAYSIA', 'MALDIVES', 'MALI', 'MALTA', 'MARSHALL_ISLANDS', 'MARTINIQUE', 'MAURITANIA',
    'MAURITIUS', 'MAYOTTE', 'MEXICO', 'MOLDOVA', 'MONGOLIA', 'MONTENEGRO', 'MONTSERRAT', 'MOROCCO', 'MOZAMBIQUE',
    'MYANMAR', 'NAMIBIA', 'NAURU', 'NEPAL', 'NETHERLANDS', 'NEW_CALEDONIA', 'NEW_ZEALAND', 'NICARAGUA', 'NIGER',
    'NIGERIA', 'NIUE', 'NORFOLK_ISLAND', 'NORTH_KOREA', 'NORTHERN_MARIANA_ISLANDS', 'NORWAY', 'OMAN', 'PAKISTAN',
    'PALAU', 'PALESTINE', 'PANAMA', 'PAPUA_NEW_GUINEA', 'PARAGUAY', 'PERU', 'PHILIPPINES', 'POLAND', 'PORTUGAL',
    'PUERTO_RICO', 'QATAR', 'REUNION', 'ROMANIA', 'RUSSIAN_FEDERATION', 'RWANDA', 'SAINT_HELENA', 'SAINT_LUCIA',
    'SAINT_MARTIN', 'SAINT_PIERRE_AND_MIQUELON', 'SAMOA', 'SAN_MARINO', 'SAUDI_ARABIA', 'SENEGAL', 'SERBIA',
    'SEYCHELLES', 'SIERRA_LEONE', 'SINGAPORE', 'SLOVAKIA', 'SLOVENIA', 'SOLOMON_ISLANDS', 'SOMALIA', 'SOUTH_AFRICA',
    'SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS', 'SOUTH_KOREA', 'SOUTH_SUDAN', 'SPAIN', 'SRI_LANKA', 'SUDAN',
    'SURINAME', 'SWEDEN', 'SWITZERLAND', 'SYRIA', 'TAIWAN', 'TAJIKISTAN', 'TANZANIA', 'THAILAND', 'TOGO', 'TOKELAU',
    'TONGA', 'TRINIDAD_AND_TOBAGO', 'TUNISIA', 'TURKEY', 'TURKMENISTAN', 'TURKS_AND_CAICOS_ISLANDS', 'TUVALU',
    'UGANDA', 'UKRAINE', 'UNITED_ARAB_EMIRATES', 'UNITED_KINGDOM', 'UNITED_STATES', 'URUGUAY',
    'US_MINOR_OUTLYING_ISLANDS', 'UZBEKISTAN', 'VANUATU', 'VENEZUELA', 'VIETNAM', 'WESTERN_SAHARA', 'YEMEN',
    'ZAMBIA', 'ZIMBABWE'
]
GEO = _IntEnum('GEO', _GEO_LIST, start=0)
