cdef extern from "inet_tools.h" nogil:
    uint32_t intf_masquerade (unsigned int idx)

cdef extern from "std_tools.h" nogil:
    void nullset(void **data, uintf16_t dlen)

cdef struct srange:
  uintf8_t  start
  uintf8_t  end

cdef enum:
    NONE      = 0
    IP_PROXY  = 1
    DNS_PROXY = 2
    IPS_IDS   = 3

cdef enum:
    DNX_DROP   = 0
    DNX_ACCEPT = 1
    DNX_REJECT = 2

    DNX_NO_NAT   = 4
    DNX_MASQ     = 8
    DNX_SRC_NAT  = 16
    DNX_DST_NAT  = 32
    DNX_FULL_NAT = 64

    DNX_NAT_FLAGS = DNX_SRC_NAT | DNX_DST_NAT | DNX_FULL_NAT

cdef enum:
    OUTBOUND = 1
    INBOUND  = 2

cdef enum:
    WAN_IN = 10

cdef enum:
    FW_SYSTEM_RULES
    FW_BEFORE_RULES
    FW_MAIN_RULES
    FW_AFTER_RULES
    NAT_PRE_RULES
    NAT_POST_RULES

# used for dynamic allocation of the array containing security profile settings
# ip proxy, ips_ids, dns_proxy
DEF SECURITY_PROFILE_COUNT = 3

# PER FIELD AND RULE LIMITS
DEF FIELD_MAX_ZONES = 16
DEF FIELD_MAX_NETWORKS = 8
DEF FIELD_MAX_SERVICES = 8
DEF FIELD_MAX_SVC_LIST_MEMBERS = 8

# STANDARD ZONE ARRAY [10, 11]
cdef struct ZoneArray:
    uintf8_t    len
    uintf8_t    objects[FIELD_MAX_ZONES]

# STANDARD NETWORK OBJECT (HOST, NETWORK, RANGE, GEO)
cdef struct NetObject:
    uintf8_t    type
    uintf32_t   netid
    uintf32_t   netmask

# MAIN NETWORK ARRAY
cdef struct NetArray:
    uintf8_t    len
    NetObject   objects[FIELD_MAX_NETWORKS]

cdef struct S1: # ICMP
    uint8_t     type
    uint8_t     code

# STANDARD SERVICE OBJECT (SOLO or RANGE)
cdef struct S2:
    uintf16_t   protocol
    uintf16_t   start_port
    uintf16_t   end_port

# SERVICE OBJECT LIST (tcp/80:tcp/443)
cdef struct S3:
    uintf8_t    len
    Service     services[FIELD_MAX_SVC_LIST_MEMBERS]

# UNION OF EACH SERVICE OBJECT TYPE
cdef union Svc_U:
    S1          s1  # ICMP
    S2          s2  # SOLO or RANGE
    S3          s3  # LIST

cdef struct SvcObject:
    uintf8_t    type
    Svc_U       service

# MAIN SERVICE ARRAY
cdef struct SvcArray:
    uintf8_t    len
    SvcObject   objects[FIELD_MAX_SERVICES]

# COMPLETE RULE STRUCT - NO POINTERS
cdef struct FWrule:
    bint        enabled

    # SOURCE
    ZoneArray   s_zones
    NetArray    s_networks
    SvcArray    s_services

    # DESTINATION
    ZoneArray   d_zones
    NetArray    d_networks
    SvcArray    d_services

    # PROFILES
    uintf8_t    action
    uintf8_t    log
    uintf8_t    sec_profiles[SECURITY_PROFILE_COUNT]
        # ip_proxy - 0 off, > 1 profile number
        # dns_proxy - 0 off, > 1 profile number
        # ips_ids - 0 off, 1 on

cdef struct NATrule:
    bint        enabled

    # SOURCE
    ZoneArray   s_zones
    NetArray    s_networks
    SvcArray    s_services

    # DESTINATION
    ZoneArray   d_zones
    NetArray    d_networks
    SvcArray    d_services

    # PROFILES
    uintf8_t    action
    uintf8_t    log

    uint32_t    saddr
    uint16_t    sport
    uint32_t    daddr
    uint16_t    dport

cdef struct HWinfo:
    double      timestamp
    uintf8_t    in_zone
    uintf8_t    out_zone
    char*       mac_addr

cdef struct IPhdr:
    uint8_t     ver_ihl
    uint8_t     tos
    uint16_t    tot_len
    uint16_t    id
    uint16_t    frag_off
    uint8_t     ttl
    uint8_t     protocol
    uint16_t    check
    uint32_t    saddr
    uint32_t    daddr

cdef struct P1: # ICMP
    uint8_t     type
    uint8_t     code

cdef struct P2: # TCP/UDP
    uint16_t    s_port
    uint16_t    d_port

cdef union Protohdr:
    P1         *p1
    P2         *p2

cdef struct cfdata:
    uint32_t    queue

cdef struct dnx_pktb:
    uint8_t    *data
    uint16_t    tlen
    HWinfo      hw
    IPhdr      *iphdr
    uint16_t    iphdr_len # header only
    Protohdr    protohdr
    uint16_t    protohdr_len # header only
    uintf8_t    mangled
    uintf16_t   fw_table
    uintf16_t   rule_num
    uint32_t    action
    uint32_t    mark


cdef class CFirewall:
    cdef:
        char*   sock_path
        int     api_fd

        cfdata  cfd

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil
    cpdef int update_zones(s, PyArray zone_map) with gil
    cpdef int update_ruleset(s, size_t ruleset, list rulelist) with gil
#    cdef  int remove_attacker(s, uint32_t host_ip)
