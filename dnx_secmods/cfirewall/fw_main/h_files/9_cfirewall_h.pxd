cdef struct srange:
  uint_fast8_t  start
  uint_fast8_t  end

cdef enum:
    NONE      = 0
    IP_PROXY  = 1
    DNS_PROXY = 2
    IPS_IDS   = 3

cdef enum:
    DROP   = 0
    ACCEPT = 1
    REJECT = 2

cdef enum:
    OUTBOUND = 1
    INBOUND  = 2

cdef enum:
    WAN_IN = 10

cdef enum:
    SYSTEM_RULES
    BEFORE_RULES
    MAIN_RULES
    AFTER_RULES

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
    size_t          len
    uint_fast8_t    objects[FIELD_MAX_ZONES]

# STANDARD NETWORK OBJECT (HOST, NETWORK, RANGE, GEO)
cdef struct Network:
    uint_fast8_t    type
    uint_fast32_t   netid
    uint_fast32_t   netmask

# MAIN NETWORK ARRAY
cdef struct NetworkArray:
    size_t          len
    Network         objects[FIELD_MAX_NETWORKS]

# STANDARD SERVICE OBJECT (SOLO or RANGE)
cdef struct Service:
    uint_fast16_t   protocol
    uint_fast16_t   start_port
    uint_fast16_t   end_port

# SERVICE OBJECT LIST (tcp/80:tcp/443)
cdef struct ServiceList:
    size_t          len
    Service         objects[FIELD_MAX_SVC_LIST_MEMBERS]

# UNION OF EACH SERVICE OBJECT TYPE
cdef union Service_U:
    Service         object
    ServiceList     list

cdef struct ServiceObject:
    uint_fast8_t    type
    Service_U    service

# MAIN SERVICE ARRAY
cdef struct ServiceArray:
    size_t          len
    ServiceObject   objects[FIELD_MAX_SERVICES]

# COMPLETE RULE STRUCT - NO POINTERS
cdef struct FWrule:
    bint            enabled

    # SOURCE
    ZoneArray       s_zones
    NetworkArray    s_networks
    ServiceArray    s_services

    # DESTINATION
    ZoneArray       d_zones
    NetworkArray    d_networks
    ServiceArray    d_services

    # PROFILES
    uint_fast8_t    action
    uint_fast8_t    log
    uint_fast8_t    sec_profiles[SECURITY_PROFILE_COUNT]
        # ip_proxy - 0 off, > 1 profile number
        # dns_proxy - 0 off, > 1 profile number
        # ips_ids - 0 off, 1 on

cdef struct HWinfo:
    uint8_t     in_zone
    uint8_t     out_zone
    char*       mac_addr
    double      timestamp

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

cdef struct Protohdr:
    uint16_t    s_port
    uint16_t    d_port

cdef struct InspectionResults:
    uint16_t    fw_section
    uint32_t    action
    uint32_t    mark

cdef struct cfdata:
    uint32_t queue


cdef class CFirewall:
    cdef:
        char*   sock_path
        int     api_fd

        cfdata  cfd

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil
    cpdef int update_zones(s, PyArray zone_map) with gil
    cpdef int update_ruleset(s, size_t ruleset, list rulelist) with gil
    cdef  int remove_attacker(s, uint32_t host_ip)
