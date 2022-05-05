cdef extern from "inet_tools.h" nogil:
    uint32_t intf_masquerade(uint32_t idx)

cdef extern from "std_tools.h" nogil:
    void nullset(void **data, uintf16_t dlen)

cdef extern from "cfirewall.h" nogil:
    enum: SECURITY_PROFILE_COUNT

    struct FWrule:
        bint        enabled
        ZoneArray   s_zones
        NetArray    s_networks
        SvcArray    s_services
        ZoneArray   d_zones
        NetArray    d_networks
        SvcArray    d_services
        uintf8_t    action
        uintf8_t    log
        uintf8_t    sec_profiles[SECURITY_PROFILE_COUNT]

    struct NATrule:
        bint        enabled
        ZoneArray   s_zones
        NetArray    s_networks
        SvcArray    s_services
        ZoneArray   d_zones
        NetArray    d_networks
        SvcArray    d_services
        uintf8_t    action
        uintf8_t    log

        uint32_t    saddr
        uint16_t    sport
        uint32_t    daddr
        uint16_t    dport


cdef struct cfdata:
    uint32_t    queue
    mnl_cb_t    queue_cb


cdef class CFirewall:
    cdef:
        char*   sock_path
        int     api_fd

        cfdata  cfd

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil
    cpdef int update_zones(s, PyArray zone_map) with gil
    cpdef int update_ruleset(s, size_t ruleset, list rulelist) with gil
#    cdef  int remove_attacker(s, uint32_t host_ip)
