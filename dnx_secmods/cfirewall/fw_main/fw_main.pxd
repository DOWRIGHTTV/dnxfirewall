#!/usr/bin/env Cython

from cpython cimport array
from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t, uint_fast32_t, int_fast8_t, int_fast16_t, int_fast32_t


ctypedef array.array PyArray

cdef extern from "<errno.h>":
    int     errno

cdef extern from "time.h" nogil:
    ctypedef    long time_t
    time_t      time(time_t*)

    struct timeval:
        time_t  tv_sec
        time_t  tv_usec

cdef extern from "sys/socket.h":
    ssize_t     recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    int         MSG_DONTWAIT

cdef enum:
    EAGAIN = 11           # Try again
    EWOULDBLOCK = EAGAIN
    ENOBUFS = 105         # No buffer space available

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_mutex_t:
        pass

    int pthread_mutex_init(pthread_mutex_t*, void*)
    int pthread_mutex_lock(pthread_mutex_t*)
    int pthread_mutex_trylock(pthread_mutex_t*)
    int pthread_mutex_unlock(pthread_mutex_t*)
    int pthread_mutex_destroy(pthread_mutex_t*)

cdef extern from "netinet/in.h":
    uint32_t ntohl (uint32_t __netlong) nogil
    uint16_t ntohs (uint16_t __netshort) nogil
    uint32_t htonl (uint32_t __hostlong) nogil
    uint16_t htons (uint16_t __hostshort) nogil

# from netinet/in.h:
cdef enum:
    IPPROTO_IP   = 0
    IPPROTO_ICMP = 1
    IPPROTO_TCP  = 6
    IPPROTO_UDP  = 17

cdef extern from "libnfnetlink/linux_nfnetlink.h":
    struct nfgenmsg:
        uint8_t    nfgen_family
        uint8_t    version
        uint16_t   res_id

cdef extern from "libnfnetlink/libnfnetlink.h":
    struct nfnl_handle:
        pass

    unsigned int nfnl_rcvbufsiz(nfnl_handle *h, unsigned int size)

cdef extern from "libnetfilter_queue/linux_nfnetlink_queue.h":
    enum nfqnl_config_mode:
        NFQNL_COPY_NONE
        NFQNL_COPY_META
        NFQNL_COPY_PACKET

    struct nfqnl_msg_packet_hdr:
        uint32_t   packet_id
        uint16_t   hw_protocol
        uint8_t    hook

cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
    struct nfq_handle:
        pass

    struct nfq_q_handle:
        pass

    struct nfq_data:
        pass

    struct nfqnl_msg_packet_hw:
        uint8_t    hw_addr[8]

    ctypedef int *nfq_callback(nfq_q_handle *gh, nfgenmsg *nfmsg, nfq_data *nfad, void *data)

    nfq_handle *nfq_open()

    int nfq_fd(nfq_handle *h)
    int nfq_close(nfq_handle *h)

    nfnl_handle *nfq_nfnlh(nfq_handle *h)
    nfq_q_handle *nfq_create_queue(nfq_handle *h, uint16_t num, nfq_callback *cb, void *data)

    int nfq_destroy_queue(nfq_q_handle *qh)
    int nfq_set_mode(nfq_q_handle *qh, uint8_t mode, unsigned int len)
    int nfq_set_queue_maxlen(nfq_q_handle *qh, uint32_t queuelen)
    int nfq_handle_packet(nfq_handle *h, char *buf, int len) nogil

    nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(nfq_data *nfad) nogil
    nfqnl_msg_packet_hw  *nfq_get_packet_hw(nfq_data *nfad) nogil

    int nfq_get_payload(nfq_data *nfad, unsigned char **data) nogil
    int nfq_get_timestamp(nfq_data *nfad, timeval *tv) nogil
    int nfq_get_nfmark (nfq_data *nfad) nogil
    uint8_t nfq_get_indev(nfq_data *nfad) nogil
    uint8_t nfq_get_outdev(nfq_data *nfad)

    int nfq_set_verdict(nfq_q_handle *qh, uint32_t id, uint32_t verdict, uint32_t data_len, uint8_t *buf) nogil
    int nfq_set_verdict2(
            nfq_q_handle *qh, uint32_t id, uint32_t verdict, uint32_t mark, uint32_t datalen, uint8_t *buf) nogil

# mirrored defines from linux/netfilter.h
cdef enum:
    NF_DROP
    NF_ACCEPT
    NF_STOLEN
    NF_QUEUE
    NF_REPEAT
    NF_STOP
    NF_MAX_VERDICT = NF_STOP

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
    uint8_t    in_zone
    uint8_t    out_zone
    char*      mac_addr
    double     timestamp

cdef struct IPhdr:
    uint8_t    ver_ihl
    uint8_t    tos
    uint16_t   tot_len
    uint16_t   id
    uint16_t   frag_off
    uint8_t    ttl
    uint8_t    protocol
    uint16_t   check
    uint32_t   saddr
    uint32_t   daddr

cdef struct Protohdr:
    uint16_t   s_port
    uint16_t   d_port

cdef struct InspectionResults:
    uint16_t   fw_section
    uint32_t   action
    uint32_t   mark

cdef class CFirewall:
    cdef:
        nfq_handle   *h
        nfq_q_handle *qh

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil
    cpdef int update_zones(s, PyArray zone_map) with gil
    cpdef int update_ruleset(s, size_t ruleset, list rulelist) with gil
    cdef  int remove_attacker(s, uint32_t host_ip)
