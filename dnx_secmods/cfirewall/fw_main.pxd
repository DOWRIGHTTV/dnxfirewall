#!/usr/bin/env Cython

from cpython cimport array
import array

ctypedef array.array PyArray

cdef extern from "sys/types.h":
    ctypedef unsigned char      u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int       u_int32_t

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

    cdef int pthread_mutex_init(pthread_mutex_t *, void *)
    cdef int pthread_mutex_lock(pthread_mutex_t *)
    cdef int pthread_mutex_trylock(pthread_mutex_t *)
    cdef int pthread_mutex_unlock(pthread_mutex_t *)
    cdef int pthread_mutex_destroy(pthread_mutex_t *)

cdef extern from "netinet/in.h":
    u_int32_t ntohl (u_int32_t __netlong) nogil
    u_int16_t ntohs (u_int16_t __netshort) nogil
    u_int32_t htonl (u_int32_t __hostlong) nogil
    u_int16_t htons (u_int16_t __hostshort) nogil

# from netinet/in.h:
cdef enum:
    IPPROTO_IP   = 0
    IPPROTO_ICMP = 1
    IPPROTO_TCP  = 6
    IPPROTO_UDP  = 17

cdef extern from "libnfnetlink/linux_nfnetlink.h":
    struct nfgenmsg:
        u_int8_t    nfgen_family
        u_int8_t    version
        u_int16_t   res_id

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
        u_int32_t   packet_id
        u_int16_t   hw_protocol
        u_int8_t    hook

cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
    struct nfq_handle:
        pass

    struct nfq_q_handle:
        pass

    struct nfq_data:
        pass

    struct nfqnl_msg_packet_hw:
        u_int8_t    hw_addr[8]

    nfq_handle *nfq_open()
    int nfq_close(nfq_handle *h)
    ctypedef int *nfq_callback(nfq_q_handle *gh, nfgenmsg *nfmsg, nfq_data *nfad, void *data)
    nfq_q_handle *nfq_create_queue(nfq_handle *h, u_int16_t num, nfq_callback *cb, void *data)
    int nfq_destroy_queue(nfq_q_handle *qh)
    int nfq_handle_packet(nfq_handle *h, char *buf, int len) nogil
    int nfq_set_mode(nfq_q_handle *qh, u_int8_t mode, unsigned int len)
    q_set_queue_maxlen(nfq_q_handle *qh, u_int32_t queuelen)
    int nfq_set_verdict(nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t data_len, unsigned char *buf) nogil
    int nfq_set_verdict2(nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark,
        u_int32_t datalen, unsigned char *buf) nogil

    int nfq_set_queue_maxlen(nfq_q_handle *qh, u_int32_t queuelen)
    int nfq_fd(nfq_handle *h) nogil
    nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(nfq_data *nfad) nogil
    int nfq_get_payload(nfq_data *nfad, unsigned char **data) nogil
    int nfq_get_timestamp(nfq_data *nfad, timeval *tv) nogil
    nfqnl_msg_packet_hw *nfq_get_packet_hw(nfq_data *nfad) nogil
    int nfq_get_nfmark (nfq_data *nfad) nogil
    u_int8_t nfq_get_indev(nfq_data *nfad) nogil
    u_int8_t nfq_get_outdev(nfq_data *nfad) nogil
    nfnl_handle *nfq_nfnlh(nfq_handle *h)

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
    NONE     = 0
    IP_PROXY = 1
    IPS_IDS  = 2

    DROP   = 0
    ACCEPT = 1
    REJECT = 2

    OUTBOUND = 1
    INBOUND  = 2

    WAN_IN = 10

cdef enum:
    SYSTEM_RULES
    BEFORE_RULES
    MAIN_RULES
    AFTER_RULES

# used for dynamic allocation of array containing security profile settings
# ip proxy, ips_ids, dns_proxy
cdef u_int8_t SECURITY_PROFILE_COUNT = 3
DEF MAX_ZONES = 16
DEF MAX_OBJECTS = 100

cdef struct ZoneArray:
    size_t      len
    u_int8_t    objects[MAX_OBJECTS]

cdef struct NetworkObj:
    long        netid # must be signed for geo marker (-1)
    u_int32_t   netmask

cdef struct NetworkArray:
    size_t      len
    NetworkObj  objects[MAX_OBJECTS]

cdef struct ServiceObj:
    u_int16_t   protocol
    u_int16_t   start_port
    u_int16_t   end_port

cdef struct ServiceArray:
    size_t      len
    ServiceObj objects[MAX_OBJECTS]

cdef struct FWrule:
    bint        enabled

    # SOURCE
    ZoneArray    s_zones
    NetworkArray s_networks
    ServiceArray s_services

    # DESTINATION
    ZoneArray    d_zones
    NetworkArray d_networks
    ServiceArray d_services

    # PROFILES
    u_int8_t     action
    u_int8_t     log
    u_int8_t     sec_profiles[SECURITY_PROFILE_COUNT]
        # ip_proxy - 0 off, > 1 profile number
        # ips_ids - 0 off, 1 on
        # dns_proxy - 0 off, > 1 profile number

cdef struct HWinfo:
    u_int8_t    in_zone
    u_int8_t    out_zone
    char*       mac_addr
    double      timestamp

# cython define
cdef struct IPhdr:
    u_int8_t    ver_ihl
    u_int8_t    tos
    u_int16_t   tot_len
    u_int16_t   id
    u_int16_t   frag_off
    u_int8_t    ttl
    u_int8_t    protocol
    u_int16_t   check
    u_int32_t   saddr
    u_int32_t   daddr

cdef struct Protohdr:
    u_int16_t   s_port
    u_int16_t   d_port

cdef struct InspectionResults:
    u_int16_t   fw_section
    u_int32_t   action
    u_int32_t   mark

cdef class CFirewall:
    cdef:
        nfq_handle   *h
        nfq_q_handle *qh

    cpdef void prepare_geolocation(self, tuple geolocation_trie, long msb, long lsb) with gil
    cpdef int update_zones(self, PyArray zone_map) with gil
    cpdef int update_ruleset(self, size_t ruleset, list rulelist) with gil
    cpdef int remove_blockedlist(self, u_int32_t host_ip)