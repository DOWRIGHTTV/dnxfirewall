#!/usr/bin/env Cython

from cpython cimport array
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t, uint_fast32_t, int_fast8_t, int_fast16_t, int_fast32_t
from libc.stdio cimport FILE

from posix.types cimport pid_t

# LIBMNL && LIBNETFILTER_QUEUE SOURCE FILES
# https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2
# https://netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2

# DNXFIREWALL TYPEDEFS
ctypedef array.array    PyArray
ctypedef uint_fast8_t   uintf8_t
ctypedef uint_fast16_t  uintf16_t
ctypedef uint_fast32_t  uintf32_t

# NOTE: might not need anymore... confirm
cdef extern from "<stdbool.h>":
    pass
    # ctypedef int bool
    # ctypedef int true
    # ctypedef int false

cdef extern from "<time.h>" nogil:
    ctypedef long   time_t

    time_t      time(time_t*)
    struct timeval:
        time_t  tv_sec
        time_t  tv_usec

cdef extern from "<sys/socket.h>":
    ctypedef unsigned int   socklen_t

    ssize_t     recv(int __fd, void *__buf, size_t __n, int __flags) nogil

    enum: AF_INET

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_mutex_t:
        pass

    int pthread_mutex_lock(pthread_mutex_t*)
    int pthread_mutex_unlock(pthread_mutex_t*)

cdef extern from "linux/netlink.h" nogil:
    enum: NETLINK_NETFILTER             # netfilter subsystem

    struct nlmsghdr:
        pass

    enum: NETLINK_NO_ENOBUFS

    #  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    # |        Header       | Pad |     Payload       | Pad |
    # |   (struct nlattr)   | ing |                   | ing |
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    #  <-------------- nlattr->nla_len -------------->
    struct nlattr:
        uint16_t nla_len
        uint16_t nla_type

cdef extern from "libnetfilter_queue/linux_nfnetlink_queue.h":
    enum nfqnl_config_mode:
        NFQNL_COPY_NONE
        NFQNL_COPY_META
        NFQNL_COPY_PACKET

    struct nfqnl_msg_packet_hdr:
        uint32_t packet_id
        uint16_t hw_protocol
        uint8_t  hook

cdef extern from "libmnl/libmnl.h" nogil:
    #
    # Netlink socket API
    #
    enum:
        MNL_SOCKET_AUTOPID
        MNL_SOCKET_BUFFER_SIZE

    struct mnl_socket:
        pass

    mnl_socket *mnl_socket_open(int type)
    mnl_socket *mnl_socket_fdopen(int fd)
    int mnl_socket_bind(mnl_socket *nl, unsigned int groups, pid_t pid)
    int mnl_socket_close(mnl_socket *nl)
    int mnl_socket_get_fd(const mnl_socket *nl)
    unsigned int mnl_socket_get_portid(const mnl_socket *nl)
    ssize_t mnl_socket_sendto(const mnl_socket *nl, const void *req, size_t siz)
    ssize_t mnl_socket_recvfrom(const mnl_socket *nl, void *buf, size_t siz)
    int mnl_socket_setsockopt(const mnl_socket *nl, int type, void *buf, socklen_t len)
    int mnl_socket_getsockopt(const mnl_socket *nl, int type, void *buf, socklen_t *len)

    # TLV attribute getters */
    uint16_t mnl_attr_get_type(const nlattr *attr)
    uint16_t mnl_attr_get_len(const nlattr *attr)
    uint16_t mnl_attr_get_payload_len(const nlattr *attr)
    nfqnl_msg_packet_hdr *mnl_attr_get_payload(const nlattr *attr)
    uint8_t mnl_attr_get_u8(const nlattr *attr)
    uint16_t mnl_attr_get_u16(const nlattr *attr)
    uint32_t mnl_attr_get_u32(const nlattr *attr)
    uint64_t mnl_attr_get_u64(const nlattr *attr)
    const char *mnl_attr_get_str(const nlattr *attr)

    # TLV attribute putters */
    void mnl_attr_put(nlmsghdr *nlh, uint16_t type, size_t len, const void *data)
    void mnl_attr_put_u8(nlmsghdr *nlh, uint16_t type, uint8_t data)
    void mnl_attr_put_u16(nlmsghdr *nlh, uint16_t type, uint16_t data)
    void mnl_attr_put_u32(nlmsghdr *nlh, uint16_t type, uint32_t data)
    void mnl_attr_put_u64(nlmsghdr *nlh, uint16_t type, uint64_t data)
    void mnl_attr_put_str(nlmsghdr *nlh, uint16_t type, const char *data)
    void mnl_attr_put_strz(nlmsghdr *nlh, uint16_t type, const char *data)

    # TLV callback-based attribute parsers
    ctypedef int (*mnl_attr_cb_t)(const nlattr *attr, void *data)

    ctypedef int (*mnl_cb_t)(const nlmsghdr *nlh, void *data)

# New API based on libmnl
cdef extern from "libnetfilter_queue/libnetfilter_queue.h" nogil:
    # CMD HELPERS
    void nfq_nlmsg_cfg_put_cmd(nlmsghdr *nlh, uint16_t pf, uint8_t cmd)
    void nfq_nlmsg_cfg_put_params(nlmsghdr *nlh, uint8_t mode, int range)
    void nfq_nlmsg_cfg_put_qmaxlen(nlmsghdr *nlh, uint32_t qmaxlen)

    # VERDICT HELPERS
    void nfq_nlmsg_verdict_put(nlmsghdr *nlh, int id, int verdict)
    void nfq_nlmsg_verdict_put_mark(nlmsghdr *nlh, uint32_t mark)
    void nfq_nlmsg_verdict_put_pkt(nlmsghdr *nlh, const void *pkt, uint32_t plen)

    # NETLINK MSG HELPERS
    int nfq_nlmsg_parse(const nlmsghdr *nlh, nlattr **attr)
    nlmsghdr *nfq_nlmsg_put(char *buf, int type, uint32_t queue_num)


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
