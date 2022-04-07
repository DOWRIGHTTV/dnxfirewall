#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t

cdef extern from "<errno.h>":
    int errno

    # dummy defines from asm-generic/errno.h:
    cdef enum:
        ENOBUFS = 105  # No buffer space available

cdef extern from "sys/socket.h":
    ssize_t recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    int MSG_DONTWAIT

cdef extern from "time.h" nogil:
    ctypedef long time_t
    time_t time(time_t*)

    struct timeval:
        time_t tv_sec
        time_t tv_usec

    struct timezone:
        pass

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_mutex_t:
        pass

    cdef int pthread_mutex_init(pthread_mutex_t*, void*)
    cdef int pthread_mutex_lock(pthread_mutex_t*)
    cdef int pthread_mutex_trylock(pthread_mutex_t*)
    cdef int pthread_mutex_unlock(pthread_mutex_t*)
    cdef int pthread_mutex_destroy(pthread_mutex_t*)

cdef extern from "netinet/in.h":
    uint32_t ntohl (uint32_t __netlong) nogil
    uint16_t ntohs (uint16_t __netshort) nogil
    uint32_t htonl (uint32_t __hostlong) nogil
    uint16_t htons (uint16_t __hostshort) nogil

cdef extern from "libnfnetlink/linux_nfnetlink.h":
    struct nfgenmsg:
        uint8_t  nfgen_family
        uint8_t  version
        uint16_t res_id

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
        uint32_t packet_id
        uint16_t hw_protocol
        uint8_t  hook

cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
    struct nfq_handle:
        # 	struct nfnl_handle *nfnlh;
        # 	struct nfnl_subsys_handle *nfnlssh;
        # 	struct nfq_q_handle *qh_list;
        pass

    struct nfq_q_handle:
        # 	struct nfq_q_handle *next;
        # 	struct nfq_handle *h;
        uint16_t id;
        #
        # 	nfq_callback *cb;
        # 	void *data;
        pass

    struct nfq_data:
        # struct nfattr **data;
        pass

    struct nfqnl_msg_packet_hw:
        uint8_t hw_addr[8]

    ctypedef int *nfq_callback(nfq_q_handle *gh, nfgenmsg *nfmsg, nfq_data *nfad, void *data)

    nfq_handle *nfq_open()

    int nfq_fd(nfq_handle *h) nogil
    int nfq_close(nfq_handle *h)

    nfnl_handle *nfq_nfnlh(nfq_handle *h)
    nfq_q_handle *nfq_create_queue(nfq_handle *h, uint16_t num, nfq_callback *cb, void *data)

    int nfq_destroy_queue(nfq_q_handle *qh)
    int nfq_set_mode(nfq_q_handle *qh, uint8_t mode, unsigned int len)
    int nfq_set_queue_maxlen(nfq_q_handle *qh, uint32_t queuelen)
    int nfq_handle_packet(nfq_handle *h, char *buf, int len) nogil

    nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(nfq_data *nfad) nogil
    nfqnl_msg_packet_hw *nfq_get_packet_hw(nfq_data *nfad) nogil

    int nfq_get_payload(nfq_data *nfad, unsigned char ** data) nogil
    int nfq_get_timestamp(nfq_data *nfad, timeval *tv) nogil
    int nfq_get_nfmark(nfq_data *nfad) nogil
    uint8_t nfq_get_indev(nfq_data *nfad) nogil
    uint8_t nfq_get_outdev(nfq_data *nfad) nogil

    int nfq_set_verdict(nfq_q_handle *qh, uint32_t id, uint32_t verdict, uint32_t data_len, uint8_t *buf) nogil
    int nfq_set_verdict2(
            nfq_q_handle *qh, uint32_t id, uint32_t verdict, uint32_t mark, uint32_t datalen, uint8_t *buf) nogil


# Dummy defines from linux/netfilter.h
cdef enum:
    NF_DROP
    NF_ACCEPT
    NF_STOLEN
    NF_QUEUE
    NF_REPEAT
    NF_STOP
    NF_MAX_VERDICT = NF_STOP

# cython define
cdef struct IPhdr:
    uint8_t  ver_ihl
    uint8_t  tos
    uint16_t tot_len
    uint16_t id
    uint16_t frag_off
    uint8_t  ttl
    uint8_t  protocol
    uint16_t check
    uint32_t saddr
    uint32_t daddr

# cython define
cdef struct TCPhdr:
    uint16_t th_sport
    uint16_t th_dport
    uint32_t th_seq
    uint32_t th_ack

    uint8_t  th_off

    uint8_t  th_flags
    uint16_t th_win
    uint16_t th_sum
    uint16_t th_urp

# cython define
cdef struct UDPhdr:
    uint16_t uh_sport
    uint16_t uh_dport
    uint16_t uh_ulen
    uint16_t uh_sum

cdef struct ICMPhdr:
    uint8_t type
    uint8_t code

# from netinet/in.h:
cdef enum:
    IPPROTO_IP   = 0       # Dummy protocol for TCP.
    IPPROTO_ICMP = 1       # Internet Control Message Protocol.
    IPPROTO_TCP  = 6       # Transmission Control Protocol.
    IPPROTO_UDP  = 17      # User Datagram Protocol.

ctypedef char pkt_buf
ctypedef unsigned char upkt_buf

cdef struct PacketData:
    nfq_q_handle *nfq_qh
    nfq_data     *nfq_d
    uint32_t      id
    uint32_t      mark
    time_t        timestamp
    uint32_t      len
    upkt_buf     *data
    uint_fast8_t  iphdr_len


cdef class CPacket:
    cdef:
        PacketData *dnx_nfqhdr

        bint   has_verdict
        size_t protohdr_len

    cpdef void update_mark(self, uint32_t mark)
    cpdef void accept(self)
    cpdef void drop(self)
    cpdef void forward(self, uint16_t queue_num)
    cpdef void repeat(self)
    cdef void set_nfqhdr(s, PacketData *dnx_nfqhdr)
    cdef  void _set_verdict(self, uint32_t verdict) nogil

cdef class NetfilterQueue:
    cdef:
        nfq_handle   *nfq_h   # NFQueue library
        nfq_q_handle *nfq_qh  # Specific processing queue
