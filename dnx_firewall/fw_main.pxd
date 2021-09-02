cdef extern from "sys/types.h":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef extern from "<errno.h>":
    int errno

cdef extern from "time.h" nogil:
    ctypedef long time_t
    time_t time(time_t*)

    struct timeval:
        time_t tv_sec
        time_t tv_usec

cdef extern from "sys/socket.h":
    ssize_t recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    int MSG_DONTWAIT

cdef enum:
    EAGAIN = 11           # Try again
    EWOULDBLOCK = EAGAIN
    ENOBUFS = 105         # No buffer space available

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
        u_int8_t nfgen_family
        u_int8_t version
        u_int16_t res_id

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
        u_int32_t packet_id
        u_int16_t hw_protocol
        u_int8_t hook

cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
    struct nfq_handle:
        pass

    struct nfq_q_handle:
        pass

    struct nfq_data:
        pass

    struct nfqnl_msg_packet_hw:
        u_int8_t hw_addr[8]

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

# Dummy defines from linux/netfilter.h
cdef enum:
    NF_DROP
    NF_ACCEPT
    NF_STOLEN
    NF_QUEUE
    NF_REPEAT
    NF_STOP
    NF_MAX_VERDICT = NF_STOP

# MARK PROTOCOL
# 4 bits per, right to left, any not specified is currently undefined
# action is being passed because still want to gather geolocation data on even implicit denies.
# these would not be logged as events, but part of country activity metric.
# ips_ids profile | ip proxy profile| action | module_identifier (corresponds to queue num)

cdef enum:
    NONE     = 0
    IP_PROXY = 1
    IPS_IDS  = 2

    DROP   = 0
    ACCEPT = 1

# cdef class _FWrule:
#     cdef readonly:
#         u_int8_t protocol
#         u_int8_t s_zone
#         u_int32_t s_net_id
#         u_int32_t s_net_mask
#         u_int16_t s_port_start
#         u_int16_t s_port_end

#         #desitnation
#         u_int8_t d_zone
#         u_int32_t d_net_id
#         u_int32_t d_net_mask
#         u_int16_t d_port_start
#         u_int16_t d_port_end

#         # profiles - forward traffic only
#         u_int8_t action # 0 drop, 1 accept (if profile set, and action is allow, action will be changed to forward)
#         u_int8_t ip_proxy # 0 off, > 1 profile number
#         u_int8_t ips_ids

#     cdef void modify(self)

cdef struct FWrule:
    # source
    u_int8_t protocol
    u_int8_t s_zone
    u_int32_t s_net_id
    u_int32_t s_net_mask
    u_int16_t s_port_start
    u_int16_t s_port_end

    #desitnation
    u_int8_t d_zone
    u_int32_t d_net_id
    u_int32_t d_net_mask
    u_int16_t d_port_start
    u_int16_t d_port_end

    # profiles - forward traffic only
    u_int8_t action # 0 drop, 1 accept (if profile set, and action is allow, action will be changed to forward)
    u_int8_t ip_proxy # 0 off, > 1 profile number
    u_int8_t ips_ids # 0 off, 1 on

cdef struct hw_info:
    u_int8_t in_intf
    u_int8_t out_intf
    char* mac_addr
    double timestamp

# cython define
cdef struct iphdr:
    u_int8_t  ver_ihl
    u_int8_t  tos
    u_int16_t tot_len
    u_int16_t id
    u_int16_t frag_off
    u_int8_t  ttl
    u_int8_t  protocol
    u_int16_t check
    u_int32_t saddr
    u_int32_t daddr

cdef struct protohdr:
    u_int16_t s_port
    u_int16_t d_port

DEF FW_RULE_COUNT = 1000

cdef class CFirewall:
    cdef FWrule *ruleset[FW_RULE_COUNT]

    cdef nfq_handle *h # Handle to NFQueue library
    cdef nfq_q_handle *qh # A handle to the queue

    cdef void _run(self) nogil
