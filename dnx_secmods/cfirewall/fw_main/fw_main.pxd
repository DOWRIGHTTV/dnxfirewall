#!/usr/bin/env Cython

from cpython cimport array
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t, uint_fast32_t, int_fast8_t, int_fast16_t, int_fast32_t
from libc.stdio cimport FILE

from posix.types cimport pid_t


ctypedef array.array PyArray

cdef extern from "<errno.h>":
    int         errno

cdef extern from "time.h" nogil:
    ctypedef    long time_t
    time_t      time(time_t*)

    struct timeval:
        time_t  tv_sec
        time_t  tv_usec

cdef extern from "<sys/socket.h>":
    ctypedef    unsigned int socklen_t
    ssize_t     recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    int         MSG_DONTWAIT

    enum: AF_INET

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

    enum: IPPROTO_IP
    enum: IPPROTO_ICMP
    enum: IPPROTO_TCP
    enum: IPPROTO_UDP

cdef extern from "netinet/tcp.h":
    struct tcphdr:
        pass

cdef extern from "netinet/udp.h":
    struct udphdr:
        pass

cdef extern from "libnfnetlink/libnfnetlink.h" nogil:
    struct nfnl_handle:
        pass

    unsigned int nfnl_rcvbufsiz(nfnl_handle *h, unsigned int size)

cdef extern from "linux/netlink.h" nogil:
    enum:
        NETLINK_ROUTE                 # Routing/device hook           # Unused number
        NETLINK_USERSOCK              # Reserved for user mode socket protocols
        NETLINK_FIREWALL              # Unused number, formerly ip_queue
        NETLINK_SOCK_DIAG             # socket monitoring
        NETLINK_NFLOG                 # netfilter/iptables ULOG                 # ipsec
        NETLINK_SELINUX               # SELinux event notifications
        NETLINK_CONNECTOR
        NETLINK_NETFILTER             # netfilter subsystem

    struct nlmsghdr:
        uint32_t nlmsg_len              # Length of message including header
        uint16_t nlmsg_type             # Message content
        uint16_t nlmsg_flags            # Additional flags
        uint32_t nlmsg_seq              # Sequence number
        uint32_t nlmsg_pid              # Sending process port ID

    #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
    int NLMSG_ALIGN(int len)

    #define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
    int NLMSG_LENGTH(int len)

    #define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
    int NLMSG_SPACE(int len)

    #define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
    void *NLMSG_DATA(nlmsghdr *nlh)

    # define NLMSG_NEXT(nlh,len) below as inline cdef

    #define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
    #                      (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
    #                      (nlh)->nlmsg_len <= (len))
    bint NLMSG_OK(nlmsghdr *nlh, len)

    #define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
    int NLMSG_PAYLOAD(nlmsghdr *nlh, len)

    struct nlmsgerr:
        int             error
        nlmsghdr        msg

    enum: NETLINK_NO_ENOBUFS

    enum:
        NETLINK_UNCONNECTED
        NETLINK_CONNECTED

    #  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    # |        Header       | Pad |     Payload       | Pad |
    # |   (struct nlattr)   | ing |                   | ing |
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    #  <-------------- nlattr->nla_len -------------->
    struct nlattr:
        uint16_t nla_len
        uint16_t nla_type

    # nla_type (16 bits)
    # +---+---+-------------------------------+
    # | N | O | Attribute Type                |
    # +---+---+-------------------------------+
    # N := Carries nested attributes
    # O := Payload stored in network byte order
    #
    # Note: The N and O flag are mutually exclusive.
    enum:
        NLA_F_NESTED
        NLA_F_NET_BYTEORDER
        NLA_TYPE_MASK
        NLA_ALIGNTO

    #define NLA_ALIGN(len)              (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
    inline int NLA_ALIGN(int len)

    enum: NLA_HDRLEN

#define NLMSG_NEXT(nlh,len)      ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
#                                 (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
cdef inline nlmsghdr *NLMSG_NEXT(nlmsghdr *nlh, int *len) nogil:
    len[0] -= NLMSG_ALIGN(nlh.nlmsg_len)
    return <nlmsghdr*>(<char*>nlh + NLMSG_ALIGN(nlh.nlmsg_len))
cdef extern from "linux/netfilter.h" nogil:
    # responses from hook functions.
    enum:
        NF_DROP
        NF_ACCEPT
        NF_STOLEN
        NF_QUEUE
        NF_REPEAT
        NF_STOP
        NF_MAX_VERDICT

        # we overload the higher bits for encoding auxiliary data such as the queue
        # number or errno values. Not nice, but better than additional function
        # arguments.
        NF_VERDICT_MASK

        # extra verdict flags have mask 0x0000ff00
        NF_VERDICT_FLAG_QUEUE_BYPASS

        # queue number (NF_QUEUE) or errno (NF_DROP)
        NF_VERDICT_QMASK
        NF_VERDICT_QBITS

    #define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)
    int NF_QUEUE_NR(int x)

    #define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)
    int NF_DROP_ERR(int x)

cdef extern from "linux/netfilter_ipv4.h" nogil:
    # IP Hooks
    # After promisc drops, checksum checks.
    enum: NF_IP_PRE_ROUTING #	0
    # If the packet is destined for this box.
    enum: NF_IP_LOCAL_IN #		1
    # If the packet is destined for another interface.
    enum: NF_IP_FORWARD #		2
    # Packets coming from a local process.
    enum: NF_IP_LOCAL_OUT #		3
    # Packets about to hit the wire.
    enum: NF_IP_POST_ROUTING #	4
    enum: NF_IP_NUMHOOKS #		5

    enum nf_ip_hook_priorities:
        NF_IP_PRI_FIRST
        NF_IP_PRI_RAW_BEFORE_DEFRAG = -450
        NF_IP_PRI_CONNTRACK_DEFRAG = -400
        NF_IP_PRI_RAW = -300
        NF_IP_PRI_SELINUX_FIRST = -225
        NF_IP_PRI_CONNTRACK = -200
        NF_IP_PRI_MANGLE = -150
        NF_IP_PRI_NAT_DST = -100
        NF_IP_PRI_FILTER = 0
        NF_IP_PRI_SECURITY = 50
        NF_IP_PRI_NAT_SRC = 100
        NF_IP_PRI_SELINUX_LAST = 225
        NF_IP_PRI_CONNTRACK_HELPER = 300
        NF_IP_PRI_CONNTRACK_CONFIRM
        NF_IP_PRI_LAST

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

cdef extern from "libnetfilter_queue/pktbuff.h" nogil:
    # PRIMARY FUNCTIONS
    struct pkt_buff:
        pass

    pkt_buff *pktb_alloc(int family, void *data, size_t len, size_t extra)
    void pktb_free(pkt_buff *pktb)

    uint8_t *pktb_data(pkt_buff *pktb)
    uint32_t pktb_len(pkt_buff *pktb)

    bint pktb_mangled(const pkt_buff *pktb)

    # PTR TO PROTO HEADERS
    uint8_t *pktb_mac_header(pkt_buff *pktb)
    uint8_t *pktb_network_header(pkt_buff *pktb)
    uint8_t *pktb_transport_header(pkt_buff *pktb)

    # LIKELY WONT USE
    void pktb_push(pkt_buff *pktb, unsigned int len)
    void pktb_pull(pkt_buff *pktb, unsigned int len)
    void pktb_put(pkt_buff *pktb, unsigned int len)
    void pktb_trim(pkt_buff *pktb, unsigned int len)
    unsigned int pktb_tailroom(pkt_buff *pktb)

    # probably wont be used directly. protocol mangle functions are recommended.
    int pktb_mangle(pkt_buff *pkt, unsigned int dataoff, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

cdef extern from "libnetfilter_queue/libnetfilter_queue_ipv4.h" nogil:
    struct iphdr:
        pass

    iphdr *nfq_ip_get_hdr(pkt_buff *pktb)
    int nfq_ip_set_transport_header(pkt_buff *pktb, iphdr *iph)

    # IP/TCP NAT CAN USE THIS
    int nfq_ip_mangle(pkt_buff *pkt, unsigned int dataoff, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

    void nfq_ip_set_checksum(iphdr *iph)
    int nfq_ip_snprintf(char *buf, size_t size, const iphdr *iph)

cdef extern from "libnetfilter_queue/libnetfilter_queue_tcp.h" nogil:
    tcphdr *nfq_tcp_get_hdr(pkt_buff *pktb)
    void *nfq_tcp_get_payload(tcphdr *tcph, pkt_buff *pktb)
    unsigned int nfq_tcp_get_payload_len(tcphdr *tcph, pkt_buff *pktb)

    # likely wont need since mangle function will call this automatically.
    void nfq_tcp_compute_checksum_ipv4(tcphdr *tcph, iphdr *iph)

    # TCP NAT CAN USE THIS
    int nfq_tcp_mangle_ipv4(
        pkt_buff *pkt, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

    int nfq_tcp_snprintf(char *buf, size_t size, const tcphdr *tcp)

cdef extern from "libnetfilter_queue/libnetfilter_queue_udp.h" nogil:
    udphdr *nfq_udp_get_hdr(pkt_buff *pktb)
    void *nfq_udp_get_payload(udphdr *udph, pkt_buff *pktb)
    unsigned int nfq_udp_get_payload_len(udphdr *udph, pkt_buff *pktb)

    # likely wont need since mangle function will call this automatically.
    void nfq_udp_compute_checksum_ipv4(udphdr *udph, iphdr *iph)

    # UDP NAT CAN USE THIS
    int nfq_udp_mangle_ipv4(
        pkt_buff *pkt, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

cdef extern from "linux/netfilter/nf_conntrack_common.h" nogil:
    # connection state tracking for netfilter. this is separated from, but required by, the
    # NAT layer. it can also be used by an iptables extension.
    enum: # ip_conntrack_info:
        # part of an established connection (either direction).
        IP_CT_ESTABLISHED

        # like NEW, but related to an existing connection, or ICMP error (in either direction).
        IP_CT_RELATED

        # started a new connection to track (only IP_CT_DIR_ORIGINAL); may be a retransmission.
        IP_CT_NEW

        # >= this indicates reply direction
        IP_CT_IS_REPLY

        IP_CT_ESTABLISHED_REPLY
        IP_CT_RELATED_REPLY
        IP_CT_NEW_REPLY
        # number of distinct IP_CT types (no NEW in reply dirn).
        IP_CT_NUMBER

cdef extern from "linux/netfilter/nfnetlink.h" nogil:
    # General form of address family dependent message.
    struct nfgenmsg:
        uint8_t    nfgen_family        # AF_xxx
        uint8_t    version             # nfnetlink version
        uint16_t   res_id              # resource id

cdef extern from "linux/netfilter/nfnetlink_queue.h" nogil:
    enum nfqnl_msg_types:
        NFQNL_MSG_PACKET                # packet from kernel to userspace
        NFQNL_MSG_VERDICT               # verdict from userspace to kernel
        NFQNL_MSG_CONFIG                # connect to a particular queue

        NFQNL_MSG_MAX

    struct nfqnl_msg_packet_hdr:
        uint32_t packet_id
        uint16_t hw_protocol
        uint8_t  hook

    struct nfqnl_msg_packet_hw:
        uint16_t hw_addrlen
        uint16_t _pad
        uint8_t  hw_addr[8]

    struct nfqnl_msg_packet_timestamp:
        uint64_t sec                      #__aligned_be64
        uint64_t usec                     #__aligned_be64

    enum nfqnl_vlan_attr:
        NFQA_VLAN_UNSPEC,
        NFQA_VLAN_PROTO,                # __be16 skb vlan_proto */
        NFQA_VLAN_TCI,                  # __be16 skb htons(vlan_tci) */
        __NFQA_VLAN_MAX,

        NFQA_VLAN_MAX = __NFQA_VLAN_MAX - 1

    # name causes cython compile error due to integer/enum type mismatch
    enum: # nfqnl_attr_type
        NFQA_UNSPEC,
        NFQA_PACKET_HDR,
        NFQA_VERDICT_HDR,               # nfqnl_msg_verdict_hrd */
        NFQA_MARK,                      # __u32 nfmark */
        NFQA_TIMESTAMP,                 # nfqnl_msg_packet_timestamp */
        NFQA_IFINDEX_INDEV,             # __u32 ifindex */
        NFQA_IFINDEX_OUTDEV,            # __u32 ifindex */
        NFQA_IFINDEX_PHYSINDEV,         # __u32 ifindex */
        NFQA_IFINDEX_PHYSOUTDEV,        # __u32 ifindex */
        NFQA_HWADDR,                    # nfqnl_msg_packet_hw */
        NFQA_PAYLOAD,                   # opaque data payload */
        NFQA_CT,                        # nfnetlink_conntrack.h */
        NFQA_CT_INFO,                   # enum ip_conntrack_info */
        NFQA_CAP_LEN,                   # __u32 length of captured packet */
        NFQA_SKB_INFO,                  # __u32 skb meta information */
        NFQA_EXP,                       # nfnetlink_conntrack.h */
        NFQA_UID,                       # __u32 sk uid */
        NFQA_GID,                       # __u32 sk gid */
        NFQA_SECCTX,                    # security context string */
        NFQA_VLAN,                      # nested attribute: packet vlan info */
        NFQA_L2HDR,                     # full L2 header */
        NFQA_PRIORITY,                  # skb->priority */

        NFQA_MAX

    struct nfqnl_msg_verdict_hdr:
        uint32_t    verdict
        uint32_t    id

    enum NfqnlMsgConfigCmds "nfqnl_msg_config_cmds":
        NFQNL_CFG_CMD_NONE
        NFQNL_CFG_CMD_BIND
        NFQNL_CFG_CMD_UNBIND
        NFQNL_CFG_CMD_PF_BIND
        NFQNL_CFG_CMD_PF_UNBIND

    struct NfqnlMsgConfigCmd "nfqnl_msg_config_cmd":
        uint8_t     command             # nfqnl_msg_config_cmds
        uint8_t     _pad
        uint16_t    pf                  # AF_xxx for PF_[UN]BIND

    enum NfqnlConfigMode "nfqnl_config_mode":
        NFQNL_COPY_NONE
        NFQNL_COPY_META
        NFQNL_COPY_PACKET

    struct NfqnlMsgConfigParams "nfqnl_msg_config_params":
        uint32_t    copy_range
        uint8_t     copy_mode           # enum nfqnl_config_mode
    # __attribute__ ((packed));

    enum NfqnlAttrConfig "nfqnl_attr_config":
        NFQA_CFG_UNSPEC
        NFQA_CFG_CMD                    # nfqnl_msg_config_cmd
        NFQA_CFG_PARAMS                 # nfqnl_msg_config_params
        NFQA_CFG_QUEUE_MAXLEN           # __u32
        NFQA_CFG_MASK                   # identify which flags to change
        NFQA_CFG_FLAGS                  # value of these flags (__u32)
        NFQA_CFG_MAX

    # Flags for NFQA_CFG_FLAGS
    enum:
        NFQA_CFG_F_FAIL_OPEN
        NFQA_CFG_F_CONNTRACK
        NFQA_CFG_F_GSO
        NFQA_CFG_F_UID_GID
        NFQA_CFG_F_MAX

    # flags for NFQA_SKB_INFO
    enum:
        # packet appears to have wrong checksums, but they are ok
        NFQA_SKB_CSUMNOTREADY

        # packet is GSO (i.e., exceeds device mtu)
        NFQA_SKB_GSO

        # csum not validated (incoming device doesn't support hw checksum, etc.)
        NFQA_SKB_CSUM_NOTVERIFIED

cdef extern from "libmnl/libmnl.h" nogil:
    # nlattr mnl_attr_for_each(nlattr attr, nlmsghdr *nlh, int offset)
    # mnl_attr_for_each_nested(nlattr attr, nest)
    # mnl_attr_for_each_payload(payload, size_t payload_size)

    #
    # Netlink socket API
    #
    enum:
        MNL_SOCKET_AUTOPID
        MNL_SOCKET_BUFFER_SIZE

    struct mnl_socket:
        pass

    #define MNL_FRAME_PAYLOAD(frame) ((void *)(frame) + NL_MMAP_HDRLEN)
    # void *MNL_FRAME_PAYLOAD(nl_mmap_hdr *frame)

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

    #
    # Netlink message API
    #
        #define MNL_ALIGN(len)              (((len)+MNL_ALIGNTO-1) & ~(MNL_ALIGNTO-1))
    #define MNL_NLMSG_HDRLEN    MNL_ALIGN(sizeof(struct nlmsghdr))
    int MNL_ALIGN(int len)
    unsigned long int MNL_NLMSG_HDRLEN

    size_t mnl_nlmsg_size(size_t len)
    size_t mnl_nlmsg_get_payload_len(const nlmsghdr *nlh)

    # Netlink message header builder
    nlmsghdr *mnl_nlmsg_put_header(void *buf)
    void *mnl_nlmsg_put_extra_header(nlmsghdr *nlh, size_t size)

    # Netlink message iterators
    bint mnl_nlmsg_ok(const nlmsghdr *nlh, int len)
    nlmsghdr *mnl_nlmsg_next(const nlmsghdr *nlh, int *len)

    # Netlink sequence tracking
    bint mnl_nlmsg_seq_ok(const nlmsghdr *nlh, unsigned int seq)

    # Netlink portID checking
    bint mnl_nlmsg_portid_ok(const nlmsghdr *nlh, unsigned int portid)

    # Netlink message getters
    void *mnl_nlmsg_get_payload(const nlmsghdr *nlh)
    void *mnl_nlmsg_get_payload_offset(const nlmsghdr *nlh, size_t offset)
    void *mnl_nlmsg_get_payload_tail(const nlmsghdr *nlh)

    # Netlink message printer
    void mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen, size_t extra_header_size)

    #
    # Netlink attributes API
    #
    enum:
        MNL_ATTR_HDRLEN

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

    # TLV attribute putters with buffer boundary checkings */
    bint mnl_attr_put_check(nlmsghdr *nlh, size_t buflen, uint16_t type, size_t len, const void *data)
    bint mnl_attr_put_u8_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint8_t data)
    bint mnl_attr_put_u16_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint16_t data)
    bint mnl_attr_put_u32_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint32_t data)
    bint mnl_attr_put_u64_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint64_t data)
    bint mnl_attr_put_str_check(nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)
    bint mnl_attr_put_strz_check(nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)

    # TLV attribute nesting */
    nlattr *mnl_attr_nest_start(nlmsghdr *nlh, uint16_t type)
    nlattr *mnl_attr_nest_start_check(nlmsghdr *nlh, size_t buflen, uint16_t type)
    void mnl_attr_nest_end(nlmsghdr *nlh, nlattr *start)
    void mnl_attr_nest_cancel(nlmsghdr *nlh, nlattr *start)

    # TLV validation */
    int mnl_attr_type_valid(const nlattr *attr, uint16_t maxtype)

    enum mnl_attr_data_type:
        MNL_TYPE_UNSPEC
        MNL_TYPE_U8
        MNL_TYPE_U16
        MNL_TYPE_U32
        MNL_TYPE_U64
        MNL_TYPE_STRING
        MNL_TYPE_FLAG
        MNL_TYPE_MSECS
        MNL_TYPE_NESTED
        MNL_TYPE_NESTED_COMPAT
        MNL_TYPE_NUL_STRING
        MNL_TYPE_BINARY
        MNL_TYPE_MAX

    int mnl_attr_validate(const nlattr *attr, mnl_attr_data_type type)
    int mnl_attr_validate2(const nlattr *attr, mnl_attr_data_type type, size_t len)

    # TLV iterators
    bint mnl_attr_ok(const nlattr *attr, int len)
    nlattr *mnl_attr_next(const nlattr *attr)

    # TLV callback-based attribute parsers
    ctypedef int (*mnl_attr_cb_t)(const nlattr *attr, void *data)
    # struct mnl_attr_cb_t:
    #     pass

    int mnl_attr_parse(const nlmsghdr *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data)
    int mnl_attr_parse_nested(const nlattr *attr, mnl_attr_cb_t cb, void *data)
    int mnl_attr_parse_payload(const void *payload, size_t payload_len, mnl_attr_cb_t cb, void *data)

    #
    # callback API
    #
    enum:
        MNL_CB_ERROR
        MNL_CB_STOP
        MNL_CB_OK

    ctypedef int (*mnl_cb_t)(const nlmsghdr *nlh, void *data)
    # struct mnl_cb_t:
    #     pass

    int mnl_cb_run(const void *buf, size_t numbytes, unsigned int seq,
                            unsigned int portid, mnl_cb_t cb_data, void *data)

    int mnl_cb_run2(const void *buf, size_t numbytes, unsigned int seq,
                            unsigned int portid, mnl_cb_t cb_data, void *data,
                            const mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len)

cdef struct srange:
  uint_fast8_t  start
  uint_fast8_t  end

cdef enum:
    NONE      = 0
    IP_PROXY  = 1
    DNS_PROXY = 2
    IPS_IDS   = 3

cdef enum:
    DNX_DROP   = 0
    DNX_ACCEPT = 1
    DNX_REJECT = 2

    DNX_SRC_NAT  = 4
    DNX_DST_NAT  = 8
    DNX_FULL_NAT = 16

    DNX_NAT_FLAGS = DNX_SRC_NAT | DNX_DST_NAT | DNX_FULL_NAT

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
    NAT_RULES

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
    IPhdr      *iphdr
    uint16_t    iphdr_len # header only
    Protohdr   *protohdr
    uint16_t    protohdr_len # header only
    uint8_t     mangled
    uint16_t    fw_section
    uint16_t    rule_num
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

