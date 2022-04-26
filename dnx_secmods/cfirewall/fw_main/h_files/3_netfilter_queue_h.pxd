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
cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
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

cdef extern from "libnetfilter_queue/pktbuff.h":
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

cdef extern from "libnetfilter_queue/libnetfilter_queue_ipv4.h":
    struct iphdr:
        pass

    iphdr *nfq_ip_get_hdr(pkt_buff *pktb)
    int nfq_ip_set_transport_header(pkt_buff *pktb, iphdr *iph)

    # IP/TCP NAT CAN USE THIS
    int nfq_ip_mangle(pkt_buff *pkt, unsigned int dataoff, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

    void nfq_ip_set_checksum(iphdr *iph)
    int nfq_ip_snprintf(char *buf, size_t size, const iphdr *iph)

cdef extern from "libnetfilter_queue/libnetfilter_queue_tcp.h":
    tcphdr *nfq_tcp_get_hdr(pkt_buff *pktb)
    void *nfq_tcp_get_payload(tcphdr *tcph, pkt_buff *pktb)
    unsigned int nfq_tcp_get_payload_len(tcphdr *tcph, pkt_buff *pktb)

    # likely wont need since mangle function will call this automatically.
    void nfq_tcp_compute_checksum_ipv4(tcphdr *tcph, iphdr *iph)

    # TCP NAT CAN USE THIS
    int nfq_tcp_mangle_ipv4(
        pkt_buff *pkt, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)

    int nfq_tcp_snprintf(char *buf, size_t size, const tcphdr *tcp)

cdef extern from "libnetfilter_queue/libnetfilter_queue_udp.h":
    udphdr *nfq_udp_get_hdr(pkt_buff *pktb)
    void *nfq_udp_get_payload(udphdr *udph, pkt_buff *pktb)
    unsigned int nfq_udp_get_payload_len(udphdr *udph, pkt_buff *pktb)

    # likely wont need since mangle function will call this automatically.
    void nfq_udp_compute_checksum_ipv4(udphdr *udph, iphdr *iph)

    # UDP NAT CAN USE THIS
    int nfq_udp_mangle_ipv4(
        pkt_buff *pkt, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len)
