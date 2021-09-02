#!/usr/bin/env python3

from libc.stdlib cimport malloc
from libc.stdio cimport printf

DEF FW_RULE_COUNT = 1000
DEF FW_RULE_SIZE = 14

CUR_RULE_SIZE = 1

cdef int BYPASS = 1

cdef u_int16_t[FW_RULE_SIZE] r0 = [6, 0, 0, 0, 1, 65535, 0, 0, 0, 1, 65535, 1, 0, 0]

cdef FWrule *firewall_rules[FW_RULE_COUNT]

cdef FWrule r1 = init_FWrule(r0, 1)

printf('rule returned\n')

firewall_rules[0] = &r1

# to make position more intuitive, this will subtract 1 from sent in value to for index.
cdef FWrule init_FWrule(u_int16_t[FW_RULE_SIZE] rule, int pos):
    pos = pos - 1

    cdef FWrule firewall_rule

    firewall_rule.protocol     = rule[0]
    firewall_rule.s_zone       = rule[1]
    firewall_rule.s_net_id     = rule[2]
    firewall_rule.s_net_mask   = rule[3]
    firewall_rule.s_port_start = rule[4]
    firewall_rule.s_port_end   = rule[5]

    #destination
    firewall_rule.d_zone       = rule[6]
    firewall_rule.d_net_id     = rule[7]
    firewall_rule.d_net_mask   = rule[8]
    firewall_rule.d_port_start = rule[9]
    firewall_rule.d_port_end   = rule[10]

    firewall_rule.action       = rule[11]
    firewall_rule.ip_proxy     = rule[12]
    firewall_rule.ips_ids      = rule[13]

    printf('rule updated. pos=%u\n', pos)

    return firewall_rule

# NOTE: this is likely temporary. just a convenience wrapper/callback target.
cdef int nf_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data):

    printf('packet received!\n')
    with nogil:
        parse(qh, nfa)

    return 1

# arr[firewall_rule, firewall_rule, firewall_rule]*
cdef void parse(nfq_q_handle *qh, nfq_data *nfa) nogil:

    cdef nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa)
    cdef u_int32_t id = ntohl(hdr.packet_id)

    cdef nfqnl_msg_packet_hw *_hw = nfq_get_packet_hw(nfa)
    cdef char *m_addr = <char*>_hw.hw_addr

    cdef hw_info *hw = <hw_info*>malloc(sizeof(hw_info))
    hw.in_intf  = nfq_get_indev(nfa)
    hw.out_intf = nfq_get_outdev(nfa)
    hw.mac_addr = m_addr
    hw.timestamp = time(NULL)

    cdef unsigned char *data_ptr
    cdef int data_len = nfq_get_payload(nfa, &data_ptr)

    cdef iphdr* ip_header = <iphdr*>data_ptr
    cdef u_int8_t iphdr_len = (ip_header.ver_ihl & 15) * 4

    cdef unsigned char *_data = &data_ptr[iphdr_len]
    cdef protohdr *proto = NULL
    if ip_header.protocol != IPPROTO_ICMP:
        proto = <protohdr*>_data

    cdef u_int32_t mark = check_filter(hw, ip_header, proto) | IP_PROXY

    ## this is where me set the verdict. ip proxy is next in line regardless of action. (for geolocation data)
    # we could likely make that a separate function within the ip proxy inspection engine that runs reduced code.
    # if action is drop it would send it it lightweight inspection and bypass standard.

    cdef u_int32_t verdict
    if BYPASS:
        verdict = NF_ACCEPT

    else:
        verdict = (mark & 15) << 16 | NF_QUEUE

    nfq_set_verdict2(
        qh, id, verdict, mark, data_len, data_ptr
            )

    printf('verdict sent: %d\n', verdict)

cdef u_int32_t check_filter(hw_info *hw, iphdr *ip_header, protohdr *proto) nogil:

    cdef u_int32_t a = 0
    cdef FWrule *rule
    cdef u_int32_t mark = DROP

    #for i in range(0, FW_RULE_COUNT):
    for i in range(CUR_RULE_SIZE):

        rule = firewall_rules[i]

        a += 1
        # source matching
        printf('RULE CHECK: %d\n', a)

        # printf(
        #     '%u,%u,%d,%d,%d,%d,%u,%d,%d,%d,%d,%u,%u,%u\n',
        #     rule.protocol,
        #     rule.s_zone,
        #     rule.s_net_id,
        #     rule.s_net_mask,
        #     rule.s_port_start,
        #     rule.s_port_end,

        #     #desitnation
        #     rule.d_zone,
        #     rule.d_net_id,
        #     rule.d_net_mask,
        #     rule.d_port_start,
        #     rule.d_port_end,

        #     # profiles - forward traffic only
        #     rule.action, # 0 drop, 1 accept (if profile set, and action is allow, action will be changed to forward)
        #     rule.ip_proxy, # 0 off, > 1 profile number
        #     rule.ips_ids
        # )

        # zone / currently tied to interface and designated LAN, WAN, DMZ
        # printf('in_int=%u, s_zone=%u\n', hw.in_intf, rule.s_zone)
        if hw.in_intf != rule.s_zone and rule.s_zone != 0:
            continue

        # subnet
        # printf('source ip=%d, ip_n_id=%d, rule ip=%d, rule net id=%d\n', ip_header.saddr, ip_header.saddr & rule.s_net_mask, rule.s_net_id)
        if ip_header.saddr & rule.s_net_mask != rule.s_net_id:
            continue

        # printf('header_proto=%u, rule_proto=%u\n', ip_header.protocol, rule.protocol)
        if ip_header.protocol != rule.protocol:
            continue

        # printf('s_port_start=%d, s_port=%d, s_port_end=%d\n', rule.s_port_start, proto.s_port, rule.s_port_end)
        # ICMP will always match since all port vals will be set to 0
        if not rule.s_port_start <= proto.s_port <= rule.s_port_end:
            continue

        # destination matching
        # printf('out_int=%u, d_zone=%u\n', hw.out_intf, rule.d_zone)
        # zone / currently tied to interface and designated LAN, WAN, DMZ
        if hw.out_intf != rule.d_zone and rule.d_zone != 0:
            continue

        # subnet
        if ip_header.daddr & rule.d_net_mask != rule.d_net_id:
            continue

        # printf('d_port_start=%d, d_port=%d, d_port_end=%d\n', rule.d_port_start, proto.d_port, rule.d_port_end)
        # ICMP will always match since all port vals will be set to 0
        if not rule.d_port_start <= proto.d_port <= rule.d_port_end:
            continue

        # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
        # TODO: see if drop can be called here and still forwarded to IPP, where it inspects but no action taken.
        if rule.action == ACCEPT:
            mark = (rule.ips_ids << 12 | rule.ip_proxy << 8 | ACCEPT << 4)

            printf('FULL PACKET MATCH.\n')

        break

    return mark

cdef u_int32_t MAX_COPY_SIZE = 4016 # 4096(buf) - 80
cdef u_int32_t DEFAULT_MAX_QUEUELEN = 8192

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
cdef u_int32_t SOCK_RCV_SIZE = 1024 * 4796 // 2


cdef class CFirewall:
    cdef FWrule *ruleset[FW_RULE_COUNT]

    cdef void _run(self) nogil:
        '''Accept packets using recv.'''

        cdef int fd = nfq_fd(self.h)
        cdef char buf[4096]
        cdef int rv
        cdef int recv_flags = 0

        while True:
            with nogil:
                rv = recv(fd, buf, sizeof(buf), recv_flags)

            if (rv >= 0):
                nfq_handle_packet(self.h, buf, rv)

            else:
                if errno != ENOBUFS:
                    break

    # PYTHON ACCESSIBLE FUNCTIONS
    def nf_run(self):
        #with nogil:
        self._run()

    def nf_set(self, u_int16_t queue_num):
        self.h = nfq_open()

        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>nf_callback, <void*>self)

        if self.qh == NULL:
            return 1

        nfq_set_mode(self.qh, NFQNL_COPY_PACKET, MAX_COPY_SIZE)

        nfq_set_queue_maxlen(self.qh, DEFAULT_MAX_QUEUELEN)

        nfnl_rcvbufsiz(nfq_nfnlh(self.h), SOCK_RCV_SIZE)

    def nf_break(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        nfq_close(self.h)
