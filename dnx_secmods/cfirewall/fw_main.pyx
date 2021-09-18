#!/usr/bin/env python3

from libc.stdlib cimport malloc, calloc, free
from libc.stdio cimport printf, sprintf

DEF FW_SECTION_COUNT = 4
DEF FW_SYSTEM_MAX_RULE_COUNT = 50
DEF FW_BEFORE_MAX_RULE_COUNT = 100
DEF FW_MAIN_MAX_RULE_COUNT = 1000
DEF FW_AFTER_MAX_RULE_COUNT = 100

DEF FW_MAX_ZONE_COUNT = 16
DEF FW_RULE_SIZE = 15

cdef bint BYPASS  = 0
cdef bint VERBOSE = 0

# Firewall rules lock. Must be held
# to read from or make changes to
# "*firewall_rules[]"
# ================================== #
cdef pthread_mutex_t FWrulelock

pthread_mutex_init(&FWrulelock, NULL)
# ================================== #

# initializing global array and size tracker. contains pointers to arrays of pointers to FWrule
cdef FWrule **firewall_rules[FW_SECTION_COUNT]

firewall_rules[0] = <FWrule**>calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[1] = <FWrule**>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[2] = <FWrule**>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[3] = <FWrule**>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule*))

# index corresponds to index of sections in firewall rules. this will allow us to skip over sections that are
# empty and know how far to iterate over. NOTE: since we track this we may be able to get away without resetting
# pointers of dangling rules since they will be out of bounds of specified iteration. otherwise we would need
# to reset to pointer to NULL then check for this every time we grab a rule pointer.
cdef u_int32_t CUR_RULE_COUNTS[FW_SECTION_COUNT]

CUR_RULE_COUNTS[0] = 0 # SYSTEM_CUR_RULE_COUNT
CUR_RULE_COUNTS[1] = 0 # BEFORE_CUR_RULE_COUNT
CUR_RULE_COUNTS[2] = 0 # MAIN_CUR_RULE_COUNT
CUR_RULE_COUNTS[3] = 0 # AFTER_CUR_RULE_COUNT

# stores zone(integer value) at index, which corresponds to if_nametoindex() / value returned from get_in/outdev()
cdef u_int16_t[FW_MAX_ZONE_COUNT] INTF_ZONE_MAP

cdef int cfirewall_rcv(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa) nogil:

    cdef protohdr proto
    cdef u_int8_t direction

    # creating ptr and assign uninitialized var proto. vals will be set lower.
    cdef protohdr *proto_ptr = &proto

    cdef nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa)
    cdef u_int32_t id = ntohl(hdr.packet_id)

    cdef nfqnl_msg_packet_hw *_hw = nfq_get_packet_hw(nfa)
    cdef char *m_addr = <char*>_hw.hw_addr

    cdef u_int8_t in_intf  = nfq_get_indev(nfa)
    cdef u_int8_t out_intf = nfq_get_outdev(nfa)

    cdef hw_info hw
    hw.in_zone   = INTF_ZONE_MAP[in_intf]
    hw.out_zone  = INTF_ZONE_MAP[out_intf]
    hw.mac_addr  = m_addr
    hw.timestamp = time(NULL)

    # define pointer and send to get payload. L3+ packet data will be accessible via this pointer.
    cdef unsigned char *data_ptr
    cdef int data_len = nfq_get_payload(nfa, &data_ptr)

    # IP HEADER
    # assigning ip_header to first index of data casted to iphdr struct and calculate ip header len.
    cdef iphdr *ip_header = <iphdr*>data_ptr
    cdef u_int8_t iphdr_len = (ip_header.ver_ihl & 15) * 4

    # PROTOCOL HEADER
    # tcp/udp will reassign the pointer to their header data
    if ip_header.protocol != IPPROTO_ICMP:
        proto_ptr = <protohdr*>&data_ptr[iphdr_len]

    # null out fields directly for icmp. ptr still passed to funcs. rules will have 0 ports for icmp also.
    else:
        proto.s_port = 0
        proto.d_port = 0

    # DIRECTION SET
    # looks at initial mark of packet to determine the stateful direction of the conn
    if hw.in_zone == WAN_IN:
        direction = INBOUND

    else:
        direction = OUTBOUND

    # =============================== #
    # LOCKING ACCESS TO FIREWALL.
    # this is currently only designed to prevent the manager thread from updating firewall rules as users configure them.
    pthread_mutex_lock(&FWrulelock)

    # X | X | X | X | ips | ipp | direction | action
    cdef u_int32_t mark = cfirewall_inspect(&hw, ip_header, proto_ptr) | direction << 4

    pthread_mutex_unlock(&FWrulelock)
    # =============================== #

    # this is where we set the verdict. ip proxy is next in line regardless of action to gather geolocation data
    cdef u_int32_t verdict
    # NOTE: this will invoke the the rule action without forwarding to another queue. only to be used for testing and
    # can be controlled via an argument to nf_run().
    if BYPASS:
        verdict = mark & 15

    else:
        verdict = (IP_PROXY & 15) << 16 | NF_QUEUE

    nfq_set_verdict2(
        qh, id, verdict, mark, data_len, data_ptr
            )

    vprint('[C/packet] action=%u,', mark & 15, 'verdict=%u\n', verdict)

    # libnfnetlink.c return >> libnetfiler_queue return >> CFirewall._run.
    # < 0 vals are errors, but return is being ignored by CFirewall._run.
    return 1

# explicit inline declaration needed for compiler to know to inline this function
cdef inline u_int32_t cfirewall_inspect(hw_info *hw, iphdr *ip_header, protohdr *proto) nogil:

    cdef:
        FWrule **section
        FWrule *rule
        u_int16_t iph_src_netid, iph_dst_netid
        u_int32_t rule_src_protocol, rule_dst_protocol # <16 bit proto | 16 bit port>
        u_int32_t gi, i

    for gi in range(FW_SECTION_COUNT):

        current_rule_count = CUR_RULE_COUNTS[gi]
        if current_rule_count < 1: # in case there becomes a purpose for < 0 values
            continue

        for i in range(current_rule_count):

            rule = firewall_rules[gi][i]

            # NOTE: inspection order: src > dst | zone, ip_addr, protocol, port

            # ================================================================== #
            # ZONE MATCHING
            # ================================================================== #
            # currently tied to interface and designated LAN, WAN, DMZ
            vprint('p-i zone=%u, ', hw.in_zone, 'r-i zone=%u\n', rule.s_zone)
            vprint('p-o zone=%u, ', hw.out_zone, 'r-o zone=%u\n', rule.d_zone)
            if hw.in_zone != rule.s_zone and rule.s_zone != 0:
                continue

            if hw.out_zone != rule.d_zone and rule.d_zone != 0:
                continue

            # ================================================================== #
            # IP/NETMASK
            # ================================================================== #
            iph_src_netid = ntohl(ip_header.saddr) & rule.s_net_mask
            vprint('p-s ip=%u, ', ntohl(ip_header.saddr), 'p-s netid=%u, ', iph_src_netid, 'r-s netid=%u\n', rule.s_net_id)
            if ip_header.saddr & rule.s_net_mask != rule.s_net_id:
                continue

            iph_dst_netid = ntohl(ip_header.daddr) & rule.d_net_mask
            vprint('p-d ip=%u, ', ntohl(ip_header.daddr), 'p-d netid=%u, ', iph_dst_netid, 'r-d netid=%u\n', rule.d_net_id)
            if ip_header.daddr & rule.d_net_mask != rule.d_net_id:
                continue

            # ================================================================== #
            # PROTOCOL
            # ================================================================== #
            rule_src_protocol = rule.s_port_start >> 16
            vprint('p proto=%u, ', ip_header.protocol, 'r-s proto=%u\n', rule_src_protocol)
            if ip_header.protocol != rule_src_protocol and rule_src_protocol != 0:
                continue

            rule_dst_protocol = rule.d_port_start >> 16
            vprint('p proto=%u, ', ip_header.protocol, 'r-d proto=%u\n', rule_dst_protocol)
            if ip_header.protocol != rule_dst_protocol and rule_dst_protocol != 0:
                continue

            # ================================================================== #
            # PORT
            # ================================================================== #
            # ICMP will match on the first port start value (looking for 0)
            if not rule.s_port_start <= ntohs(proto.s_port) <= rule.s_port_end:
                continue

            if not rule.d_port_start <= ntohs(proto.d_port) <= rule.d_port_end:
                continue

            # ================================================================== #
            # ACTION | return rule options
            # ================================================================== #
            # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
            return (rule.sec_profiles[1] << 12 | rule.sec_profiles[0] << 8 | rule.action)

        return DROP

cdef u_int32_t MAX_COPY_SIZE = 4016 # 4096(buf) - 80
cdef u_int32_t DEFAULT_MAX_QUEUELEN = 8192

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
cdef u_int32_t SOCK_RCV_SIZE = 1024 * 4796 // 2


cdef class CFirewall:

    cdef void _run(self) nogil:
        '''Accept packets using recv.'''

        cdef int fd = nfq_fd(self.h)
        cdef char buf[4096]
        cdef int rv
        cdef int recv_flags = 0

        while True:
            rv = recv(fd, buf, sizeof(buf), recv_flags)

            if (rv >= 0):
                nfq_handle_packet(self.h, buf, rv)

            else:
                if errno != ENOBUFS:
                    break

    cdef u_int32_t cidr_to_int(self, long cidr):

        cdef u_int32_t integer_mask = 0
        cdef u_int8_t  mask_index = 31 # 1 + 31 shifts = 32 bits

        for i in range(cidr+1):
            integer_mask |= 1 << mask_index

            mask_index -= 1

        if VERBOSE:
            print(f'cidr={cidr}, integer_mask={integer_mask}')

        return integer_mask

    cdef void set_FWrule(self, int ruleset, unsigned long[:] rule, int pos):

        cdef FWrule **fw_section
        cdef FWrule *fw_rule

        # allows us to access rule pointer array to check if position has already been
        # initialized with a pointer. all uninitialized positions will be set to 0.
        fw_section = firewall_rules[ruleset]

        # initial rule/pointer init for this position.
        # allocate new memory to hold rule, then assign address to pointer held in section array.
        if fw_section[pos] == NULL:
            fw_rule = <FWrule*>malloc(sizeof(FWrule))

            fw_section[pos] = fw_rule

        # rule already has memory allocated and pointer has been initialized and set.
        else:
            fw_rule = fw_section[pos]

        # general
        fw_rule.enabled = <u_int8_t>rule[0]

        # source
        fw_rule.s_zone       = <u_int8_t> rule[1]
        fw_rule.s_net_id     = <u_int32_t>rule[2]
        fw_rule.s_net_mask   = self.cidr_to_int(rule[3]) # converting CIDR to integer. pow(2, rule[3])
        fw_rule.s_port_start = <u_int16_t>rule[4]
        fw_rule.s_port_end   = <u_int16_t>rule[5]

        #destination
        fw_rule.d_zone       = <u_int8_t> rule[6]
        fw_rule.d_net_id     = <u_int32_t>rule[7]
        fw_rule.d_net_mask   = self.cidr_to_int(rule[8]) # converting CIDR to integer. pow(2, rule[3])
        fw_rule.d_port_start = <u_int16_t>rule[9]
        fw_rule.d_port_end   = <u_int16_t>rule[10]

        # printf('[set/FWrule] %u > standard fields set\n', pos)

        # handling
        fw_rule.action = <u_int8_t>rule[11]
        fw_rule.log    = <u_int8_t>rule[12]

        # printf('[set/FWrule] %u > action fields set\n', pos)

        # security profiles
        fw_rule.sec_profiles[0] = <u_int8_t>rule[13]
        fw_rule.sec_profiles[1] = <u_int8_t>rule[14]

        # printf('[set/FWrule] %u > security profiles set\n', pos)

    # PYTHON ACCESSIBLE FUNCTIONS
    def nf_run(self, bint bypass, bint verbose):
        ''' calls internal C run method to engage nfqueue processes. this call will run forever, but will
        release the GIL prior to entering C and never try to reacquire it.'''

        global BYPASS, VERBOSE

        BYPASS  = bypass
        VERBOSE = verbose

        # release gil and never look back.
        with nogil:
            self._run()

    def nf_set(self, u_int16_t queue_num):
        self.h = nfq_open()

        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>cfirewall_rcv, <void*>self)

        if self.qh == NULL:
            return 1

        nfq_set_mode(self.qh, NFQNL_COPY_PACKET, MAX_COPY_SIZE)

        nfq_set_queue_maxlen(self.qh, DEFAULT_MAX_QUEUELEN)

        nfnl_rcvbufsiz(nfq_nfnlh(self.h), SOCK_RCV_SIZE)

    def nf_break(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        nfq_close(self.h)

    cpdef int update_zones(self, Py_Array zone_map) with gil:
        '''acquires FWrule lock then updates the zone values by interface index. max slots defined by
        FW_MAX_ZONE_COUNT. the GIL will be acquired before any code execution.
        '''

        pthread_mutex_lock(&FWrulelock)
        # printf('[update/zones] acquired lock\n')

        for i in range(FW_MAX_ZONE_COUNT):
            INTF_ZONE_MAP[i] = zone_map[i]

        pthread_mutex_unlock(&FWrulelock)
        # printf('[update/zones] released lock\n')

        return 0

    cpdef int update_ruleset(self, int ruleset, list rulelist) with gil:
        '''acquires FWrule lock then rewrites the corresponding section ruleset. the current length var
        will also be update while the lock is held. the GIL will be acquired before any code execution.
        '''

        cdef int i, rule_count

        cdef unsigned long[:] rule

        rule_count = len(rulelist)

        pthread_mutex_lock(&FWrulelock)

        # printf('[update/ruleset] acquired lock\n')
        for i in range(rule_count):
            rule = rulelist[i]

            self.set_FWrule(ruleset, rule, i)

        # updating rule count in global tracker. this is very important in that it establishes the right side bound for
        # firewall ruleset iteration operations.
        CUR_RULE_COUNTS[ruleset] = rule_count

        pthread_mutex_unlock(&FWrulelock)
        # printf('[update/ruleset] released lock\n')

        return 0

cdef inline void vprint(char *msg1, u_int32_t one, char *msg2='', long two=-1, char *msg3='', long thr=-1) nogil:
    if VERBOSE:
        printf(msg1, one)

        if two != -1:
            printf(msg2, two)

        if thr != -1:
            printf(msg3, thr)