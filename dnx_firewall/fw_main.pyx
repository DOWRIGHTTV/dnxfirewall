#!/usr/bin/env python3

from libc.stdlib cimport malloc, calloc, free
from libc.stdio cimport printf

DEF FW_SECTION_COUNT = 3
DEF FW_BEFORE_MAX_RULE_COUNT = 100
DEF FW_MAIN_MAX_RULE_COUNT = 1000
DEF FW_AFTER_MAX_RULE_COUNT = 100

DEF FW_MAX_ZONE_COUNT = 16
DEF FW_RULE_SIZE = 14

DEF SECURITY_PROFILE_COUNT = 2

cdef bint BYPASS = 0

# cdef u_int16_t[SECURITY_PROFILE_COUNT]

# stores zone(integer value) at index, which corresponds to if_nametoindex() / value returned from get_in/outdev()
cdef u_int16_t[FW_MAX_ZONE_COUNT] INTF_ZONE_MAP

# Firewall rules lock. Must be held
# to read from or make changes to
# "*firewall_rules[]"
# ================================== #
cdef pthread_mutex_t FWrulelock

pthread_mutex_init(&FWrulelock, NULL)
# ================================== #

# initializing global array and size tracker. contains pointers to arrays of pointers to FWrule
cdef FWrule **firewall_rules[FW_SECTION_COUNT]

cdef FWrule *fw_before_section[FW_BEFORE_MAX_RULE_COUNT]
fw_before_section = <FWrule[]*>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule*))

cdef FWrule *fw_main_section[FW_MAIN_MAX_RULE_COUNT]
fw_main_section = <FWrule[]*>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule*))

cdef FWrule *fw_after_section[FW_AFTER_MAX_RULE_COUNT]
fw_after_section = <FWrule[]*>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule*))

firewall_rules[0] = <FWrule**>&fw_before_section
firewall_rules[1] = <FWrule**>&fw_main_section
firewall_rules[2] = <FWrule**>&fw_after_section

# index corresponds to index of sections in firewall rules. this will allow us to skip over sections that are
# empty and know how far to iterate over. NOTE: since we track this we may be able to get away without resetting
# pointers of dangling rules since they will be out of bounds of specified iteration. otherwise we would need
# to reset to pointer to NULL then check for this every time we grab a rule pointer.
cdef u_int32_t CUR_RULE_COUNTS[3]

CUR_RULE_COUNTS[0] = 0 # BEFORE_CUR_RULE_COUNT
CUR_RULE_COUNTS[1] = 0 # MAIN_CUR_RULE_COUNT
CUR_RULE_COUNTS[2] = 0 # AFTER_CUR_RULE_COUNT

# NOTE: this is likely temporary. just a convenience wrapper/callback target.
cdef int nf_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data):

    parse(qh, nfa)

    return 1

cdef void parse(nfq_q_handle *qh, nfq_data *nfa) nogil:

    cdef protohdr proto
    proto.s_port = 0
    proto.d_port = 0

    cdef protohdr *proto_ptr = &proto

    cdef nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa)
    cdef u_int32_t id = ntohl(hdr.packet_id)

    cdef nfqnl_msg_packet_hw *_hw = nfq_get_packet_hw(nfa)
    cdef char *m_addr = <char*>_hw.hw_addr

    cdef hw_info hw
    hw.in_intf  = nfq_get_indev(nfa)
    hw.out_intf = nfq_get_outdev(nfa)
    hw.mac_addr = m_addr
    hw.timestamp = time(NULL)

    # define pointer and send to get payload. L3+ packet data will be accessible via this pointer.
    cdef unsigned char *data_ptr
    cdef int data_len = nfq_get_payload(nfa, &data_ptr)

    # assigning ip_header to first index of data casted to iphdr struct and calculate ip header len.
    cdef iphdr *ip_header = <iphdr*>data_ptr
    cdef u_int8_t iphdr_len = (ip_header.ver_ihl & 15) * 4

    # assign _data pointer to index 0 of protocol header.
    # cdef unsigned char *_data = &data_ptr[iphdr_len]

    printf('ip header len=%u | %u, %u, %u, %u\n', iphdr_len, data_ptr[iphdr_len], data_ptr[iphdr_len+1], data_ptr[iphdr_len+2], data_ptr[iphdr_len+3])
    # tcp/udp will reassign the pointer to their header data
    if ip_header.protocol != IPPROTO_ICMP:
        proto_ptr = <protohdr*>&data_ptr[iphdr_len]

    # nulling out fields if icmp (this will be done on rule creation also to match)
    else:
        proto.s_port = 0
        proto.d_port = 0

    # LOCKING ACCESS TO FIREWALL RULESETS.
    # this is currently only designed to prevent the manager thread from updating firewall rules as users configure them.
    pthread_mutex_lock(&FWrulelock)

    cdef u_int32_t mark = check_filter(&hw, ip_header, proto_ptr) | IP_PROXY

    pthread_mutex_unlock(&FWrulelock)

    # this is where me set the verdict. ip proxy is next in line regardless of action. (for geolocation data)
    # we could likely make that a separate function within the ip proxy inspection engine that runs reduced code.
    # if action is drop it would send it it lightweight inspection and bypass standard.

    cdef u_int32_t verdict
    # NOTE: this will invoke the the rule action without forwarding to another queue. only to be used for testing and
    # can be controlled via an argument to nf_run().
    if BYPASS:
        verdict = mark >> 4 & 15

    else:
        verdict = (mark & 15) << 16 | NF_QUEUE

    nfq_set_verdict2(
        qh, id, verdict, mark, data_len, data_ptr
            )

    printf('packet action: %u\n', mark >> 4 & 15)
    printf('packet verdict: %u\n', verdict)

cdef u_int32_t check_filter(hw_info *hw, iphdr *ip_header, protohdr *proto) nogil:

    cdef u_int32_t gi, i
    cdef u_int32_t a = 0
    cdef FWrule **section
    cdef FWrule *rule
    cdef u_int32_t mark, section_count

    for gi in range(FW_SECTION_COUNT):

        section_count = CUR_RULE_COUNTS[gi]
        if section_count < 1: # in case there becomes a purpose for < 0 values
            continue

        #for i in range(0, FW_RULE_COUNT):
        for i in range(section_count):

            rule = firewall_rules[gi][i]

            a += 1
            printf(
                'RULE CHECK: %d > %u,%u,%u,%u,%d,%d,%u,%u,%u,%d,%d,%i,%i,%u,%u\n',
                a,
                rule.protocol,
                rule.s_zone,
                rule.s_net_id,
                rule.s_net_mask,
                rule.s_port_start,
                rule.s_port_end,

                #desitnation
                rule.d_zone,
                rule.d_net_id,
                rule.d_net_mask,
                rule.d_port_start,
                rule.d_port_end,

                # profiles - forward traffic only
                rule.action, # 0 drop, 1 accept (if profile set, and action is allow, action will be changed to forward)
                rule.log,

                rule.sec_profiles[0], # 0 off, > 1 profile number
                rule.sec_profiles[1]
            )

            # source matching

            # zone / currently tied to interface and designated LAN, WAN, DMZ
            # printf('in_int=%u, s_zone=%u\n', hw.in_intf, rule.s_zone)
            if hw.in_intf != rule.s_zone and rule.s_zone != 0:
                continue

            # subnet
            # printf('source ip=%u, ip_n_id=%u, rule ip=%u, rule netmask=%u\n', ip_header.saddr, ip_header.saddr & rule.s_net_mask, rule.s_net_id, rule.s_net_mask)
            if ip_header.saddr & rule.s_net_mask != rule.s_net_id:
                continue

            printf('header_proto=%u, rule_proto=%u\n', ip_header.protocol, rule.protocol)
            if ip_header.protocol != rule.protocol and rule.protocol != 0:
                continue

            printf('s_port_start=%u, s_port=%u, s_port_end=%u\n', rule.s_port_start, ntohs(proto.s_port), rule.s_port_end)
            # ICMP will always match since all port vals will be set to 0
            if not rule.s_port_start <= ntohs(proto.s_port) <= rule.s_port_end:
                continue

            # destination matching
            # printf('out_int=%u, d_zone=%u\n', hw.out_intf, rule.d_zone)
            # zone / currently tied to interface and designated LAN, WAN, DMZ
            if hw.out_intf != rule.d_zone and rule.d_zone != 0:
                continue

            # subnet
            if ip_header.daddr & rule.d_net_mask != rule.d_net_id:
                continue

            printf('d_port_start=%u, d_port=%u, d_port_end=%u\n', rule.d_port_start, ntohs(proto.d_port), rule.d_port_end)
            # ICMP will always match since all port vals will be set to 0
            if not rule.d_port_start <= ntohs(proto.d_port) <= rule.d_port_end:
                continue

            printf('rule action: %i\n', rule.action)
            # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
            # printf('FULL PACKET MATCH.\n')

            return (rule.sec_profiles[1] << 12 | rule.sec_profiles[0] << 8 | rule.action << 4)

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

    cdef void _set_FWrule(self, int ruleset, unsigned long[:] rule, int pos):

        cdef FWrule **fw_section
        cdef FWrule *fw_rule

        printf('[set/FWrule] %u > rule rcvd\n', pos)
        print(ruleset, rule, pos)

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

        printf('[set/FWrule] %u > ruleset location loaded, first item=%p\n', pos, fw_section[0])

        # general
        fw_rule.protocol = <u_int8_t>rule[0]

        # source
        fw_rule.s_zone       = <u_int8_t> rule[1]
        fw_rule.s_net_id     = <u_int32_t>rule[2]
        fw_rule.s_net_mask   = <u_int32_t>rule[3]
        fw_rule.s_port_start = <u_int16_t>rule[4]
        fw_rule.s_port_end   = <u_int16_t>rule[5]

        #destination
        fw_rule.d_zone       = <u_int8_t> rule[6]
        fw_rule.d_net_id     = <u_int32_t>rule[7]
        fw_rule.d_net_mask   = <u_int32_t>rule[8]
        fw_rule.d_port_start = <u_int16_t>rule[9]
        fw_rule.d_port_end   = <u_int16_t>rule[10]

        printf('[set/FWrule] %u > standard fields set\n', pos)

        # handling
        fw_rule.action = <u_int8_t>rule[11]
        fw_rule.log    = <u_int8_t>rule[12]

        printf('[set/FWrule] %u > action fields set\n', pos)

        # security profiles
        fw_rule.sec_profiles[0] = <u_int8_t>rule[13]
        fw_rule.sec_profiles[1] = <u_int8_t>rule[14]

        printf('[set/FWrule] %u > security profiles set\n', pos)

    # PYTHON ACCESSIBLE FUNCTIONS
    def nf_run(self, bint bypass=0):
        ''' calls internal C run method to engage nfqueue processes. this call will run forever, but will
        release the GIL prior to entering C and never try to reacquire it.'''

        global BYPASS

        BYPASS = bypass

        with nogil:
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

    cpdef int update_zones(self, Py_Array zone_map) with gil:
        '''acquires FWrule lock then updates the zone values by interface index. max slots defined by
        FW_MAX_ZONE_COUNT. the GIL will be acquired before any code execution.
        '''
        printf('[update/zones] attempting to aquire lock\n')

        pthread_mutex_lock(&FWrulelock)
        printf('[update/zones] aquired lock\n')

        for i in range(FW_MAX_ZONE_COUNT):
            INTF_ZONE_MAP[i] = zone_map[i]

        pthread_mutex_unlock(&FWrulelock)
        printf('[update/zones] released lock\n')

        return 0

    cpdef int update_ruleset(self, int ruleset, list rulelist) with gil:
        '''acquires FWrule lock then rewrites the corresponding section ruleset. the current length var
        will also be update while the lock is held. the GIL will be acquired before any code execution.
        '''

        printf('[update/ruleset] called\n')

        cdef int i, rule_count

        cdef unsigned long[:] rule

        rule_count = len(rulelist)

        printf('[update/ruleset] attempting to aquire lock\n')

        pthread_mutex_lock(&FWrulelock)

        printf('[update/ruleset] aquired lock\n')
        for i in range(rule_count):
            rule = rulelist[i]

            self._set_FWrule(ruleset, rule, i)

        # updating rule count in global tracker. this is very important in that it establishes the right side bound for
        # firewall ruleset iteration operations.
        CUR_RULE_COUNTS[ruleset] = rule_count

        pthread_mutex_unlock(&FWrulelock)
        printf('[update/ruleset] released lock\n')

        return 0
