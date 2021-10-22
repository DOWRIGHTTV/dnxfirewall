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

DEF ANY_ZONE = 99
DEF NO_SECTION = 99
DEF ANY_PROTOCOL = 0

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

firewall_rules[SYSTEM_RULES] = <FWrule**>calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[BEFORE_RULES] = <FWrule**>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[MAIN_RULES] = <FWrule**>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule*))
firewall_rules[AFTER_RULES] = <FWrule**>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule*))

# index corresponds to index of sections in firewall rules. this will allow us to skip over sections that are
# empty and know how far to iterate over. NOTE: since we track this we may be able to get away without resetting
# pointers of dangling rules since they will be out of bounds of specified iteration. otherwise we would need
# to reset to pointer to NULL then check for this every time we grab a rule pointer.
cdef u_int32_t CUR_RULE_COUNTS[FW_SECTION_COUNT]

CUR_RULE_COUNTS[SYSTEM_RULES] = 0 # SYSTEM_CUR_RULE_COUNT
CUR_RULE_COUNTS[BEFORE_RULES] = 0 # BEFORE_CUR_RULE_COUNT
CUR_RULE_COUNTS[MAIN_RULES]   = 0 # MAIN_CUR_RULE_COUNT
CUR_RULE_COUNTS[AFTER_RULES]  = 0 # AFTER_CUR_RULE_COUNT

# stores zone(integer value) at index, which corresponds to if_nametoindex() / value returned from get_in/outdev()
cdef u_int16_t[FW_MAX_ZONE_COUNT] INTF_ZONE_MAP

cdef int cfirewall_rcv(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa) nogil:

    # definitions or default assignments
    cdef:
        unsigned char *data
        iphdr *ip_header
        protohdr *proto_header

        # default proto_header values for icmp. will be replaced with protocol specific values if applicable
        protohdr _proto_header = [0, 0]

        u_int8_t direction, iphdr_len
        int data_len
        res_tuple inspection_res
        u_int32_t mark, verdict = DROP

    # definition + assignment with function calls
    cdef:
        nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa)
        u_int32_t id = ntohl(hdr.packet_id)

        # interface index which corresponds to zone map index
        u_int8_t in_intf = nfq_get_indev(nfa)
        u_int8_t out_intf = nfq_get_outdev(nfa)

        # grabbing source mac address and casting to char array
        nfqnl_msg_packet_hw *_hw = nfq_get_packet_hw(nfa)
        char *m_addr = <char*>_hw.hw_addr

        hw_info hw = [
            INTF_ZONE_MAP[in_intf],
            INTF_ZONE_MAP[out_intf],
            m_addr,
            time(NULL)
        ]

    # passing ptr of uninitialized data ptr to func. L3+ packet data will be placed at and accessible by this pointer.
    data_len = nfq_get_payload(nfa, &data)

    # IP HEADER
    # assigning ip_header to first index of data casted to iphdr struct and calculate ip header len.
    ip_header = <iphdr*>data_ptr
    iphdr_len = (ip_header.ver_ihl & 15) * 4

    # PROTOCOL HEADER
    # tcp/udp will reassign the pointer to their header data
    proto_header_ptr = <protohdr*>&data_ptr[iphdr_len] if ip_header.protocol != IPPROTO_ICMP else &proto_header

    # DIRECTION SET
    # uses initial mark of packet to determine the stateful direction of the conn
    direction = OUTBOUND if hw.in_zone != WAN_IN else INBOUND

    # =============================== #
    # LOCKING ACCESS TO FIREWALL.
    # this is currently only designed to prevent the manager thread from updating firewall rules as users configure them.
    pthread_mutex_lock(&FWrulelock)

    inspection_res = cfirewall_inspect(&hw, ip_header, proto_ptr)

    pthread_mutex_unlock(&FWrulelock)
    # =============================== #

    # SYSTEM RULES will have cfirewall invoke action directly since this traffic does not need further inspection
    if (inspection_res.fw_section == SYSTEM_RULES):

        printf('[SYSTEM RULE] proto=%u, port=%u\n', ip_header.protocol, proto_ptr.d_port)

        nfq_set_verdict(qh, id, inspection_res.action, data_len, data_ptr)

    else:
        # X | X | X | X | ips | ipp | direction | action. direction bits set after mark is returned.
        mark = inspection_res.mark | direction << 4

        # verdict is defined here based on BYPASS flag.
        # if not BYPASS, ip proxy is next in line regardless of action to gather geolocation data
        # if BYPASS, invoke the rule action without forwarding to another queue. only to be used for testing and
        #   - can be controlled via an argument to nf_run().
        verdict = inspection_res.action if BYPASS else IP_PROXY << 16 | NF_QUEUE

        nfq_set_verdict2(qh, id, verdict, mark, data_len, data_ptr)

    vprint('[C/packet] action=%u,', inspection_res.action, 'verdict=%u\n', verdict)

    # libnfnetlink.c return >> libnetfiler_queue return >> CFirewall._run.
    # < 0 vals are errors, but return is being ignored by CFirewall._run.
    return 1

# explicit inline declaration needed for compiler to know to inline this function
cdef inline res_tuple cfirewall_inspect(hw_info *hw, iphdr *ip_header, protohdr *proto) nogil:

    cdef:
        FWrule **section
        FWrule *rule
        u_int32_t iph_src_netid, iph_dst_netid
        u_int32_t rule_src_protocol, rule_dst_protocol # <16 bit proto | 16 bit port>
        u_int16_t section_num, rule_num

        # default action pre set. will be overridden if rule match.
        res_tuple results = [NO_SECTION, DROP, DROP]

    for section_num in range(FW_SECTION_COUNT):

        current_rule_count = CUR_RULE_COUNTS[section_num]
        if (current_rule_count < 1): # in case there becomes a purpose for < 0 values
            continue

        for rule_num in range(current_rule_count):

            rule = firewall_rules[section_num][rule_num]

            # NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (not rule.enabled):
                continue

            # ================================================================== #
            # ZONE MATCHING
            # ================================================================== #
            # currently tied to interface and designated LAN, WAN, DMZ
            vprint('p-i zone=%u, ', hw.in_zone, 'r-i zone=%u\n', rule.s_zone)
            vprint('p-o zone=%u, ', hw.out_zone, 'r-o zone=%u\n', rule.d_zone)
            if (hw.in_zone != rule.s_zone and rule.s_zone != ANY_ZONE):
                continue

            if (hw.out_zone != rule.d_zone and rule.d_zone != ANY_ZONE):
                continue

            # ================================================================== #
            # IP/NETMASK
            # ================================================================== #
            iph_src_netid = ntohl(ip_header.saddr) & rule.s_net_mask
            vprint('p-s ip=%u, ', ntohl(ip_header.saddr), 'p-s netid=%u, ', iph_src_netid, 'r-s netid=%u\n', rule.s_net_id)
            if (iph_src_netid != rule.s_net_id):
                continue

            iph_dst_netid = ntohl(ip_header.daddr) & rule.d_net_mask
            vprint('p-d ip=%u, ', ntohl(ip_header.daddr), 'p-d netid=%u, ', iph_dst_netid, 'r-d netid=%u\n', rule.d_net_id)
            if (iph_dst_netid != rule.d_net_id):
                continue

            # ================================================================== #
            # PROTOCOL
            # ================================================================== #
            rule_src_protocol = rule.s_port_start >> 16
            vprint('p proto=%u, ', ip_header.protocol, 'r-s proto=%u\n', rule_src_protocol)
            if (ip_header.protocol != rule_src_protocol and rule_src_protocol != ANY_PROTOCOL):
                continue

            rule_dst_protocol = rule.d_port_start >> 16
            vprint('p proto=%u, ', ip_header.protocol, 'r-d proto=%u\n', rule_dst_protocol)
            if (ip_header.protocol != rule_dst_protocol and rule_dst_protocol != ANY_PROTOCOL):
                continue

            # ================================================================== #
            # PORT
            # ================================================================== #
            # ICMP will match on the first port start value (looking for 0)
            if (not rule.s_port_start <= ntohs(proto.s_port) <= rule.s_port_end):
                continue

            if (not rule.d_port_start <= ntohs(proto.d_port) <= rule.d_port_end):
                continue

            # ================================================================== #
            # ACTION | return rule options
            # ================================================================== #
            # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
            # notify caller which section match was in. this will be used to skip inspection for system access rules
            results.fw_section = section_num
            results.action = rule.action
            results.mark = rule.sec_profiles[1] << 12 | rule.sec_profiles[0] << 8 | rule.action

            return results

        return results

cdef u_int32_t MAX_COPY_SIZE = 4016 # 4096(buf) - 80
cdef u_int32_t DEFAULT_MAX_QUEUELEN = 8192

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
cdef u_int32_t SOCK_RCV_SIZE = 1024 * 4796 // 2


cdef class CFirewall:

    def __cinit__(self, bint bypass, bint verbose):
        global BYPASS, VERBOSE

        BYPASS  = bypass
        VERBOSE = verbose

    cdef void _run(self) nogil:
        '''Accept packets using recv.'''

        cdef int fd = nfq_fd(self.h)
        cdef char packet_buf[4096]
        cdef size_t sizeof_buf = sizeof(packet_buf)
        cdef int data_len
        cdef int recv_flags = 0

        while True:
            data_len = recv(fd, packet_buf, sizeof_buf, recv_flags)

            if (data_len >= 0):
                nfq_handle_packet(self.h, packet_buf, data_len)

            else:
                if errno != ENOBUFS:
                    break

    cdef inline u_int32_t cidr_to_int(self, long cidr):

        cdef u_int32_t integer_mask = 0
        cdef u_int8_t  mask_index = 31 # 1 + 31 shifts = 32 bits

        for i in range(cidr):
            integer_mask |= 1 << mask_index

            mask_index -= 1

        if (VERBOSE):
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
        if (fw_section[pos] == NULL):
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
    def nf_run(self):
        ''' calls internal C run method to engage nfqueue processes. this call will run forever, but will
        release the GIL prior to entering C and never try to reacquire it.'''

        # release gil and never look back.
        with nogil:
            self._run()

    def nf_set(self, u_int16_t queue_num):
        self.h = nfq_open()

        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>cfirewall_rcv, <void*>self)

        if (self.qh == NULL):
            return 1

        nfq_set_mode(self.qh, NFQNL_COPY_PACKET, MAX_COPY_SIZE)

        nfq_set_queue_maxlen(self.qh, DEFAULT_MAX_QUEUELEN)

        nfnl_rcvbufsiz(nfq_nfnlh(self.h), SOCK_RCV_SIZE)

    def nf_break(self):
        if (self.qh != NULL):
            nfq_destroy_queue(self.qh)

        nfq_close(self.h)

    cpdef int update_zones(self, Py_Array zone_map) with gil:
        '''acquires FWrule lock then updates the zone values by interface index. max slots defined by
        FW_MAX_ZONE_COUNT. the GIL will be acquired before any code execution.
        '''

        pthread_mutex_lock(&FWrulelock)
        printf('[update/zones] acquired lock\n')

        for i in range(FW_MAX_ZONE_COUNT):
            INTF_ZONE_MAP[i] = zone_map[i]

        pthread_mutex_unlock(&FWrulelock)
        printf('[update/zones] released lock\n')

        return 0

    cpdef int update_ruleset(self, int ruleset, list rulelist) with gil:
        '''acquires FWrule lock then rewrites the corresponding section ruleset. the current length var
        will also be update while the lock is held. the GIL will be acquired before any code execution.
        '''

        cdef int i, rule_count

        cdef unsigned long[:] rule

        rule_count = len(rulelist)

        pthread_mutex_lock(&FWrulelock)

        printf('[update/ruleset] acquired lock\n')
        for i in range(rule_count):
            rule = rulelist[i]

            self.set_FWrule(ruleset, rule, i)

        # updating rule count in global tracker. this is very important in that it establishes the right side bound for
        # firewall ruleset iteration operations.
        CUR_RULE_COUNTS[ruleset] = rule_count

        pthread_mutex_unlock(&FWrulelock)
        printf('[update/ruleset] released lock\n')

        return 0

cdef inline void vprint(char *msg1, u_int32_t one, char *msg2='', long two=-1, char *msg3='', long thr=-1) nogil:
    if (VERBOSE):
        printf(msg1, one)

        if two != -1:
            printf(msg2, two)

        if thr != -1:
            printf(msg3, thr)
