from libc.stdlib cimport malloc, calloc, free
from libc.stdio cimport printf, sprintf

from dnx_iptools.dnx_trie_search cimport RangeTrie

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
DEF COUNTRY_NOT_DEFINED = 0

DEF OK  = 0
DEF ERR = 1

DEF TWO_BITS = 2
DEF FOUR_BITS = 4
DEF ONE_BYTE = 8
DEF TWELVE_BITS = 12
DEF TWO_BYTES = 16

DEF TWO_BIT_MASK = 3
DEF FOUR_BIT_MASK = 15

cdef bint BYPASS  = 0
cdef bint VERBOSE = 0

# Firewall rules lock. Must be held
# to read from or make changes to
# "*firewall_rules[]"
# ================================== #
cdef pthread_mutex_t FWrulelock

pthread_mutex_init(&FWrulelock, NULL)
# ================================== #

# Geolocation definitions
# ================================== #
DEF GEO_MARKER = -1

cdef long MSB, LSB
cdef RangeTrie GEOLOCATION
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
# to reset pointer to NULL then check for this every time we grab a rule pointer.
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
        unsigned char *pktdata
        iphdr *ip_header
        protohdr *proto_header

        # default proto_header values for icmp. will be replaced with protocol specific values if applicable
        protohdr _proto_header = [0, 0]

        bint system_rule = 0

        u_int8_t direction, iphdr_len
        int pktdata_len
        res_tuple inspection_res
        u_int32_t verdict

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
    pktdata_len = nfq_get_payload(nfa, &pktdata)

    # IP HEADER
    # assigning ip_header to first index of data casted to iphdr struct and calculate ip header len.
    ip_header = <iphdr*>pktdata
    iphdr_len = (ip_header.ver_ihl & FOUR_BIT_MASK) * 4

    # PROTOCOL HEADER
    # tcp/udp will reassign the pointer to their header data
    proto_header = <protohdr*>&pktdata[iphdr_len] if ip_header.protocol != IPPROTO_ICMP else &_proto_header

    # DIRECTION SET
    # uses initial mark of packet to determine the stateful direction of the conn
    direction = OUTBOUND if hw.in_zone != WAN_IN else INBOUND

    # =============================== #
    # LOCKING ACCESS TO FIREWALL.
    # this is currently only designed to prevent the manager thread from updating firewall rules as users configure them.
    pthread_mutex_lock(&FWrulelock)

    inspection_res = cfirewall_inspect(&hw, ip_header, proto_header, direction)

    pthread_mutex_unlock(&FWrulelock)
    # =============================== #

    # SYSTEM RULES will have cfirewall invoke action directly since this traffic does not need further inspection
    if (inspection_res.fw_section == SYSTEM_RULES):

        system_rule = 1 # only used by verbose logging.

        nfq_set_verdict(qh, id, inspection_res.action, pktdata_len, pktdata)

    else:
        # verdict is defined here based on BYPASS flag.
        # if not BYPASS, ip proxy is next in line regardless of action to gather geolocation data
        # if BYPASS, invoke the rule action without forwarding to another queue. only to be used for testing and
        #   toggled via an argument to nf_run().
        verdict = inspection_res.action if BYPASS else IP_PROXY << TWO_BYTES | NF_QUEUE

        nfq_set_verdict2(qh, id, verdict, inspection_res.mark, pktdata_len, pktdata)

    # verdict is being used to eval whether packet matched a system rule. 0 verdict infers this also, but for ease
    # of reading, ill have both.
    if (VERBOSE):
        printf('[C/packet] action=%u, verdict=%u, system_rule=%u\n', inspection_res.action, verdict, system_rule)

    # libnfnetlink.c return >> libnetfiler_queue return >> CFirewall._run.
    # < 0 vals are errors, but return is being ignored by CFirewall._run. there may be a use for sending messages
    # back to socket loop, but who knows.
    return OK

# explicit inline declaration needed for compiler to know to inline this function
cdef inline res_tuple cfirewall_inspect(hw_info *hw, iphdr *ip_header, protohdr *proto_header, u_int8_t direction) nogil:

    cdef:
        FWrule **section
        FWrule *rule
        u_int32_t rule_src_protocol, rule_dst_protocol # <16 bit proto | 16 bit port>
        u_int16_t section_num, rule_num

        # normalizing src/dst ip in header to host order
        u_int32_t iph_src_ip = ntohl(ip_header.saddr)
        u_int32_t iph_dst_ip = ntohl(ip_header.daddr)

        # ip > country code. NOTE: this will be calculated regardless of a rule match so this process can take over
        # geolocation processing for all modules. ip proxy will still do the logging and profile blocking it just wont
        # need to pull the country code anymore.
        u_int16_t src_country = GEOLOCATION._search(iph_src_ip & MSB, iph_src_ip & LSB)
        u_int16_t dst_country = GEOLOCATION._search(iph_dst_ip & MSB, iph_dst_ip & LSB)

        # value used by ip proxy which is normalized and always represents the external ip address
        u_int16_t tracked_geo = src_country if direction == INBOUND else dst_country

        # return struct (section | action | mark)
        res_tuple results

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
            if (hw.in_zone != rule.s_zone and rule.s_zone != ANY_ZONE):
                continue

            if (hw.out_zone != rule.d_zone and rule.d_zone != ANY_ZONE):
                continue

            # ================================================================== #
            # GEOLOCATION or IP/NETMASK
            # ================================================================== #
            # geolocation matching repurposes network id and netmask fields in the firewall rule. net id of -1 flags
            # the rule as a geolocation rule with the country code using the netmask field. NOTE: just as with networks,
            # only a single country is currently supported per firewall rule src and dst.
            if (rule.s_net_id == GEO_MARKER):

                if (src_country != rule.s_net_mask):
                    continue

            else:

                # using rules mask to floor source ip in header and checking against rules network id
                if (iph_src_ip & rule.s_net_mask != rule.s_net_id):
                    continue

            if (rule.d_net_id == GEO_MARKER):
                if (dst_country != rule.d_net_mask):
                    continue

            else:

                # using rules mask to floor ip in header and checking against rules network id
                if (iph_dst_ip & rule.d_net_mask != rule.d_net_id):
                    continue

            # ================================================================== #
            # PROTOCOL
            # ================================================================== #
            rule_src_protocol = rule.s_port_start >> TWO_BYTES
            if (ip_header.protocol != rule_src_protocol and rule_src_protocol != ANY_PROTOCOL):
                continue

            rule_dst_protocol = rule.d_port_start >> TWO_BYTES
            if (ip_header.protocol != rule_dst_protocol and rule_dst_protocol != ANY_PROTOCOL):
                continue

            # ================================================================== #
            # PORT
            # ================================================================== #
            # ICMP will match on the first port start value (looking for 0)
            if (not rule.s_port_start <= ntohs(proto_header.s_port) <= rule.s_port_end):
                continue

            if (not rule.d_port_start <= ntohs(proto_header.d_port) <= rule.d_port_end):
                continue

            # ================================================================== #
            # VERBOSE MATCH OUTPUT | only showing matches due to too much output
            # ================================================================== #
            if (VERBOSE):
                printf('VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV\n')
                printf('pkt-in zone=%u, rule-in zone=%u, ', hw.in_zone, rule.s_zone)
                printf('pkt-out zone=%u, rule-out zone=%u\n', hw.out_zone, rule.d_zone)
                printf('pkt-src ip=%u, pkt-src netid=%u, rule-s netid=%lu\n', ntohl(ip_header.saddr), iph_src_ip & rule.s_net_mask, rule.s_net_id)
                printf('pkt-dst ip=%u, pkt-dst netid=%u, rule-d netid=%lu\n', ntohl(ip_header.daddr), iph_dst_ip & rule.d_net_mask, rule.d_net_id)
                printf('pkt-proto=%u, rule-s proto=%u, rule-d proto=%u\n', ip_header.protocol, rule_src_protocol, rule_dst_protocol)
                printf('pkt-src geo=%u, pkt-dst geo=%u\n', src_country, dst_country)
                printf('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n')

            # ================================================================== #
            # MATCH ACTION | return rule options
            # ================================================================== #
            # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
            # notify caller which section match was in. this will be used to skip inspection for system access rules
            results.fw_section = section_num
            results.action = rule.action
            results.mark = rule.sec_profiles[1] << TWO_BYTES | rule.sec_profiles[0] << TWELVE_BITS | \
                tracked_geo << FOUR_BITS | direction << TWO_BITS | rule.action

            return results

    # ================================================================== #
    # DEFAULT ACTION
    # ================================================================== #
    results.fw_section = NO_SECTION
    results.action = DROP
    results.mark = tracked_geo << FOUR_BITS | direction << TWO_BITS | DROP

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
                # TODO: i believe we can get rid of this and set up a lower level ignore of this. this might require
                #  the libmnl implementation version though.
                if (errno != ENOBUFS):
                    break

    cdef inline u_int32_t cidr_to_int(self, long cidr):

        cdef u_int32_t integer_mask = 0
        cdef u_int8_t  mask_index = 31 # 1 + 31 shifts = 32 bits

        for i in range(cidr):
            integer_mask |= 1 << mask_index

            mask_index -= 1

        if (VERBOSE):
            printf('cidr=%ld, integer_mask=%u\n', cidr, integer_mask)

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
        fw_rule.s_net_id     = <long>rule[2]
        fw_rule.s_net_mask   = self.cidr_to_int(rule[3]) # converting CIDR to integer. pow(2, rule[3])
        fw_rule.s_port_start = <u_int16_t>rule[4]
        fw_rule.s_port_end   = <u_int16_t>rule[5]

        #destination
        fw_rule.d_zone       = <u_int8_t> rule[6]
        fw_rule.d_net_id     = <long>rule[7] # need signed for -1/geolocation marker
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

        # printf('[set/FWrule] %u/%u > security profiles set\n', ruleset, pos)

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
            return ERR

        nfq_set_mode(self.qh, NFQNL_COPY_PACKET, MAX_COPY_SIZE)

        nfq_set_queue_maxlen(self.qh, DEFAULT_MAX_QUEUELEN)

        nfnl_rcvbufsiz(nfq_nfnlh(self.h), SOCK_RCV_SIZE)

    def nf_break(self):
        if (self.qh != NULL):
            nfq_destroy_queue(self.qh)

        nfq_close(self.h)

    cpdef void prepare_geolocation(self, tuple geolocation_trie, long msb, long lsb) with gil:
        '''initializes Cython Extension RangeTrie passing in py_trie provided then assigning reference globally to be
        used by cfirewall inspection. also globally assigns MSB and LSB definitions.'''

        global GEOLOCATION, MSB, LSB

        # TODO: implement lru caching compatible with cfirewall
        GEOLOCATION = RangeTrie()

        GEOLOCATION.generate_structure(geolocation_trie)

        MSB = msb
        LSB = lsb

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

        return OK

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

        return OK
