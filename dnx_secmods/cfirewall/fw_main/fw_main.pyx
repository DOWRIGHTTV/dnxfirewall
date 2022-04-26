#!/usr/bin/env Cython

from libc.stdlib cimport calloc, malloc, free
from libc.stdio cimport printf

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t, uint_fast32_t

from dnx_iptools.hash_trie.hash_trie cimport HashTrie_Range
from dnx_iptools.cprotocol_tools.cprotocol_tools cimport nullset

from fw_api.fw_api cimport api_open, process_api

# ===============================
# VERBOSE T-SHOOT ASSISTANCE
# ===============================
from pprint import PrettyPrinter
ppt = PrettyPrinter(sort_dicts=False).pprint
# ===============================

DEF FW_SECTION_COUNT = 6
DEF FW_SYSTEM_MAX_RULE_COUNT = 50
DEF FW_BEFORE_MAX_RULE_COUNT = 100
DEF FW_MAIN_MAX_RULE_COUNT = 1000
DEF FW_AFTER_MAX_RULE_COUNT = 100
DEF FW_NAT_PRE_MAX_RULE_COUNT = 250
DEF FW_NAT_POST_MAX_RULE_COUNT = 100

DEF FW_MAX_ATTACKERS = 250
DEF FW_MAX_ZONE_COUNT = 16
DEF FW_RULE_SIZE = 15

DEF NFQA_RANGE = NFQA_MAX + 1

DEF SYSTEM_RANGE_MAX = 1
DEF RULE_RANGE_MAX = 4
DEF NAT_PRE_RANGE_MAX = 5
DEF NAT_POST_RANGE_MAX = 6

DEF NAT_PREROUTE = 70
DEF NAT_POSTROUTE = 71

DEF ANY_ZONE = 99
DEF NO_SECTION = 99
DEF ANY_PROTOCOL = 0
DEF COUNTRY_NOT_DEFINED = 0

DEF OK  = 0
DEF ERR = -1

DEF Py_OK  = 0
DEF Py_ERR = 1

DEF NO_MATCH = 0
DEF MATCH = 1
DEF END_OF_ARRAY = 0

DEF TWO_BITS = 2
DEF FOUR_BITS = 4
DEF ONE_BYTE = 8
DEF TWELVE_BITS = 12
DEF TWO_BYTES = 16

DEF SECURITY_PROFILE_COUNT = 3
DEF PROFILE_SIZE = 4  # bits
DEF PROFILE_START = 12
DEF PROFILE_STOP = (SECURITY_PROFILE_COUNT * 4) + 8 + 1  # +1 for range

DEF TWO_BIT_MASK = 3
DEF FOUR_BIT_MASK = 15

DEF NETWORK = 1
DEF SERVICE = 2

# network object types. not using enums because they need to be hardcoded anyway.
DEF IP_ADDRESS = 1
DEF IP_NETWORK = 2
DEF IP_RANGE   = 3
DEF IP_GEO     = 6

DEF SVC_SOLO  = 1
DEF SVC_RANGE = 2
DEF SVC_LIST  = 3

cdef bint PROXY_BYPASS  = 0
cdef bint VERBOSE = 0

# ================================== #
# Firewall rules lock
# ================================== #
# Must be held to read from or make
# changes to "*firewall_rules[]"
# ---------------------------------- #
cdef pthread_mutex_t FWrulelock

pthread_mutex_init(&FWrulelock, NULL)

# Blocked list access lock
# ----------------------------------
cdef pthread_mutex_t FWblocklistlock

pthread_mutex_init(&FWblocklistlock, NULL)

# ================================== #
# Geolocation definitions
# ================================== #
cdef uint32_t MSB, LSB
cdef HashTrie_Range GEOLOCATION

# ==================================
# ARRAY INITIALIZATION
# ==================================
# contains pointers to arrays of pointers to FWrule
cdef FWrule *firewall_rules[FW_SECTION_COUNT]

# arrays of pointers to FWrule
firewall_rules[SYSTEM_RULES] = <FWrule*>calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(FWrule))
firewall_rules[BEFORE_RULES] = <FWrule*>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule))
firewall_rules[MAIN_RULES]   = <FWrule*>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule))
firewall_rules[AFTER_RULES]  = <FWrule*>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule))

# the index corresponds to the index of sections in firewall rules.
# this will allow us to skip over sections that are empty and know how far to iterate over.
# tracking this allows the ability to not clear pointers of dangling rules
# since they will be out of bounds of specified iteration.
cdef uint_fast16_t *CUR_RULE_COUNTS = <uint_fast16_t*>calloc(FW_SECTION_COUNT, sizeof(uint_fast16_t))

# stores zone(integer value) at index, which is mapped to if_nametoindex() (value returned from get_in/outdev)
cdef uint_fast16_t *INTF_ZONE_MAP = <uint_fast16_t*>calloc(FW_MAX_ZONE_COUNT, sizeof(uint_fast16_t))

# stores the active attackers set/controlled by IPS/IDS
cdef uint32_t *ATTACKER_BLOCKLIST = <uint32_t*>calloc(FW_MAX_ATTACKERS, sizeof(uint32_t))

cdef uint32_t BLOCKLIST_CUR_SIZE = 0 # if we decide to track size for appends

# ==================================
# PRIMARY INSPECTION LOGIC
# ==================================
cdef int cfirewall_recv(const nlmsghdr *nlh, void *data) nogil:

    # definitions or default assignments
    cdef:
        cfdata *cfd = <cfdata*>data

        uint8_t *pktdata
        IPhdr *ip_header

        # default proto_header values (used by icmp) and replaced with protocol specific values
        # not using calloc to keep mem allocation handled on stack
        Protohdr proto_def = [0, 0]
        Protohdr *proto_header = &proto_def

        uint8_t     direction
        uint16_t    pktdata_len
        size_t      iphdr_len

        srange fw_sections
        InspectionResults inspection = [0, NF_ACCEPT, 69]

        # NEW
        nlattr *netlink_attrs[NFQA_RANGE]
        # nlattr **netlink_attrs = <nlattr**>malloc((NFQA_RANGE) * sizeof(nlattr*))

        nfqnl_msg_packet_hdr *nlhdr

        uint32_t iif, oif, mark, ct_info

        HWinfo hw
        char *m_addr = NULL
        ##

    # NEW #
    nullset(netlink_attrs, NFQA_RANGE)

    nfq_nlmsg_parse(nlh, netlink_attrs)
    # ======================
    # CONNTRACK
    # this should be checked as soon as feasibly possible for performance.
    # this will be used to allow for stateless inspection policies later.
    ct_info = <uint32_t*>mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO])
    if (htonl(ct_info) & IP_CT_RELATED|IP_CT_ESTABLISHED):
        dnx_send_verdict(cfd.queue, ntohl(nlhdr.packet_id), &inspection)
    # ======================
    # INTERFACE, NL, AND HW
    nlhdr = <nfqnl_msg_packet_hdr*>mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR])
    nft_hook = ntohl(nlhdr.hook)

    mark = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) if netlink_attrs[NFQA_MARK] else 0
    iif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) if netlink_attrs[NFQA_IFINDEX_INDEV] else 0
    oif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) if netlink_attrs[NFQA_IFINDEX_OUTDEV] else 0

    if (netlink_attrs[NFQA_HWADDR]):
        _hw = <nfqnl_msg_packet_hw*>mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR])

        m_addr = <char*>_hw.hw_addr

    hw = [INTF_ZONE_MAP[iif], INTF_ZONE_MAP[oif], m_addr[:6], time(NULL)]

    pktdata_len = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD])
    pktdata = <uint8_t*>mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD])
    # --------------------
    # IP HEADER
    # --------------------
    ip_header = <IPhdr*>pktdata
    iphdr_len = (ip_header.ver_ihl & FOUR_BIT_MASK) * 4

    # --------------------
    # PROTOCOL HEADER
    # --------------------
    # tcp/udp will reassign the pointer to their header data
    if (ip_header.protocol != IPPROTO_ICMP):
        proto_header = <Protohdr*>&pktdata[iphdr_len]

    # --------------------
    # DIRECTION SET
    # --------------------
    direction = OUTBOUND if hw.in_zone != WAN_IN else INBOUND

    # SETTING RULE TABLES
    if (not mark):
        fw_sections = [0, SYSTEM_RANGE_MAX] if not oif else [SYSTEM_RANGE_MAX, RULE_RANGE_MAX]

    elif (nft_hook == NF_IP_PRE_ROUTING):
        fw_sections = [RULE_RANGE_MAX, NAT_PRE_RANGE_MAX]

    elif (nft_hook == NF_IP_POST_ROUTING):
        fw_sections = [NAT_PRE_RANGE_MAX, NAT_POST_RANGE_MAX]

    # ===================================
    # LOCKING ACCESS TO FIREWALL RULES
    # prevents the manager thread from updating firewall rules during packet inspection
    pthread_mutex_lock(&FWrulelock)
    # --------------------
    # FIREWALL RULE CHECK
    # --------------------
    inspection = cfirewall_inspect(&hw, ip_header, proto_header, direction, fw_sections)

    pthread_mutex_unlock(&FWrulelock)
    # UNLOCKING ACCESS TO FIREWALL RULES
    # ===================================

    # --------------------
    # NFQUEUE VERDICT
    # --------------------
    # only SYSTEM RULES will have cfirewall invoke action directly
    if (fw_sections.end != SYSTEM_RANGE_MAX):

        # if PROXY_BYPASS, cfirewall will invoke the rule action without forwarding to another queue.
        # if not PROXY_BYPASS, forward to ip proxy regardless of action for geolocation log or IPS
        if (not PROXY_BYPASS):
            inspection.action = IP_PROXY << TWO_BYTES | NF_QUEUE

    dnx_send_verdict(cfd.queue, ntohl(nlhdr.packet_id), &inspection)

    # verdict is being used to eval whether the packet matched a system rule.
    # a 0 verdict infers this also, but for ease of reading, ill use both.
    if (VERBOSE):
        pkt_print(&hw, ip_header, proto_header)

        printf('[C/packet] system->%u, action->%u, ', nft_hook, inspection.action)
        printf('ipp->%u, dns->%u, ips->%u\n',
               inspection.mark >> 12 & 15, inspection.mark >> 16 & 15, inspection.mark >> 20 & 15)
        printf(<char*>'=====================================================================\n')

    # return heirarchy -> libnfnetlink.c >> libnetfiler_queue >> CFirewall._run.
    # < 0 vals are errors, but return is being ignored by CFirewall._run.
    return Py_OK

cdef inline InspectionResults cfirewall_inspect(
        HWinfo *hw, IPhdr *ip_header, Protohdr *proto_header, uint8_t direction, srange fw_sections) nogil:

    cdef:
        FWrule rule
        size_t section_num, rule_num

        uint32_t rule_src_protocol, rule_dst_protocol # <16 bit proto | 16 bit port>

        # normalizing src/dst ip in header to host order
        uint32_t iph_src_ip = ntohl(ip_header.saddr)
        uint32_t iph_dst_ip = ntohl(ip_header.daddr)

        # ip address to country code
        uint8_t src_country = GEOLOCATION.search(iph_src_ip & MSB, iph_src_ip & LSB)
        uint8_t dst_country = GEOLOCATION.search(iph_dst_ip & MSB, iph_dst_ip & LSB)

        # value used by ip proxy which is normalized and always represents the external ip address
        uint16_t tracked_geo = src_country if direction == INBOUND else dst_country

        # return struct (section | action | mark)
        InspectionResults results

        # security profile loop
        size_t i, idx

    for section_num in range(fw_sections.start, fw_sections.end):

        current_rule_count = CUR_RULE_COUNTS[section_num]
        if (current_rule_count < 1): # in case there becomes a purpose for < 0 values
            continue

        for rule_num in range(current_rule_count):

            rule = firewall_rules[section_num][rule_num]

            # NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (not rule.enabled):
                continue

            # ------------------------------------------------------------------
            # ZONE MATCHING
            # ------------------------------------------------------------------
            # currently tied to interface and designated LAN, WAN, DMZ
            if not zone_match(&rule.s_zones, hw.in_zone):
                continue

            if not zone_match(&rule.d_zones, hw.out_zone):
                continue

            # ------------------------------------------------------------------
            # GEOLOCATION or IP/NETMASK
            # ------------------------------------------------------------------
            if not network_match(&rule.s_networks, iph_src_ip, src_country):
                continue

            if not network_match(&rule.d_networks, iph_dst_ip, dst_country):
                continue

            # ------------------------------------------------------------------
            # PROTOCOL / PORT
            # ------------------------------------------------------------------
            if not service_match(&rule.s_services, ip_header.protocol, ntohs(proto_header.s_port)):
                continue

            if not service_match(&rule.d_services, ip_header.protocol, ntohs(proto_header.d_port)):
                continue

            # ------------------------------------------------------------------
            # MATCH ACTION | return rule options
            # ------------------------------------------------------------------
            # drop will inherently forward to the ip proxy for geo inspection and local dns records.
            results.fw_section = section_num
            results.action = rule.action
            results.mark = tracked_geo << FOUR_BITS | direction << TWO_BITS | rule.action

            idx = 0
            for i in range(PROFILE_START, PROFILE_STOP, PROFILE_SIZE):
                results.mark |= rule.sec_profiles[idx] << i
                idx += 1

            return results

    # ------------------------------------------------------------------
    # DEFAULT ACTION
    # ------------------------------------------------------------------
    results.fw_section = NO_SECTION
    results.action = DROP
    results.mark = tracked_geo << FOUR_BITS | direction << TWO_BITS | DROP

    return results

cdef ssize_t dnx_send_verdict(uint32_t queue_num, uint32_t pktid, InspectionResults *inspection) nogil:

    cdef:
        uint8_t buf[MNL_SOCKET_BUFFER_SIZE]
        nlmsghdr *nlh
        nlattr *nest

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num)

    nfq_nlmsg_verdict_put(nlh, pktid, inspection.action)
    nfq_nlmsg_verdict_put_mark(nlh, inspection.mark)

    return mnl_socket_sendto(nl, nlh, nlh.nlmsg_len)

# ==================================
# Firewall Matching Functions
# ==================================
# attacker blocklist membership test
cdef inline bint in_blocklist(uint32_t src_host) nogil:

    cdef:
        size_t   i
        uint32_t blocked_host

    pthread_mutex_lock(&FWblocklistlock)

    for i in range(FW_MAX_ATTACKERS):
   
        blocked_host = ATTACKER_BLOCKLIST[i]  

        if (blocked_host == END_OF_ARRAY):
            break

        elif (blocked_host == src_host):
            return MATCH

    pthread_mutex_unlock(&FWblocklistlock)

    return NO_MATCH

# generic function for src/dst zone matching
cdef inline bint zone_match(ZoneArray *zone_array, uint8_t pkt_zone) nogil:

    cdef size_t i

    # any zone def is a guaranteed match
    if (zone_array.objects[0] == ANY_ZONE):
        return MATCH

    # iterating over all zones defined in the rule
    for i in range(zone_array.len):

        # continue on no match, blocking return
        if (pkt_zone != zone_array.objects[i]):
            continue

        # zone match
        return MATCH

    # default action
    return NO_MATCH

# generic function for source OR destination network obj matching
cdef inline bint network_match(NetworkArray *net_array, uint32_t iph_ip, uint8_t country) nogil:

    cdef:
        size_t  i
        Network *net

    if (VERBOSE):
        printf(<char*>'checking ip->%u, country->%u\n', iph_ip, country)

    for i in range(net_array.len):

        net = &net_array.objects[i]

        # --------------------
        # TYPE -> HOST (1)
        # --------------------
        if (net.type == IP_ADDRESS):

            if (iph_ip == net.netid):
                return MATCH

        # --------------------
        # TYPE -> NETWORK (2)
        # --------------------
        elif (net.type == IP_NETWORK):

            # using the rule defs netmask to floor the packet ip and matching netid
            if (iph_ip & net.netmask == net.netid):
                return MATCH

        # --------------------
        # TYPE -> GEO (6)
        # --------------------
        elif (net.type == IP_GEO):

            if (country == net.netid):
                return MATCH

    if (VERBOSE):
        printf(<char*>'no match ip->%u, country->%u\n', iph_ip, country)

    # default action
    return NO_MATCH

# generic function that can handle source OR destination proto/port matching
cdef inline bint service_match(ServiceArray *svc_array, uint16_t pkt_protocol, uint16_t pkt_port) nogil:

    cdef:
        size_t i
        Service         *svc
        ServiceList     *svc_list
        ServiceObject   *svc_object

    if (VERBOSE):
        printf(<char*>'packet protocol->%u, port->%u\n', pkt_protocol, pkt_port)

    for i in range(svc_array.len):
        svc_object = &svc_array.objects[i]
        # --------------------
        # TYPE -> SOLO (1)
        # --------------------
        if (svc_object.type == SVC_SOLO):

            svc = &svc_object.service.object
            if (pkt_protocol == svc.protocol or svc.protocol == ANY_PROTOCOL):

                if (pkt_port == svc.start_port):
                    return MATCH

        # --------------------
        # TYPE -> RANGE (2)
        # --------------------
        elif (svc_object.type == SVC_RANGE):

            svc = &svc_object.service.object
            if (pkt_protocol == svc.protocol or svc.protocol == ANY_PROTOCOL):

                if (svc.start_port <= pkt_port <= svc.end_port):
                    return MATCH

        # --------------------
        # TYPE -> LIST (3)
        # --------------------
        else:
            svc_list = &svc_object.service.list
            for i in range(svc_list.len):

                svc = &svc_list.objects[i]
                if (pkt_protocol == svc.protocol or svc.protocol == ANY_PROTOCOL):

                    if (svc.start_port <= pkt_port <= svc.end_port):
                        return MATCH

    if (VERBOSE):
        printf(<char*>'no match for packet protocol->%u, port->%u\n', pkt_protocol, pkt_port)

    # default action
    return NO_MATCH

# ==================================
# PRINT FUNCTIONS
# ==================================
# NOTE: the integer casts are to clamp the struct fields to standard because they are implemented as fast_ints
cdef inline void pkt_print(HWinfo *hw, IPhdr *ip_header, Protohdr *proto_header) with gil:
    '''nested struct print of the passed in references using Python pretty printer.

    the GIL will be acquired before executing the print and released on return.
    the byte order will be big endian/ network so the integer outputs will be backwards on Linux.
    '''
    ppt(hw[0])
    ppt(ip_header[0])
    ppt(proto_header[0])

cdef inline void rule_print(FWrule *rule) with gil:
    '''nested struct print of the passed in reference using Python pretty printer.
    
    the GIL will be acquired before executing the print and released on return.
    the byte order will be big endian/ network so the integer outputs will be backwards on Linux.
    '''
    ppt(rule[0])

# NOTE: consider making this a union
cdef inline void obj_print(int name, void *obj) nogil:

    cdef:
        Network     *net_obj
        Service     *svc_obj

    if (name == NETWORK):
        net_obj = <Network*>obj

        printf('net_obj, id->%u, mask->%u\n', <uint32_t>net_obj.netid, <uint32_t>net_obj.netmask)

    elif (name == SERVICE):
        svc_obj = <Service*>obj

        printf('svc_obj, protocol->%u, port->(%u, %u)\n',
               <uint8_t>svc_obj.protocol, <uint16_t>svc_obj.start_port, <uint16_t>svc_obj.end_port)

# ==================================
# C CONVERSION / INIT FUNCTIONS
# ==================================
DEF NFQ_BUF_SIZE = 2048

cdef void process_traffic(cfdata *cfd) nogil:

    cdef:
        char        packet_buf[NFQ_BUF_SIZE]
        ssize_t     dlen

        uint32_t    portid = mnl_socket_get_portid(nl)

    printf(<char*>'<ready to process traffic>\n')

    while True:
        dlen = mnl_socket_recvfrom(nl, <void*>packet_buf, NFQ_BUF_SIZE)
        if (dlen == -1):
            return ERR

        ret = mnl_cb_run(<void*>packet_buf, dlen, 0, portid, cfirewall_recv, cfd)
        if (ret < 0):
            return ERR

cdef void set_FWrule(size_t ruleset, dict rule, size_t pos):

    cdef:
        size_t i, ix, svc_list_len

        Service          *svc
        ServiceList      *svc_list
        ServiceObject    *svc_object

        FWrule *fw_rule = &firewall_rules[ruleset][pos]

    fw_rule.enabled = <bint>rule['enabled']

    # ===========
    # SOURCE
    # ===========
    fw_rule.s_zones.len = <size_t>len(rule['src_zone'])
    for i in range(fw_rule.s_zones.len):
        fw_rule.s_zones.objects[i] = <uint_fast8_t>rule['src_zone'][i]

    fw_rule.s_networks.len = <size_t>len(rule['src_network'])
    for i in range(fw_rule.s_networks.len):
        fw_rule.s_networks.objects[i].type    = <uint_fast8_t> rule['src_network'][i][0]
        fw_rule.s_networks.objects[i].netid   = <uint_fast32_t>rule['src_network'][i][1]
        fw_rule.s_networks.objects[i].netmask = <uint_fast32_t>rule['src_network'][i][2]

    # -----------------------
    # SOURCE SERVICE OBJECTS
    # -----------------------
    fw_rule.s_services.len = <size_t>len(rule['src_service'])
    for i in range(fw_rule.s_services.len):
        svc_object = &fw_rule.s_services.objects[i]

        svc_object.type = <uint_fast8_t>rule['src_service'][i][0]
        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        if (svc_object.type != SVC_LIST):
            svc = &svc_object.service.object

            svc.protocol   = <uint_fast16_t>rule['src_service'][i][1]
            svc.start_port = <uint_fast16_t>rule['src_service'][i][2]
            svc.end_port   = <uint_fast16_t>rule['src_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            svc_list = &svc_object.service.list

            svc_list.len = <size_t>(len(rule['src_service'][i]) - 1)
            for ix in range(svc_list.len):
                svc = &svc_list.objects[ix]
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                svc.protocol   = <uint_fast16_t>rule['src_service'][i][ix + 1][0]
                svc.start_port = <uint_fast16_t>rule['src_service'][i][ix + 1][1]
                svc.end_port   = <uint_fast16_t>rule['src_service'][i][ix + 1][2]

    # ===========
    # DESTINATION
    # ===========
    fw_rule.d_zones.len = <size_t>len(rule['dst_zone'])
    for i in range(fw_rule.d_zones.len):
        fw_rule.d_zones.objects[i] = <uint_fast8_t>rule['dst_zone'][i]

    fw_rule.d_networks.len = <size_t>len(rule['dst_network'])
    for i in range(fw_rule.d_networks.len):
        fw_rule.d_networks.objects[i].type    = <uint_fast8_t> rule['dst_network'][i][0]
        fw_rule.d_networks.objects[i].netid   = <uint_fast32_t>rule['dst_network'][i][1]
        fw_rule.d_networks.objects[i].netmask = <uint_fast32_t>rule['dst_network'][i][2]

    # -----------------------
    # SOURCE SERVICE OBJECTS
    # -----------------------
    fw_rule.d_services.len = <size_t>len(rule['dst_service'])
    for i in range(fw_rule.d_services.len):
        svc_object = &fw_rule.d_services.objects[i]

        svc_object.type = <uint_fast8_t>rule['dst_service'][i][0]
        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        if (svc_object.type != SVC_LIST):
            svc = &svc_object.service.object

            svc.protocol   = <uint_fast16_t>rule['dst_service'][i][1]
            svc.start_port = <uint_fast16_t>rule['dst_service'][i][2]
            svc.end_port   = <uint_fast16_t>rule['dst_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            svc_list = &svc_object.service.list

            svc_list.len = <size_t>(len(rule['dst_service'][i]) - 1)
            for ix in range(svc_list.len):
                svc = &svc_list.objects[ix]
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                svc.protocol   = <uint_fast16_t>rule['dst_service'][i][ix + 1][0]
                svc.start_port = <uint_fast16_t>rule['dst_service'][i][ix + 1][1]
                svc.end_port   = <uint_fast16_t>rule['dst_service'][i][ix + 1][2]

    # --------------------------
    # RULE PROFILES AND ACTIONS
    # --------------------------
    fw_rule.action = <uint_fast8_t>rule['action']
    fw_rule.log    = <uint_fast8_t>rule['log']

    fw_rule.sec_profiles[0] = <uint_fast8_t>rule['ipp_profile']
    fw_rule.sec_profiles[1] = <uint_fast8_t>rule['dns_profile']
    fw_rule.sec_profiles[2] = <uint_fast8_t>rule['ips_profile']

    if (VERBOSE and ruleset >= 1):
        ppt(fw_rule[0])


# ===================================
# C EXTENSION - Python Comm Pipeline
# ===================================
# NETLINK SOCKET - cfirewall <> kernel
cdef mnl_socket *nl
# =====================================

cdef class CFirewall:

    def set_options(s, int bypass, int verbose):
        global PROXY_BYPASS, VERBOSE

        PROXY_BYPASS = <bint>bypass
        VERBOSE = <bint>verbose

        if (bypass):
            print('<proxy bypass enable>')

        if (verbose):
            print('<verbose console logging enabled>')

    def api_set(s, unicode sock_path):

        s.sock_path = sock_path.encode('utf-8')
        s.api_fd = api_open(s.sock_path)

    def api_run(s):
        print('<releasing GIL>')
        # release gil and never look back.
        with nogil:
            process_api(s.h)

    def nf_run(s):
        '''calls internal C run method to engage nfqueue processes.

        this call will run forever, but will release the GIL prior to entering C and never try to reacquire it.
        '''
        print('<releasing GIL>')
        # release gil and never look back.
        with nogil:
            process_traffic(&s.cfd)

    def nf_set(s, uint16_t queue_num):

        global nl

        cdef:
            char *mnl_buf
            nlmsghdr *nlh

            int ret = 1
            # largest possible packet payload, plus netlink data overhead
            size_t sizeof_buf = <size_t>(65535 + (MNL_SOCKET_BUFFER_SIZE / 2))

        s.cfd.queue = queue_num

        mnl_buf = <char*>malloc(sizeof_buf)

        nl = mnl_socket_open(NETLINK_NETFILTER)
        if (nl == NULL):
            return Py_ERR

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0):
            return Py_ERR

        # ---------------
        # BINDING SOCKET
        nlh = nfq_nlmsg_put(mnl_buf, NFQNL_MSG_CONFIG, queue_num)
        nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND)

        if (mnl_socket_sendto(nl, nlh, nlh.nlmsg_len) < 0):
            return Py_ERR

        # ---------------
        # ATTR FLAGS
        nlh = nfq_nlmsg_put(mnl_buf, NFQNL_MSG_CONFIG, queue_num)
        nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 65535)

        # DISABLE PACKET NORMALIZATION (REASSEMBLE FRAGMENTS)
        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO))
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO))

        # CONNECTION STATE (NEW, ESTABLISHED, ETC)
        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_CONNTRACK))
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_CONNTRACK))

        if (mnl_socket_sendto(nl, nlh, nlh.nlmsg_len) < 0):
            return Py_ERR

        # ENOBUFS is signalled to userspace when packets were lost on the kernel side.
        # We don't care, so we can turn it off.
        mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, <void*>&ret, sizeof(int))

        free(mnl_buf)

        return Py_OK

    def nf_break(s):
        mnl_socket_close(nl)

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil:
        '''initializes Cython Extension HashTrie for use by CFirewall.
         
        py_trie is passed through as data source and reference to function is globally assigned. MSB and LSB definitions 
        are also globally assigned.
        '''
        global GEOLOCATION, MSB, LSB

        cdef size_t trie_len = len(geolocation_trie)

        GEOLOCATION = HashTrie_Range()
        GEOLOCATION.generate_structure(geolocation_trie, trie_len)

        MSB = msb
        LSB = lsb

        return Py_OK

    cpdef int update_zones(s, PyArray zone_map) with gil:
        '''acquires FWrule lock then updates the zone values by interface index.
        
        MAX_SLOTS defined by FW_MAX_ZONE_COUNT. the GIL will be acquired before any code execution.
        '''
        cdef size_t i

        pthread_mutex_lock(&FWrulelock)
        printf(<char*>'[update/zones] acquired lock\n')

        for i in range(FW_MAX_ZONE_COUNT):
            INTF_ZONE_MAP[i] = zone_map[i]

        pthread_mutex_unlock(&FWrulelock)
        printf(<char*>'[update/zones] released lock\n')

        return Py_OK

    cpdef int update_ruleset(s, size_t ruleset, list rulelist) with gil:
        '''acquires FWrule lock then rewrites the corresponding section ruleset.
        
        the current length var will also be update while the lock is held. 
        the GIL will be acquired before any code execution.
        '''
        cdef:
            size_t  i
            dict    fw_rule
            size_t  rule_count = len(rulelist)

        pthread_mutex_lock(&FWrulelock)
        printf(<char*>'[update/ruleset] acquired lock\n')

        for i in range(rule_count):
            fw_rule = rulelist[i]

            set_FWrule(ruleset, fw_rule, i)

        # updating rule count in global tracker. this is very important in that it establishes the right side bound for
        # firewall ruleset iteration operations.
        CUR_RULE_COUNTS[ruleset] = rule_count

        pthread_mutex_unlock(&FWrulelock)
        printf(<char*>'[update/ruleset] released lock\n')

        return Py_OK
