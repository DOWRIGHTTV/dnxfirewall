#!/usr/bin/env Cython

#

from libc.stdlib cimport calloc, malloc, free
from libc.stdio cimport printf

from libc.stdint cimport uint8_t, uint16_t, uint32_t

from dnx_iptools.hash_trie.hash_trie cimport HashTrie_Range
from dnx_iptools.cprotocol_tools.cprotocol_tools cimport nullset

# from fw_api cimport api_open, process_api

# ===============================
# VERBOSE T-SHOOT ASSISTANCE
# ===============================
from pprint import PrettyPrinter
ppt = PrettyPrinter(sort_dicts=False).pprint
# ===============================

DEF FW_TABLE_COUNT = 4
DEF FW_SYSTEM_MAX_RULE_COUNT = 50
DEF FW_BEFORE_MAX_RULE_COUNT = 100
DEF FW_MAIN_MAX_RULE_COUNT   = 500
DEF FW_AFTER_MAX_RULE_COUNT  = 100

DEF FW_MAX_ATTACKERS  = 250
DEF FW_MAX_ZONE_COUNT = 16

DEF FW_SYSTEM_RANGE_START = 0
DEF FW_RULE_RANGE_START   = 1
DEF FW_RULE_RANGE_END     = 4

DEF NAT_TABLE_COUNT = 2
DEF NAT_PRE_MAX_RULE_COUNT  = 100
DEF NAT_POST_MAX_RULE_COUNT = 100

DEF NAT_PRE_TABLE  = 0
DEF NAT_POST_TABLE = 1

#DEF NAT_PREROUTE = 70
#DEF NAT_POSTROUTE = 71

DEF SECURITY_PROFILE_COUNT = 3
DEF PROFILE_SIZE  = 4  # bits
DEF PROFILE_START = 12
DEF PROFILE_STOP  = (SECURITY_PROFILE_COUNT * 4) + 8 + 1  # +1 for range

# function return values
DEF OK  = 0
DEF ERR = -1
DEF Py_OK  = 0
DEF Py_ERR = 1

DEF NETWORK = 1
DEF SERVICE = 2

# compile time def because vals are assigned by the external webui
# network object types.
DEF IP_ADDRESS = 1
DEF IP_NETWORK = 2
DEF IP_RANGE   = 3
DEF IP_GEO     = 6
# service object types.
DEF SVC_SOLO  = 1
DEF SVC_RANGE = 2
DEF SVC_LIST  = 3
DEF SVC_ICMP  = 4
# matching options
DEF ANY_ZONE     = 99
DEF NO_SECTION   = 99
DEF ANY_PROTOCOL = 0
DEF COUNTRY_NOT_DEFINED = 0

# identifies which packet field to compare
DEF SRC_MATCH = 1
DEF DST_MATCH = 2

DEF NO_MATCH = 0
DEF MATCH = 1
DEF END_OF_ARRAY = 0 # to make code more readable

# bit shifting helpers
DEF TWO_BITS    = 2
DEF FOUR_BITS   = 4
DEF ONE_BYTE    = 8
DEF TWELVE_BITS = 12
DEF TWO_BYTES   = 16

DEF TWO_BIT_MASK  = 3
DEF FOUR_BIT_MASK = 15

# nfq alias for iteration range
cdef enum: NFQA_RANGE = NFQA_MAX + 1

# cli args
cdef bint PROXY_BYPASS = 0
cdef bint VERBOSE = 0

# ================================== #
# Firewall tables access lock
# ================================== #
# Must be held to read from or make
# changes to "*firewall_tables[]"
# ---------------------------------- #
cdef:
    pthread_mutex_t     FWtableslock
    pthread_mutex_t    *FWlock_ptr = &FWtableslock

pthread_mutex_init(FWlock_ptr, NULL)

# ================================== #
# NAT tables access lock
# ================================== #
# Must be held to read from or make
# changes to "*firewall_tables[]"
# ---------------------------------- #
cdef:
    pthread_mutex_t     NATtableslock
    pthread_mutex_t    *NATlock_ptr = &NATtableslock

pthread_mutex_init(NATlock_ptr, NULL)

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
cdef struct FWtable:
    uintf16_t   len
    FWrule     *rules

cdef FWtable *firewall_tables[FW_TABLE_COUNT]

# arrays of pointers to FWrule
firewall_tables[FW_SYSTEM_RULES] = [0, <FWrule*>calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(FWrule))]
firewall_tables[FW_BEFORE_RULES] = [0, <FWrule*>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule))]
firewall_tables[FW_MAIN_RULES]   = [0, <FWrule*>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule))]
firewall_tables[FW_AFTER_RULES]  = [0, <FWrule*>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule))]

cdef struct NATtable:
    uintf16_t   len
    NATrule     *rules

# contains pointers to arrays of pointers to NATrule
cdef NATtable *nat_tables[NAT_TABLE_COUNT]

# arrays of pointers to NATrule
nat_tables[NAT_PRE_RULES]  = [0, <NATrule*>calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(NATrule))]
nat_tables[NAT_POST_RULES] = [0, <NATrule*>calloc(NAT_POST_MAX_RULE_COUNT, sizeof(NATrule))]

cdef uintf16_t *NAT_CUR_RULE_COUNTS = <uintf16_t*>calloc(NAT_TABLE_COUNT, sizeof(uintf16_t))

# stores zone(integer value) at index, which is mapped Fto if_nametoindex() (value returned from get_in/outdev)
cdef uintf16_t *INTF_ZONE_MAP = <uintf16_t*>calloc(FW_MAX_ZONE_COUNT, sizeof(uintf16_t))

# stores the active attackers set/controlled by IPS/IDS
cdef uint32_t *ATTACKER_BLOCKLIST = <uint32_t*>calloc(FW_MAX_ATTACKERS, sizeof(uint32_t))

cdef uint32_t BLOCKLIST_CUR_SIZE = 0 # if we decide to track size for appends

# ==================================
# PRIMARY FIREWALL LOGIC
# ==================================
cdef int cfirewall_recv(const nlmsghdr *nlh, void *data) nogil:

    cdef:
        cfdata     *cfd = <cfdata*>data
        nlattr     *netlink_attrs[NFQA_RANGE]

        nl_pkt_hdr *nlhdr
        nl_pkt_hw  *_hw

        uint32_t    _iif, _oif, _mark, ct_info

        dnx_pktb    pkt

        srange      fw_tables

    nullset(<void**>netlink_attrs, NFQA_RANGE)
    nfq_nlmsg_parse(nlh, netlink_attrs)

    nlhdr = <nl_pkt_hdr*>mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR])
    # ======================
    # CONNTRACK
    # this should be checked as soon as feasibly possible for performance.
    # this will be used to allow for stateless inspection policies later.
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]))
    if (ct_info != IP_CT_NEW):
        dnx_send_verdict_fast(cfd.queue, ntohl(nlhdr.packet_id), NF_ACCEPT)

        return OK
    # ======================
    # INTERFACE, NL, AND HW
    _mark = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) if netlink_attrs[NFQA_MARK] else 0
    _iif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) if netlink_attrs[NFQA_IFINDEX_INDEV] else 0
    _oif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) if netlink_attrs[NFQA_IFINDEX_OUTDEV] else 0

    if (netlink_attrs[NFQA_HWADDR]):
        _hw = <nl_pkt_hw*>mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR])

        pkt.hw.m_addr = <char*>_hw.hw_addr

    pkt.hw.timestamp = time(NULL)
    pkt.hw.in_zone   = INTF_ZONE_MAP[_iif]
    pkt.hw.out_zone  = INTF_ZONE_MAP[_oif]

    # ======================
    # PACKET DATA / LEN
    pkt.data = <uint8_t*>mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD])
    pkt.tlen = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD])
    # ======================
    # FW TABLE ASSIGNMENT
    # ordered by system priority
    if (ntohl(nlhdr.hook) == NF_IP_FORWARD):
        fw_tables = [FW_RULE_RANGE_START, FW_RULE_RANGE_END]

    elif (ntohl(nlhdr.hook) == NF_IP_LOCAL_IN):
        fw_tables = [FW_SYSTEM_RANGE_START, FW_RULE_RANGE_END]

    # ===================================
    # LOCKING ACCESS TO FIREWALL RULES
    # prevents the manager thread from updating firewall rules during packet inspection
    pthread_mutex_lock(FWlock_ptr)
    # --------------------
    cfirewall_inspect(&fw_tables, &pkt)
    # --------------------
    pthread_mutex_unlock(FWlock_ptr)
    # UNLOCKING ACCESS TO FIREWALL RULES
    # ===================================

    # --------------------
    # NFQUEUE VERDICT
    # --------------------
    # only SYSTEM RULES will have cfirewall invoke action directly
    if (fw_tables.start != FW_SYSTEM_RANGE_START):

        # if PROXY_BYPASS, cfirewall will invoke the rule action without forwarding to another queue.
        # if not PROXY_BYPASS, forward to ip proxy regardless of action for geolocation log or IPS
        if (not PROXY_BYPASS):
            pkt.action = IP_PROXY << TWO_BYTES | NF_QUEUE

    dnx_send_verdict(cfd.queue, ntohl(nlhdr.packet_id), &pkt)

    # verdict is being used to eval whether the packet matched a system rule.
    # a 0 verdict infers this also, but for ease of reading, ill use both.
    if (VERBOSE):
        # pkt_print(&hw, ip_header, proto_header)

        printf('[C/packet] hook->%u, mark->%u, action->%u, ', ntohl(nlhdr.hook), _mark, pkt.action)
        printf('ipp->%u, dns->%u, ips->%u\n', pkt.mark >> 12 & 15, pkt.mark >> 16 & 15, pkt.mark >> 20 & 15)
        printf('=====================================================================\n')

    # return heirarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    # < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK

cdef inline void cfirewall_inspect(srange *fw_tables, dnx_pktb *pkt) nogil:

    parse_pkt_headers(pkt)

    cdef:
        FWrule     *rule_table
        FWrule     *rule
        uintf16_t   table_idx, rule_idx

        # normalizing src/dst ip in header to host order
        uint32_t    iph_src_ip = ntohl(pkt.iphdr.saddr)
        uint32_t    iph_dst_ip = ntohl(pkt.iphdr.daddr)

        # ip address to country code
        uint8_t     src_country = GEOLOCATION.search(iph_src_ip & MSB, iph_src_ip & LSB)
        uint8_t     dst_country = GEOLOCATION.search(iph_dst_ip & MSB, iph_dst_ip & LSB)

        # general direction of the packet and ip addr normalized to always be the external host/ip
        uint8_t     direction = OUTBOUND if pkt.hw.in_zone != WAN_IN else INBOUND
        uint16_t    tracked_geo = src_country if direction == INBOUND else dst_country

        # security profile loop
        uintf8_t    i, idx

    for table_idx in range(fw_tables.start, fw_tables.end):

        firewall_table = firewall_tables[table_idx]

        if (not firewall_table.len):
            continue

        for rule_idx in range(firewall_table.len):

            rule = &rule_table[rule_idx]

            # NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (not rule.enabled):
                continue

            # ------------------------------------------------------------------
            # ZONE MATCHING
            # ------------------------------------------------------------------
            # currently tied to interface and designated LAN, WAN, DMZ
            if not zone_match(&rule.s_zones, pkt.hw.in_zone):
                continue

            if not zone_match(&rule.d_zones, pkt.hw.out_zone):
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
            if not service_match(&rule.s_services, pkt, SRC_MATCH):
                continue

            if not service_match(&rule.d_services, pkt, DST_MATCH):
                continue

            # ------------------------------------------------------------------
            # MATCH ACTION | return rule options
            # ------------------------------------------------------------------
            # drop will inherently forward to the ip proxy for geo inspection and local dns records.
            pkt.fw_table = table_idx
            pkt.rule_num = rule_num # if logging, this needs to be +1
            pkt.action   = rule.action
            pkt.mark     = tracked_geo << FOUR_BITS | direction << TWO_BITS | rule.action

            idx = 0
            for i in range(PROFILE_START, PROFILE_STOP, PROFILE_SIZE):
                pkt.mark |= rule.sec_profiles[idx] << i
                idx += 1

            return

    # ------------------------------------------------------------------
    # DEFAULT ACTION
    # ------------------------------------------------------------------
    pkt.fw_section = NO_SECTION
    pkt.action     = DNX_DROP
    pkt.mark       = tracked_geo << FOUR_BITS | direction << TWO_BITS | DNX_DROP

# ==================================
# PRIMARY NAT LOGIC
# ==================================
cdef int cnat_recv(const nlmsghdr *nlh, void *data) nogil:

    cdef:
        cfdata     *cfd = <cfdata*>data
        nlattr     *netlink_attrs[NFQA_RANGE]

        nl_pkt_hdr *nlhdr

        uint32_t    _iif, _oif, _mark

        int         table_idx
        uintf16_t   rule_count

        dnx_pktb    pkt

    nullset(<void**>netlink_attrs, NFQA_RANGE)
    nfq_nlmsg_parse(nlh, netlink_attrs)

    nlhdr = <nl_pkt_hdr*>mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR])

    if (ntohl(nlhdr.hook) == NF_IP_POST_ROUTING):
        table_idx = NAT_POST_TABLE

    elif (ntohl(nlhdr.hook) == NF_IP_PRE_ROUTING):
        table_idx = NAT_PRE_TABLE

    # ======================
    # NO NAT QUICK PATH
    rule_count = NAT_CUR_RULE_COUNTS[table_idx]
    if (not rule_count):
        dnx_send_verdict_fast(cfd.queue, ntohl(nlhdr.packet_id), NF_ACCEPT)

        return OK
    # ======================
    # _mark = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) if netlink_attrs[NFQA_MARK] else 0
    # _iif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) if netlink_attrs[NFQA_IFINDEX_INDEV] else 0
    # _oif  = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) if netlink_attrs[NFQA_IFINDEX_OUTDEV] else 0

    # ======================
    # PACKET DATA / LEN
    pkt.data = <uint8_t*>mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD])
    pkt.tlen = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD])
    # ===================================
    # LOCKING ACCESS TO NAT RULES
    # prevents the manager thread from updating nat rules during packet inspection
    pthread_mutex_lock(NATlock_ptr)
    # --------------------
    cnat_inspect(nat_tables[table_idx], &pkt)
    # --------------------
    pthread_mutex_unlock(NATlock_ptr)
    # UNLOCKING ACCESS TO NAT RULES
    # ===================================

    # --------------------
    # NAT / MANGLE
    # --------------------
    # NOTE: it looks like it will be better if we manually NAT the packet contents.
    # the alternative is to allocate a pktb and user the proper mangler.
    # this would auto manage the header checksums, but we would need alloc/free every time we mangle.
    # i have alot of experience with nat and checksum calculations so its probably easier and more efficient to use
    # the on stack buffer to mangle. (this is unless we need to retain a copy of the original packet)
    if (pkt.action & DNX_NAT_FLAGS):
        dnx_mangle_pkt(&pkt)

cdef inline void cnat_inspect(int table_idx, int rule_count, dnx_pktb *pkt) nogil:

    parse_pkt_headers(pkt)

    cdef:
        NATrule    *nat_table
        NATrule    *rule

        # normalizing src/dst ip in header to host order
        uint32_t    iph_src_ip = ntohl(pkt.iphdr.saddr)
        uint32_t    iph_dst_ip = ntohl(pkt.iphdr.daddr)

        # ip address to country code
        uint8_t     src_country = GEOLOCATION.search(iph_src_ip & MSB, iph_src_ip & LSB)
        uint8_t     dst_country = GEOLOCATION.search(iph_dst_ip & MSB, iph_dst_ip & LSB)

    nat_table = nat_tables[table_idx]
    for rule_idx in range(rule_count):

        rule = &nat_table[rule_idx]
        # NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
        if (not rule.enabled):
            continue

        # ------------------------------------------------------------------
        # ZONE MATCHING
        # ------------------------------------------------------------------
        # currently tied to interface and designated LAN, WAN, DMZ
        if not zone_match(rule, pkt.hw.in_zone, SRC_MATCH):
            continue

        if not zone_match(rule, pkt.hw.out_zone, DST_MATCH):
            continue

        # ------------------------------------------------------------------
        # GEOLOCATION or IP/NETMASK
        # ------------------------------------------------------------------
        if not network_match(rule, iph_src_ip, src_country, SRC_MATCH):
            continue

        if not network_match(rule, iph_dst_ip, dst_country, DST_MATCH):
            continue

        # ------------------------------------------------------------------
        # PROTOCOL / PORT
        # ------------------------------------------------------------------
        if not service_match(rule, pkt, SRC_MATCH):
            continue

        if not service_match(rule, pkt, DST_MATCH):
            continue

        # ------------------------------------------------------------------
        # MATCH ACTION | rule details
        # ------------------------------------------------------------------
        pkt.fw_table   = table_idx
        pkt.rule_num   = rule_idx # if logging, this needs to be +1
        pkt.action     = rule.action

        return

    # ------------------------------------------------------------------
    # DEFAULT ACTION
    # ------------------------------------------------------------------
    pkt.fw_section = NO_SECTION
    pkt.action     = DNX_ACCEPT

cdef inline void parse_pkt_headers(dnx_pktb *pkt) nogil:

    # initial header parse and assignment to dnx_pktb struct
    # ---------------------
    # L3 - IP HEADER
    # ---------------------
    pkt.iphdr     = <IPhdr*>pkt.data
    pkt.iphdr_len = (pkt.iphdr.ver_ihl & FOUR_BIT_MASK) * 4
    # ---------------------
    # L4 - PROTOCOL HEADER
    # ---------------------
    if (pkt.iphdr.protocol == IPPROTO_ICMP):
        pkt.protohdr.p1 = <P1*>(pkt.iphdr + 1)
    else:
        pkt.protohdr.p2 = <P2*>(pkt.iphdr + 1)


cdef inline void dnx_send_verdict_fast(uint32_t queue_num, uint32_t pktid, int action) nogil:
    cdef:
        char        buf[MNL_SOCKET_BUFFER_SIZE]
        nlmsghdr   *nlh

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num)
    nfq_nlmsg_verdict_put(nlh, pktid, action)
    mnl_socket_sendto(nl, nlh, nlh.nlmsg_len)

cdef int dnx_send_verdict(uint32_t queue_num, uint32_t pktid, dnx_pktb *pkt) nogil:

    cdef:
        char        buf[MNL_SOCKET_BUFFER_SIZE]
        nlmsghdr   *nlh

        ssize_t     ret

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num)

    nfq_nlmsg_verdict_put(nlh, pktid, pkt.action)
    nfq_nlmsg_verdict_put_mark(nlh, pkt.mark)
    if (pkt.mangled):
        nfq_nlmsg_verdict_put_pkt(nlh, pkt.data, pkt.tlen)

    ret = mnl_socket_sendto(nl, nlh, nlh.nlmsg_len)

    return ERR if ret < 0 else OK

cdef int dnx_mangle_pkt(dnx_pktb *pkt) nogil:

    # MAKE SURE WE RECALCULATE THE PROPER CHECKSUMS.
    # we can probably use the nfq checksum functions if they are publicly available, otherwise use cprotocol_tools.

    # changing dst ip and/or port pre route
    if (pkt.action & DNX_DST_NAT):
        pass

    # changing src ip and/or port post route
    elif (pkt.action & DNX_SRC_NAT):
        pass

    # changing dst ip and/or port pre route
    elif (pkt.action & DNX_FULL_NAT):
        pass

    return OK

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
cdef inline bint zone_match(FWrule *rule, uint8_t pkt_zone, int mtype) nogil:

    cdef:
        uintf8_t    i
        ZoneArray   zone_array

    # DATASET SWITCH
    if (mtype == SRC_MATCH):
        zone_array = rule.s_zones

    elif (mtype == DST_MATCH):
        zone_array = rule.d_zones

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
cdef inline bint network_match(FWrule *rule, uint32_t iph_ip, uint8_t country, int mtype) nogil:

    cdef:
        uintf8_t    i

        NetArray   *net_array
        NetObject   net

    if (VERBOSE):
        printf('checking ip->%u, country->%u\n', iph_ip, country)

    # DATASET SWITCH
    if (mtype == SRC_MATCH):
        net_array = rule.s_networks

    elif (mtype == DST_MATCH):
        net_array = rule.d_networks

    for i in range(net_array.len):

        net = net_array.objects[i]
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

            if (net.netid == country):
                return MATCH

    if (VERBOSE):
        printf('no match ip->%u, country->%u\n', iph_ip, country)

    # default action
    return NO_MATCH

# generic function that can handle source OR destination proto/port matching
cdef inline bint service_match(FWrule *rule, dnx_pktb *pkt, int mtype) nogil:

    cdef:
        uintf16_t   i

        SvcArray   *svc_array
        SvcObject   svc_object
        S2          svc
        S3          svc_list

        uint8_t         pkt_protocol = pkt.iphdr.protocol
        uint16_t        pkt_port = 0

    if (pkt_protocol == IPPROTO_ICMP):

        # inspect both icmp fields in src check, so if inspection makes it to dst src was a match.
        if (mtype == DST_MATCH):
            return MATCH

    elif (mtype == SRC_MATCH):
        svc_array = rule.s_services
        pkt_port = ntohs(pkt.protohdr.p2.s_port)

    elif (mtype == DST_MATCH):
        svc_array = rule.d_services
        pkt_port  = ntohs(pkt.protohdr.p2.d_port)

    # if (VERBOSE):
    #     printf(<char*>'packet protocol->%u, port->%u\n', pkt_protocol, pkt_port)

    for i in range(svc_array.len):
        svc_object = svc_array.objects[i]
        # --------------------
        # TYPE -> SOLO (1)
        # --------------------
        if (svc_object.type == SVC_SOLO):

            svc = svc_object.service.s2
            if (pkt_protocol != svc.protocol and svc.protocol != ANY_PROTOCOL):
                continue

            if (pkt_port == svc.start_port):
                return MATCH

        # --------------------
        # TYPE -> RANGE (2)
        # --------------------
        elif (svc_object.type == SVC_RANGE):

            svc = &svc_object.service.s2
            if (pkt_protocol != svc.protocol and svc.protocol != ANY_PROTOCOL):
                continue

            if (svc.start_port <= pkt_port <= svc.end_port):
                return MATCH

        # --------------------
        # TYPE -> LIST (3)
        # --------------------
        elif (svc_object.type == SVC_LIST):

            svc_list = svc_object.service.s3
            for i in range(svc_list.len):

                svc = svc_list.services[i]
                if (svc.protocol != pkt_protocol and svc.protocol != ANY_PROTOCOL):
                    continue

                if (svc.start_port <= pkt_port <= svc.end_port):
                    return MATCH

        # --------------------
        # TYPE -> ICMP (4)
        # --------------------
        elif (svc_object.type == SVC_ICMP):

            svc = svc_object.service.s1
            if (pkt_protocol != IPPROTO_ICMP):
                continue

            if (svc.type == pkt.protohdr.p1.type and svc.code == pkt.protohdr.p1.code):
                return MATCH

    # if (VERBOSE):
    #     printf(<char*>'no match for packet protocol->%u, port->%u\n', pkt_protocol, pkt_port)

    # default action
    return NO_MATCH

# ==================================
# PRINT FUNCTIONS
# ==================================
# NOTE: the integer casts are to clamp the struct fields to standard because they are implemented as fast_ints
# cdef inline void pkt_print(HWinfo *hw, IPhdr *ip_header, Protohdr *proto_header) with gil:
#     '''nested struct print of the passed in references using Python pretty printer.
#
#     the GIL will be acquired before executing the print and released on return.
#     the byte order will be big endian/ network so the integer outputs will be backwards on Linux.
#     '''
#     ppt(hw[0])
#     ppt(ip_header[0])
#     ppt(proto_header[0])

cdef inline void rule_print(FWrule *rule) with gil:
    '''nested struct print of the passed in reference using Python pretty printer.
    
    the GIL will be acquired before executing the print and released on return.
    the byte order will be big endian/ network so the integer outputs will be backwards on Linux.
    '''
    ppt(rule[0])

# NOTE: consider making this a union
cdef inline void obj_print(int name, void *obj) nogil:
    return

# ==================================
# C CONVERSION / INIT FUNCTIONS
# ==================================

cdef int process_traffic(cfdata *cfd) nogil:

    cdef:
        char        packet_buf[MNL_BUF_SIZE]
        ssize_t     dlen

        uint32_t    portid = mnl_socket_get_portid(nl)

    printf(<char*>'<ready to process traffic>\n')

    while True:
        dlen = mnl_socket_recvfrom(nl, <void*>packet_buf, MNL_BUF_SIZE)
        if (dlen == -1):
            return ERR

        ret = mnl_cb_run(<void*>packet_buf, dlen, 0, portid, cfirewall_recv, cfd)
        if (ret < 0):
            return ERR

cdef void set_FWrule(size_t ruleset, dict rule, size_t pos):

    cdef:
        uintf8_t        i, ix, svc_list_len
        SvcObject      *svc_object

        FWrule         *fw_rule = &firewall_tables[ruleset].rules[pos]

    fw_rule.enabled = <bint>rule['enabled']
    # ===========
    # SOURCE
    # ===========
    fw_rule.s_zones.len = <uintf8_t>len(rule['src_zone'])
    for i in range(fw_rule.s_zones.len):
        fw_rule.s_zones.objects[i] = <uintf8_t>rule['src_zone'][i]

    fw_rule.s_networks.len = <uintf8_t>len(rule['src_network'])
    for i in range(fw_rule.s_networks.len):
        fw_rule.s_networks.objects[i].type    = <uintf8_t> rule['src_network'][i][0]
        fw_rule.s_networks.objects[i].netid   = <uintf32_t>rule['src_network'][i][1]
        fw_rule.s_networks.objects[i].netmask = <uintf32_t>rule['src_network'][i][2]

    # -----------------------
    # SOURCE SERVICE OBJECTS
    # -----------------------
    fw_rule.s_services.len = <uintf8_t>len(rule['src_service'])
    for i in range(fw_rule.s_services.len):
        svc_object = &fw_rule.s_services.objects[i]

        svc_object.type = <uintf8_t>rule['src_service'][i][0]
        svc_object.type = <uintf8_t>rule['src_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (svc_object.type == SVC_ICMP):
            svc_object.service.s1.type = <uintf8_t>rule['src_service'][i][1]
            svc_object.service.s1.code = <uintf8_t>rule['src_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (svc_object.type == SVC_SOLO or svc_object.type == SVC_RANGE):
            svc_object.service.s2.protocol   = <uintf16_t>rule['src_service'][i][1]
            svc_object.service.s2.start_port = <uintf16_t>rule['src_service'][i][2]
            svc_object.service.s2.end_port   = <uintf16_t>rule['src_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            svc_object.service.s3.len = <uintf8_t>(len(rule['src_service'][i]) - 1)
            for ix in range(svc_object.service.s3.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                svc_object.service.s3.services[ix].protocol   = <uintf16_t>rule['src_service'][i][ix + 1][0]
                svc_object.service.s3.services[ix].start_port = <uintf16_t>rule['src_service'][i][ix + 1][1]
                svc_object.service.s3.services[ix].end_port   = <uintf16_t>rule['src_service'][i][ix + 1][2]

    # ===========
    # DESTINATION
    # ===========
    fw_rule.d_zones.len = <uintf8_t>len(rule['dst_zone'])
    for i in range(fw_rule.d_zones.len):
        fw_rule.d_zones.objects[i] = <uintf8_t>rule['dst_zone'][i]

    fw_rule.d_networks.len = <uintf8_t>len(rule['dst_network'])
    for i in range(fw_rule.d_networks.len):
        fw_rule.d_networks.objects[i].type    = <uintf8_t> rule['dst_network'][i][0]
        fw_rule.d_networks.objects[i].netid   = <uintf32_t>rule['dst_network'][i][1]
        fw_rule.d_networks.objects[i].netmask = <uintf32_t>rule['dst_network'][i][2]

    # -----------------------
    # DST SERVICE OBJECTS
    # -----------------------
    fw_rule.d_services.len = <uintf8_t>len(rule['dst_service'])
    for i in range(fw_rule.d_services.len):
        svc_object = &fw_rule.d_services.objects[i]

        svc_object.type = <uintf8_t>rule['dst_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (svc_object.type == SVC_ICMP):
            svc_object.service.s1.type = <uintf8_t>rule['dst_service'][i][1]
            svc_object.service.s1.code = <uintf8_t>rule['dst_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (svc_object.type == SVC_SOLO or svc_object.type == SVC_RANGE):
            svc_object.service.s2.protocol   = <uintf16_t>rule['dst_service'][i][1]
            svc_object.service.s2.start_port = <uintf16_t>rule['dst_service'][i][2]
            svc_object.service.s2.end_port   = <uintf16_t>rule['dst_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            svc_object.service.s3.len = <uintf8_t>(len(rule['dst_service'][i]) - 1)
            for ix in range(svc_object.service.s3.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                svc_object.service.s3.services[ix].protocol   = <uintf16_t>rule['dst_service'][i][ix + 1][0]
                svc_object.service.s3.services[ix].start_port = <uintf16_t>rule['dst_service'][i][ix + 1][1]
                svc_object.service.s3.services[ix].end_port   = <uintf16_t>rule['dst_service'][i][ix + 1][2]

    # --------------------------
    # RULE PROFILES AND ACTIONS
    # --------------------------
    fw_rule.action = <uintf8_t>rule['action']
    fw_rule.log    = <uintf8_t>rule['log']

    fw_rule.sec_profiles[0] = <uintf8_t>rule['ipp_profile']
    fw_rule.sec_profiles[1] = <uintf8_t>rule['dns_profile']
    fw_rule.sec_profiles[2] = <uintf8_t>rule['ips_profile']

    if (VERBOSE and ruleset >= 1):
        ppt(fw_rule[0])


# ===================================
# C EXTENSION - Python Comm Pipeline
# ===================================
# NETLINK SOCKET - cfirewall <> kernel
cdef mnl_socket *nl
# =====================================

# MNL_SOCKET_BUFFER_SIZE ~= 8192
DEF DNX_BUF_SIZE = 2048 # (will only handle packets of standard 1500 MTU)
DEF MNL_BUF_SIZE = DNX_BUF_SIZE + (8192/2)

cdef class CFirewall:

    def set_options(s, int bypass, int verbose):
        global PROXY_BYPASS, VERBOSE

        PROXY_BYPASS = <bint>bypass
        VERBOSE = <bint>verbose

        if (bypass):
            print('<proxy bypass enable>')

        if (verbose):
            print('<verbose console logging enabled>')

    # def api_set(s, unicode sock_path):
    #
    #     cdef:
    #         bytes   _sock_path = sock_path.encode('utf-8')
    #
    #     s.sock_path = <char*>_sock_path
    #     s.api_fd = api_open(s.sock_path)

    # def api_run(s):
    #     print('<releasing GIL>')
    #     # release gil and never look back.
    #     #with nogil:
    #     process_api(s.api_fd)

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
        s.cfd.queue = queue_num

        cdef:
            char        mnl_buf[MNL_BUF_SIZE]
            nlmsghdr   *nlh

            int         ret = 1

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
        nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, DNX_BUF_SIZE)

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

        return Py_OK

    def nf_break(s):
        mnl_socket_close(nl)

    cpdef int prepare_geolocation(s, list geolocation_trie, uint32_t msb, uint32_t lsb) with gil:
        '''initializes Cython Extension HashTrie for use by CFirewall.
         
        py_trie is passed through as data source and reference to function is globally assigned.
        MSB and LSB definitions are also globally assigned.
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
        
        MAX_SLOTS defined by FW_MAX_ZONE_COUNT.
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef uintf16_t  i

        pthread_mutex_lock(&FWrulelock)
        print('[update/zones] acquired lock')

        for i in range(FW_MAX_ZONE_COUNT):
            INTF_ZONE_MAP[i] = zone_map[i]

        pthread_mutex_unlock(&FWrulelock)
        print('[update/zones] released lock')

        return Py_OK

    cpdef int update_ruleset(s, size_t table_idx, list rulelist) with gil:
        '''acquires FWrule lock then rewrites the corresponding section ruleset.
        
        the current length var will also be update while the lock is held. 
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            uintf16_t   i
            dict        fw_rule
            size_t      rule_count = len(rulelist)

        pthread_mutex_lock(&FWrulelock)
        print('[update/ruleset] acquired lock')

        for i in range(rule_count):
            fw_rule = rulelist[i]

            set_FWrule(table_idx, fw_rule, i)

        # updating rule count in global tracker.
        # this is important to establish iter bounds during inspection.
        firewall_tables[table_idx] = rule_count

        pthread_mutex_unlock(&FWrulelock)
        print('[update/ruleset] released lock')

        return Py_OK
