#!/usr/bin/env Cython

#from libc.stdlib cimport calloc, malloc, free
from libc.string cimport memset
from libc.stdio cimport printf

from libc.stdint cimport uint8_t, uint16_t, uint32_t

from dnx_iptools.hash_trie.hash_trie cimport HashTrie_Range

# from fw_api cimport api_open, process_api

# ===============================
# VERBOSE T-SHOOT ASSISTANCE
# ===============================
from pprint import PrettyPrinter
ppt = PrettyPrinter(sort_dicts=False).pprint
# ===============================

DEF FW_MAX_ATTACKERS  = 250

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
DEF INV_IP_ADDRESS = 11
DEF INV_IP_NETWORK = 12
DEF INV_IP_RANGE   = 13
DEF INV_IP_GEO     = 16

# service object types.
DEF SVC_SOLO  = 1
DEF SVC_RANGE = 2
DEF SVC_LIST  = 3
DEF SVC_ICMP  = 4

# DEF NO_MATCH = 0
# DEF MATCH = 1
# DEF END_OF_ARRAY = 0 # to make code more readable

# Blocked list access lock
# ----------------------------------
# cdef pthread_mutex_t FWblocklistlock

# pthread_mutex_init(&FWblocklistlock, NULL)

# ================================== #
# Geolocation definitions
# ================================== #
cdef HashTrie_Range GEOLOCATION

# stores the active attackers set/controlled by IPS/IDS
# cdef uint32_t *ATTACKER_BLOCKLIST = <uint32_t*>calloc(FW_MAX_ATTACKERS, sizeof(uint32_t))

# cdef uint32_t BLOCKLIST_CUR_SIZE = 0 # if we decide to track size for appends

# MNL_SOCKET_BUFFER_SIZE ~= 8192
DEF DNX_BUF_SIZE = 2048  # (will only handle packets of standard 1500 MTU)
DEF MNL_BUF_SIZE = 6144  # DNX_BUF_SIZE + (8192 / 2)

DEF QFIREWALL = 0
DEF QNAT      = 1

# ===================================
# C EXTENSION - Python Comm Pipeline
# ===================================
# NETLINK SOCKET - cfirewall <> kernel
def nl_open():
    global nl

    nl = mnl_socket_open(NETLINK_NETFILTER)
    if (nl == NULL):
        return Py_ERR

    return Py_OK

def nl_bind():
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0):
        return Py_ERR

    return Py_OK

def nl_break():
    mnl_socket_close(nl)

    return Py_OK

# =====================================
# GEOLOCATION INITIALIZATION
# =====================================
def initialize_geolocation(list hash_trie, uint32_t msb, uint32_t lsb):
    '''initializes Cython Extension HashTrie for use by CFirewall.

    py_trie is passed through as a data source and the reference to the search function is globally assigned.
    MSB and LSB definitions are also globally assigned.
    '''
    global GEOLOCATION, MSB, LSB

    cdef size_t trie_len = len(hash_trie)

    GEOLOCATION = HashTrie_Range()
    GEOLOCATION.generate_structure(hash_trie, trie_len)

    # lazy way to give geo_search reference to inspection handlers.
    cfds[0].geolocation = <void*>GEOLOCATION
    cfds[1].geolocation = <void*>GEOLOCATION

    MSB = msb
    LSB = lsb

    return Py_OK

# =====================================
# MAIN QUEUE LOOP
# =====================================
cdef int process_traffic(cfdata *cfd) nogil:

    cdef:
        char        packet_buf[MNL_BUF_SIZE]
        intf16_t    dlen, ret

        uint32_t    portid = mnl_socket_get_portid(nl)

    printf(<char*>'<ready to process traffic>\n')

    while True:
        dlen = mnl_socket_recvfrom(nl, <void*>packet_buf, MNL_BUF_SIZE)
        if (dlen == -1):
            return ERR

        ret = mnl_cb_run(<void*>packet_buf, dlen, 0, portid, cfd.queue_cb, <void*>cfd)
        if (ret < 0):
            return ERR


# =====================================
# CALLBACK STRUCTURES + TABLE INIT
# =====================================
cdef cfdata cfds[2]

cfds[0].queue_cb = firewall_recv
cfds[1].queue_cb = nat_recv

firewall_init()
nat_init()

# ===================================
# C Extension
# ===================================
cdef class CFirewall:

    # TODO: make this work on a per "module" basis. NAT vs FIREWALL.
    #   also provide a global argument option for these.
    #   FW instance will be responsible for settings these globally for the time being.
    def set_options(s, int bypass, int verbose, int verbose2):
        global PROXY_BYPASS, VERBOSE, VERBOSE2

        PROXY_BYPASS = <bool>bypass
        VERBOSE = <bool>verbose
        VERBOSE2 = <bool>verbose2

        if (bypass):
            print('<proxy bypass enable>')

        if (verbose):
            print('<verbose console logging enabled>')

        # keeping this independant from verbose so they are not tethered
        if (verbose2):
            print('<verbose2 console logging enabled>')

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
            process_traffic(&cfds[s.queue_type])

    def nf_set(s, uint16_t queue_num, uint8_t queue_type):

        s.queue_type = queue_type
        cfds[queue_type].queue = queue_num

        cdef:
            char        mnl_buf[MNL_BUF_SIZE]
            nlmsghdr   *nlh

            int         ret = 1

        # ---------------
        # BINDING QUEUE
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

    def update_zones(s, PyArray zone_map):
        '''acquires FWrule lock then updates the zone values by interface index.

        MAX_SLOTS defined by FW_MAX_ZONE_COUNT.
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            intf16_t    idx
            uintf8_t   temp_map[FW_MAX_ZONES]

        for idx in range(FW_MAX_ZONES):
            temp_map[idx] = zone_map[idx]

        firewall_push_zones(temp_map)

        return Py_OK

    def update_rules(s, uintf8_t table_type, uintf8_t table_idx, list rulelist):

        if (table_type == 0):
            return s._update_firewall_rules(table_idx, rulelist)

        elif (table_type == 1):
            return s._update_nat_rules(table_idx, rulelist)

        return Py_ERR

    def _update_firewall_rules(s, uintf8_t table_idx, list rulelist):
        '''acquires FWrule lock then rewrites the corresponding section ruleset.

        the current length var will also be update while the lock is held. 
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            uintf16_t   rule_idx, rule_count = len(rulelist)
            dict        fw_rule

        for rule_idx in range(rule_count):
            fw_rule = rulelist[rule_idx]

            set_FWrule(table_idx, rule_idx, fw_rule)

        # updating rule count in global tracker.
        # this is important to establish iter bounds during inspection.
        firewall_stage_count(table_idx, rule_count)

        firewall_push_rules(table_idx)

        return Py_OK

    def _update_nat_rules(s, uintf8_t table_idx, list rulelist):
        '''acquires FWrule lock then rewrites the corresponding section ruleset.

        the current length var will also be update while the lock is held.
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            uintf16_t   rule_idx, rule_count = len(rulelist)
            dict        nat_rule

        for rule_idx in range(rule_count):
            nat_rule = rulelist[rule_idx]

            set_NATrule(table_idx, rule_idx, nat_rule)

        # updating rule count in global tracker.
        # this is important to establish iter bounds during inspection.
        nat_stage_count(table_idx, rule_count)

        nat_push_rules(table_idx)

        return Py_OK


cdef void set_FWrule(size_t table_idx, size_t rule_idx, dict rule):

    cdef:
        uintf8_t        i, ix, svc_list_len
        SvcObject       svc_object

        FWrule          fw_rule

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
        # svc_object = &fw_rule.s_services.objects[i]

        fw_rule.s_services.objects[i].type = <uintf8_t>rule['src_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (fw_rule.s_services.objects[i].type == SVC_ICMP):
            fw_rule.s_services.objects[i].icmp.type = <uintf8_t>rule['src_service'][i][1]
            fw_rule.s_services.objects[i].icmp.code = <uintf8_t>rule['src_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (fw_rule.s_services.objects[i].type == SVC_SOLO or fw_rule.s_services.objects[i].type == SVC_RANGE):
            fw_rule.s_services.objects[i].svc.protocol   = <uintf16_t>rule['src_service'][i][1]
            fw_rule.s_services.objects[i].svc.start_port = <uintf16_t>rule['src_service'][i][2]
            fw_rule.s_services.objects[i].svc.end_port   = <uintf16_t>rule['src_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            fw_rule.s_services.objects[i].svc_list.len = <uintf8_t>(len(rule['src_service'][i]) - 1)
            for ix in range(fw_rule.s_services.objects[i].svc_list.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                fw_rule.s_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['src_service'][i][ix + 1][0]
                fw_rule.s_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['src_service'][i][ix + 1][1]
                fw_rule.s_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['src_service'][i][ix + 1][2]

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
        # svc_object = &fw_rule.d_services.objects[i]

        fw_rule.d_services.objects[i].type = <uintf8_t>rule['dst_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (fw_rule.d_services.objects[i].type == SVC_ICMP):
            fw_rule.d_services.objects[i].icmp.type = <uintf8_t>rule['dst_service'][i][1]
            fw_rule.d_services.objects[i].icmp.code = <uintf8_t>rule['dst_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (fw_rule.d_services.objects[i].type == SVC_SOLO or fw_rule.d_services.objects[i].type == SVC_RANGE):
            fw_rule.d_services.objects[i].svc.protocol   = <uintf16_t>rule['dst_service'][i][1]
            fw_rule.d_services.objects[i].svc.start_port = <uintf16_t>rule['dst_service'][i][2]
            fw_rule.d_services.objects[i].svc.end_port   = <uintf16_t>rule['dst_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            fw_rule.d_services.objects[i].svc_list.len = <uintf8_t>(len(rule['dst_service'][i]) - 1)
            for ix in range(fw_rule.d_services.objects[i].svc_list.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                fw_rule.d_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['dst_service'][i][ix + 1][0]
                fw_rule.d_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['dst_service'][i][ix + 1][1]
                fw_rule.d_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['dst_service'][i][ix + 1][2]

    # --------------------------
    # RULE PROFILES AND ACTIONS
    # --------------------------
    fw_rule.action = <uintf8_t>rule['action']
    fw_rule.log    = <uintf8_t>rule['log']

    fw_rule.sec_profiles[0] = <uintf8_t>rule['ipp_profile']
    fw_rule.sec_profiles[1] = <uintf8_t>rule['dns_profile']
    fw_rule.sec_profiles[2] = <uintf8_t>rule['ips_profile']

    if (VERBOSE and table_idx >= 1):
        ppt(fw_rule)

    firewall_stage_rule(table_idx, rule_idx, &fw_rule)

cdef void set_NATrule(size_t table_idx, size_t rule_idx, dict rule):

    cdef:
        uintf8_t        i, ix, svc_list_len
        SvcObject       svc_object

        NATrule          nat_rule

    nat_rule.enabled = <bint>rule['enabled']
    # ===========
    # SOURCE
    # ===========
    nat_rule.s_zones.len = <uintf8_t>len(rule['src_zone'])
    for i in range(nat_rule.s_zones.len):
        nat_rule.s_zones.objects[i] = <uintf8_t>rule['src_zone'][i]

    nat_rule.s_networks.len = <uintf8_t>len(rule['src_network'])
    for i in range(nat_rule.s_networks.len):
        nat_rule.s_networks.objects[i].type    = <uintf8_t> rule['src_network'][i][0]
        nat_rule.s_networks.objects[i].netid   = <uintf32_t>rule['src_network'][i][1]
        nat_rule.s_networks.objects[i].netmask = <uintf32_t>rule['src_network'][i][2]

    # -----------------------
    # SOURCE SERVICE OBJECTS
    # -----------------------
    nat_rule.s_services.len = <uintf8_t>len(rule['src_service'])
    for i in range(nat_rule.s_services.len):
        # svc_object = &nat_rule.s_services.objects[i]

        nat_rule.s_services.objects[i].type = <uintf8_t>rule['src_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (nat_rule.s_services.objects[i].type == SVC_ICMP):
            nat_rule.s_services.objects[i].icmp.type = <uintf8_t>rule['src_service'][i][1]
            nat_rule.s_services.objects[i].icmp.code = <uintf8_t>rule['src_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (nat_rule.s_services.objects[i].type == SVC_SOLO or nat_rule.s_services.objects[i].type == SVC_RANGE):
            nat_rule.s_services.objects[i].svc.protocol   = <uintf16_t>rule['src_service'][i][1]
            nat_rule.s_services.objects[i].svc.start_port = <uintf16_t>rule['src_service'][i][2]
            nat_rule.s_services.objects[i].svc.end_port   = <uintf16_t>rule['src_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            nat_rule.s_services.objects[i].svc_list.len = <uintf8_t>(len(rule['src_service'][i]) - 1)
            for ix in range(nat_rule.s_services.objects[i].svc_list.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                nat_rule.s_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['src_service'][i][ix + 1][0]
                nat_rule.s_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['src_service'][i][ix + 1][1]
                nat_rule.s_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['src_service'][i][ix + 1][2]

    # ===========
    # DESTINATION
    # ===========
    nat_rule.d_zones.len = <uintf8_t>len(rule['dst_zone'])
    for i in range(nat_rule.d_zones.len):
        nat_rule.d_zones.objects[i] = <uintf8_t>rule['dst_zone'][i]

    nat_rule.d_networks.len = <uintf8_t>len(rule['dst_network'])
    for i in range(nat_rule.d_networks.len):
        nat_rule.d_networks.objects[i].type    = <uintf8_t> rule['dst_network'][i][0]
        nat_rule.d_networks.objects[i].netid   = <uintf32_t>rule['dst_network'][i][1]
        nat_rule.d_networks.objects[i].netmask = <uintf32_t>rule['dst_network'][i][2]

    # -----------------------
    # DST SERVICE OBJECTS
    # -----------------------
    nat_rule.d_services.len = <uintf8_t>len(rule['dst_service'])
    for i in range(nat_rule.d_services.len):
        # svc_object = &nat_rule.d_services.objects[i]

        nat_rule.d_services.objects[i].type = <uintf8_t>rule['dst_service'][i][0]
        # TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (nat_rule.d_services.objects[i].type == SVC_ICMP):
            nat_rule.d_services.objects[i].icmp.type = <uintf8_t>rule['dst_service'][i][1]
            nat_rule.d_services.objects[i].icmp.code = <uintf8_t>rule['dst_service'][i][2]

        # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        elif (nat_rule.d_services.objects[i].type == SVC_SOLO or nat_rule.d_services.objects[i].type == SVC_RANGE):
            nat_rule.d_services.objects[i].svc.protocol   = <uintf16_t>rule['dst_service'][i][1]
            nat_rule.d_services.objects[i].svc.start_port = <uintf16_t>rule['dst_service'][i][2]
            nat_rule.d_services.objects[i].svc.end_port   = <uintf16_t>rule['dst_service'][i][3]

        # TYPE 3 (LIST) OBJECT ASSIGNMENT
        else:
            nat_rule.d_services.objects[i].svc_list.len = <uintf8_t>(len(rule['dst_service'][i]) - 1)
            for ix in range(nat_rule.d_services.objects[i].svc_list.len):
                # [0] START INDEX ON FW RULE SIZE
                # [1] START INDEX PYTHON DICT SIDE (to first index for size)
                nat_rule.d_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['dst_service'][i][ix + 1][0]
                nat_rule.d_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['dst_service'][i][ix + 1][1]
                nat_rule.d_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['dst_service'][i][ix + 1][2]

    # --------------------------
    # RULE PROFILES AND ACTIONS
    # --------------------------
    nat_rule.action = <uintf8_t>rule['action']
    nat_rule.log    = <uintf8_t>rule['log']

    nat_rule.saddr = <uintf32_t>rule['saddr']
    nat_rule.sport = <uintf16_t>rule['sport']
    nat_rule.daddr = <uintf16_t>rule['daddr']
    nat_rule.dport = <uintf16_t>rule['dport']

    if (VERBOSE):
        ppt(nat_rule)

    nat_stage_rule(table_idx, rule_idx, &nat_rule)

# ==================================
# Firewall Matching Functions
# ==================================
# attacker blocklist membership test
# cdef inline bint in_blocklist(uint32_t src_host) nogil:
#
#     cdef:
#         size_t   i
#         uint32_t blocked_host
#
#     pthread_mutex_lock(&FWblocklistlock)
#
#     for i in range(FW_MAX_ATTACKERS):
#
#         blocked_host = ATTACKER_BLOCKLIST[i]
#
#         if (blocked_host == END_OF_ARRAY):
#             break
#
#         elif (blocked_host == src_host):
#             return MATCH
#
#     pthread_mutex_unlock(&FWblocklistlock)
#
#     return NO_MATCH
