 #!/usr/bin/env Cython

from libc.string cimport memset, strncpy
from libc.stdio cimport printf, perror

from libc.stdint cimport uint8_t, uint16_t, uint32_t

# from fw_api cimport api_open, process_api

# ===============================
# VERBOSE T-SHOOT ASSISTANCE
# ===============================
from pprint import PrettyPrinter
ppt = PrettyPrinter(sort_dicts=False).pprint
# ===============================

DEF FW_MAX_ATTACKERS  = 250

# function return values
DEF OK  = 0
DEF ERR = -1
DEF Py_OK  = 0
DEF Py_ERR = 1

DEF NETWORK = 1
DEF SERVICE = 2

# service object types.
DEF SVC_SOLO  = 1
DEF SVC_RANGE = 2
DEF SVC_LIST  = 3
DEF SVC_ICMP  = 4

# Blocked list access lock
# ----------------------------------
# cdef pthread_mutex_t FWblocklistlock

# pthread_mutex_init(&FWblocklistlock, NULL)

# stores the active attackers set/controlled by IPS/IDS
# cdef uint32_t *ATTACKER_BLOCKLIST = <uint32_t*>calloc(FW_MAX_ATTACKERS, sizeof(uint32_t))

# cdef uint32_t BLOCKLIST_CUR_SIZE = 0 # if we decide to track size for appends

# MNL_SOCKET_BUFFER_SIZE ~= 8192
DEF DNX_BUF_SIZE = 2048  # (will only handle packets of standard 1500 MTU)
DEF MNL_BUF_SIZE = 6144  # DNX_BUF_SIZE + (8192 / 2)

DEF QFIREWALL = 0
DEF QNAT      = 1

# ===================================
# Netfilter Communication Pipeline
# ===================================
# NETLINK SOCKET - cmod <> kernel
cdef int nl_open(mnl_socket **nl_ptr) nogil:

    nl_ptr[0] = mnl_socket_open(NETLINK_NETFILTER)
    if (nl_ptr == NULL):
        return ERR

    return OK

cdef int nl_bind(mnl_socket *nl_ptr) nogil:
    if (mnl_socket_bind(nl_ptr, 0, MNL_SOCKET_AUTOPID) < 0):
        return ERR

    return OK

def nl_break(int idx):
    mnl_socket_close(nl[idx])

    return Py_OK

# =====================================
# MAIN QUEUE LOOP
# =====================================
cdef int process_traffic(cfdata *cfd) nogil:

    cdef:
        char        packet_buf[MNL_BUF_SIZE]
        intf16_t    dlen, ret

        uint32_t    portid = mnl_socket_get_portid(nl[cfd.idx])

    printf("<ready to process traffic for Queue(%u)(%u)>\n", portid, cfd.queue)

    while True:
        dlen = mnl_socket_recvfrom(nl[cfd.idx], <void*>packet_buf, MNL_BUF_SIZE)
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
# cfds[1].queue_cb = nat_recv

firewall_init()
# nat_init()

# ===================================
# C Extension
# ===================================
cdef class CFirewall:

    # TODO: make this work on a per "module" basis. NAT vs FIREWALL.
    #   also provide a global argument option for these.
    #   FW instance will be responsible for settings these globally for the time being.
    def set_options(s, int verbose, int verbose2, int fw, int nat):
        global VERBOSE, VERBOSE2, FW_V, NAT_V

        VERBOSE = <bool>verbose
        VERBOSE2 = <bool>verbose2

        FW_V = <bool>fw
        NAT_V = <bool>nat

        if (verbose):
            print('<verbose console logging enabled>')

        # keeping this independent of verbose for flexibility
        if (verbose2):
            print('<verbose2 console logging enabled>')

        if (fw):
            print('<fw verbose console logging enabled>')

        if (nat):
            print('<nat verbose console logging enabled>')

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
        cdef int ret = OK
        cdef unicode msg

        print(f'<releasing GIL for Queue[{s.queue_idx}]({cfds[s.queue_idx].queue})>')
        # release gil and never look back.
        with nogil:
            ret = process_traffic(&cfds[s.queue_idx])

        msg = f'<! processing error on Queue[{s.queue_idx}]({cfds[s.queue_idx].queue}) !>'
        if (ret == ERR):
            perror(msg.encode('utf-8'))

    def nf_set(s, uint8_t queue_idx, uint16_t queue_num):

        s.queue_idx = queue_idx
        cfds[queue_idx].idx = queue_idx
        cfds[queue_idx].queue = queue_num

        # initializing nl socket for communication
        nl_open(&nl[queue_idx])
        nl_bind(nl[queue_idx])

        cdef:
            char        mnl_buf[MNL_BUF_SIZE]
            nlmsghdr   *nlh

            int         ret = 1

        # ---------------
        # BINDING QUEUE
        nlh = nfq_nlmsg_put(mnl_buf, NFQNL_MSG_CONFIG, queue_num)
        nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND)

        if (mnl_socket_sendto(nl[queue_idx], nlh, nlh.nlmsg_len) < 0):
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

        if (mnl_socket_sendto(nl[queue_idx], nlh, nlh.nlmsg_len) < 0):
            return Py_ERR

        # ENOBUFS is signalled to userspace when packets were lost on the kernel side.
        # We don't care, so we can turn it off.
        mnl_socket_setsockopt(nl[queue_idx], NETLINK_NO_ENOBUFS, <void*>&ret, sizeof(int))

        return Py_OK

    def update_zones(s, list zone_map):
        '''acquires FWrule lock then updates the zone values by interface index.

        MAX_SLOTS defined by FW_MAX_ZONE_COUNT.
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            intf16_t    idx
            ZoneMap     temp_map[FW_MAX_ZONES]
            unicode     zone_name

        for idx in range(FW_MAX_ZONES):
            temp_map[idx].id = zone_map[idx][0]
            zone_name = zone_map[idx][1]

            strncpy(temp_map[idx].name, zone_name.encode('utf-8'), 16)

        with nogil:
            firewall_push_zones(temp_map)

        return Py_OK

    def update_rules(s, uintf8_t cntrl_group, uintf8_t cntrl_list_idx, list rulelist):

        if (cntrl_group == 0):
            return s._update_firewall_rules(cntrl_list_idx, rulelist)

        # elif (cntrl_group == 1):
        #     return s._update_nat_rules(cntrl_list_idx, rulelist)

        return Py_ERR

    def _update_firewall_rules(s, uintf8_t cntrl_list_idx, list rulelist):
        '''acquires FWrule lock then rewrites the corresponding section ruleset.

        the current length var will also be update while the lock is held. 
        the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
        '''
        cdef:
            uintf16_t   rule_idx, rule_count = len(rulelist)
            dict        fw_rule

        for rule_idx in range(rule_count):
            fw_rule = rulelist[rule_idx]

            set_FWrule(cntrl_list_idx, rule_idx, fw_rule)

        # updating rule count in global tracker.
        # this is important to establish iter bounds during inspection.
        firewall_stage_count(cntrl_list_idx, rule_count)

        with nogil:
            firewall_push_rules(cntrl_list_idx)

        return Py_OK

    # def _update_nat_rules(s, uintf8_t clist_idx, list rulelist):
    #     '''acquires FWrule lock then rewrites the corresponding section ruleset.
    #
    #     the current length var will also be update while the lock is held.
    #     the GIL will be explicitly acquired before any code execution to ensure calls from C are safe.
    #     '''
    #     cdef:
    #         uintf16_t   rule_idx, rule_count = len(rulelist)
    #         dict        nat_rule
    #
    #     for rule_idx in range(rule_count):
    #         nat_rule = rulelist[rule_idx]
    #
    #         set_NATrule(clist_idx, rule_idx, nat_rule)
    #
    #     # updating rule count in global tracker.
    #     # this is important to establish iter bounds during inspection.
    #     nat_stage_count(clist_idx, rule_count)
    #
    #     with nogil:
    #         nat_push_rules(clist_idx)
    #
    #     return Py_OK


cdef void set_FWrule(size_t cntrl_list_idx, size_t rule_idx, dict rule):

    cdef:
        uintf8_t    i, ix, svc_list_len
        SvcObject   svc_object

        FWrule      fw_rule
        unicode     rule_name = rule['name']

    memset(&fw_rule, 0, sizeof(FWrule))

    strncpy(<char*>&fw_rule.name, rule_name.encode('utf-8'), 32)
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

    if (VERBOSE2 and FW_V and cntrl_list_idx >= 1):
        ppt(fw_rule)

    firewall_stage_rule(cntrl_list_idx, rule_idx, &fw_rule)

# cdef void set_NATrule(size_t cntrl_list_idx, size_t rule_idx, dict rule):
#
#     cdef:
#         uintf8_t    i, ix, svc_list_len
#         SvcObject   svc_object
#
#         NATrule     nat_rule
#         unicode     rule_name = rule['name']
#
#     memset(&nat_rule, 0, sizeof(NATrule))
#
#     strncpy(<char*>&nat_rule.name, rule_name.encode('utf-8'), 32)
#     nat_rule.enabled = <bint>rule['enabled']
#     # ===========
#     # SOURCE
#     # ===========
#     nat_rule.s_zones.len = <uintf8_t>len(rule['src_zone'])
#     for i in range(nat_rule.s_zones.len):
#         nat_rule.s_zones.objects[i] = <uintf8_t>rule['src_zone'][i]
#
#     nat_rule.s_networks.len = <uintf8_t>len(rule['src_network'])
#     for i in range(nat_rule.s_networks.len):
#         nat_rule.s_networks.objects[i].type    = <uintf8_t> rule['src_network'][i][0]
#         nat_rule.s_networks.objects[i].netid   = <uintf32_t>rule['src_network'][i][1]
#         nat_rule.s_networks.objects[i].netmask = <uintf32_t>rule['src_network'][i][2]
#
#     # -----------------------
#     # SOURCE SERVICE OBJECTS
#     # -----------------------
#     nat_rule.s_services.len = <uintf8_t>len(rule['src_service'])
#     for i in range(nat_rule.s_services.len):
#         # svc_object = &nat_rule.s_services.objects[i]
#
#         nat_rule.s_services.objects[i].type = <uintf8_t>rule['src_service'][i][0]
#         # TYPE 4 (ICMP) OBJECT ASSIGNMENT
#         if (nat_rule.s_services.objects[i].type == SVC_ICMP):
#             nat_rule.s_services.objects[i].icmp.type = <uintf8_t>rule['src_service'][i][1]
#             nat_rule.s_services.objects[i].icmp.code = <uintf8_t>rule['src_service'][i][2]
#
#         # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
#         elif (nat_rule.s_services.objects[i].type == SVC_SOLO or nat_rule.s_services.objects[i].type == SVC_RANGE):
#             nat_rule.s_services.objects[i].svc.protocol   = <uintf16_t>rule['src_service'][i][1]
#             nat_rule.s_services.objects[i].svc.start_port = <uintf16_t>rule['src_service'][i][2]
#             nat_rule.s_services.objects[i].svc.end_port   = <uintf16_t>rule['src_service'][i][3]
#
#         # TYPE 3 (LIST) OBJECT ASSIGNMENT
#         else:
#             nat_rule.s_services.objects[i].svc_list.len = <uintf8_t>(len(rule['src_service'][i]) - 1)
#             for ix in range(nat_rule.s_services.objects[i].svc_list.len):
#                 # [0] START INDEX ON FW RULE SIZE
#                 # [1] START INDEX PYTHON DICT SIDE (to first index for size)
#                 nat_rule.s_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['src_service'][i][ix + 1][0]
#                 nat_rule.s_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['src_service'][i][ix + 1][1]
#                 nat_rule.s_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['src_service'][i][ix + 1][2]
#
#     # ===========
#     # DESTINATION
#     # ===========
#     nat_rule.d_zones.len = <uintf8_t>len(rule['dst_zone'])
#     for i in range(nat_rule.d_zones.len):
#         nat_rule.d_zones.objects[i] = <uintf8_t>rule['dst_zone'][i]
#
#     nat_rule.d_networks.len = <uintf8_t>len(rule['dst_network'])
#     for i in range(nat_rule.d_networks.len):
#         nat_rule.d_networks.objects[i].type    = <uintf8_t> rule['dst_network'][i][0]
#         nat_rule.d_networks.objects[i].netid   = <uintf32_t>rule['dst_network'][i][1]
#         nat_rule.d_networks.objects[i].netmask = <uintf32_t>rule['dst_network'][i][2]
#
#     # -----------------------
#     # DST SERVICE OBJECTS
#     # -----------------------
#     nat_rule.d_services.len = <uintf8_t>len(rule['dst_service'])
#     for i in range(nat_rule.d_services.len):
#         # svc_object = &nat_rule.d_services.objects[i]
#
#         nat_rule.d_services.objects[i].type = <uintf8_t>rule['dst_service'][i][0]
#         # TYPE 4 (ICMP) OBJECT ASSIGNMENT
#         if (nat_rule.d_services.objects[i].type == SVC_ICMP):
#             nat_rule.d_services.objects[i].icmp.type = <uintf8_t>rule['dst_service'][i][1]
#             nat_rule.d_services.objects[i].icmp.code = <uintf8_t>rule['dst_service'][i][2]
#
#         # TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
#         elif (nat_rule.d_services.objects[i].type == SVC_SOLO or nat_rule.d_services.objects[i].type == SVC_RANGE):
#             nat_rule.d_services.objects[i].svc.protocol   = <uintf16_t>rule['dst_service'][i][1]
#             nat_rule.d_services.objects[i].svc.start_port = <uintf16_t>rule['dst_service'][i][2]
#             nat_rule.d_services.objects[i].svc.end_port   = <uintf16_t>rule['dst_service'][i][3]
#
#         # TYPE 3 (LIST) OBJECT ASSIGNMENT
#         else:
#             nat_rule.d_services.objects[i].svc_list.len = <uintf8_t>(len(rule['dst_service'][i]) - 1)
#             for ix in range(nat_rule.d_services.objects[i].svc_list.len):
#                 # [0] START INDEX ON FW RULE SIZE
#                 # [1] START INDEX PYTHON DICT SIDE (to first index for size)
#                 nat_rule.d_services.objects[i].svc_list.services[ix].protocol   = <uintf16_t>rule['dst_service'][i][ix + 1][0]
#                 nat_rule.d_services.objects[i].svc_list.services[ix].start_port = <uintf16_t>rule['dst_service'][i][ix + 1][1]
#                 nat_rule.d_services.objects[i].svc_list.services[ix].end_port   = <uintf16_t>rule['dst_service'][i][ix + 1][2]
#
#     # --------------------------
#     # RULE PROFILES AND ACTIONS
#     # --------------------------
#     nat_rule.action = <uintf8_t>rule['action']
#     nat_rule.log    = <uintf8_t>rule['log']
#
#     nat_rule.nat.saddr = <uintf32_t>rule['saddr']
#     nat_rule.nat.sport = <uintf16_t>rule['sport']
#     nat_rule.nat.daddr = <uintf16_t>rule['daddr']
#     nat_rule.nat.dport = <uintf16_t>rule['dport']
#
#     if (VERBOSE2 and NAT_V):
#         ppt(nat_rule)
#
#     nat_stage_rule(cntrl_list_idx, rule_idx, &nat_rule)

# ===================================
# HASHING TRIE (Range Type)
# ===================================
from libc.stdlib cimport malloc, calloc, realloc

DEF EMPTY_CONTAINER = 0
DEF NO_MATCH = 0
# data structure supporting ip to geolocation lookup
DEF HTR_MAX_WIDTH_MULTIPLIER = 2
# 4 slots to allow for concurrent use of structures if needed
DEF HTR_MAX_SLOTS = 4

# GLOBAL CONTAINER FOR HTRs. likely only 1 will ever be needed
cdef public HTR_Slot HTR_SLOTS[HTR_MAX_SLOTS]
memset(HTR_SLOTS, 0, sizeof(HTR_Slot) * HTR_MAX_SLOTS)

# -----------------------------------
# python accessible API
# -----------------------------------
def initialize_geolocation(list hash_trie, uint32_t msb, uint32_t lsb):
    '''initializes HashTrie data structure for use by CFirewall.

    py_trie is passed through as a data source.
    MSB, LSB, and HTR_IDX definitions are globally assigned.
    '''
    global MSB, LSB, HTR_IDX

    cdef:
        size_t trie_len = len(hash_trie)
        int htr_idx = htr_generate_structure(hash_trie, trie_len)

    MSB = msb
    LSB = lsb
    HTR_IDX = htr_idx

    return Py_OK

cdef int htr_generate_structure(list py_trie, size_t py_trie_len):
    '''generate hash trie range structure and return container index.

    resulting structure must be access through c function calls and container index.

        note: this function IS NOT thread safe.
    '''
    # ====================================
    # MAP OBJECT ALLOCATION AND PLACEMENT
    # ====================================
    cdef:
        int         trie_idx
        HTR_Slot   *htr_slot

    # 1. dynamically check next available index
    for trie_idx in range(HTR_MAX_SLOTS):

        htr_slot = &HTR_SLOTS[trie_idx]

        # 2. allocate memory at current index for TrieMap
        if (htr_slot.len == 0):
            # TODO: test the multiplier for max_width (current is 2, try 1.3)
            htr_slot.len = <size_t> py_trie_len * HTR_MAX_WIDTH_MULTIPLIER
            htr_slot.keys = <HTR_L1*> calloc(htr_slot.len, sizeof(HTR_L1))

            break

    # reached max container allocation (this should NEVER happen)
    else: return -1

    # ======================================
    # RANGE OBJECT ALLOCATION AND PLACEMENT
    # ======================================
    cdef:
        size_t      i, xi

        HTR_L1  *htr_key
        HTR_L2  *htr_multi_val

        uint32_t    trie_key
        uint32_t    trie_key_hash
        list        trie_vals
        size_t      num_values

    # 3. populate TrieMap structure with TrieRange structs
    for i in range(py_trie_len):

        trie_key = <uint32_t> py_trie[i][0]
        trie_key_hash = trie_key % (htr_slot.len - 1)

        trie_vals = py_trie[i][1]
        num_values = <size_t> len(trie_vals)

        htr_key = &htr_slot.keys[trie_key_hash]

        # first time on index so allocating memory for the number of current multi-vals this iteration
        if (htr_key.len == 0):
            htr_key.multi_val = <HTR_L2*> malloc(sizeof(HTR_L2) * num_values)

        # at least 1 multi-val is present, so reallocating memory to include new multi-vals
        else:
            htr_key.multi_val = <HTR_L2*> realloc(
                htr_key.multi_val, sizeof(HTR_L2) * (htr_key.len + num_values)
            )

        # define struct members for each range in py_l2
        for xi in range(num_values):
            htr_l2 = &htr_key.multi_val[htr_key.len + xi]  # skipping to next empty idx

            htr_l2.key = trie_key
            htr_l2.netid = <uint32_t> py_trie[i][1][xi][0]
            htr_l2.bcast = <uint32_t> py_trie[i][1][xi][1]
            htr_l2.country = <uint8_t> py_trie[i][1][xi][2]

        htr_key.len += num_values

    # 4. returning slot the structure was placed in (for subsequent access)
    return trie_idx

# -----------------------------------
# C accessible API
# -----------------------------------
cdef public uint8_t htr_search(int trie_idx, uint32_t trie_key, uint32_t host_id) nogil:

        cdef :
            HTR_Slot   *htr_slot = &HTR_SLOTS[trie_idx]

            uint32_t    trie_key_hash = trie_key % (htr_slot.len - 1)

            HTR_L1     *htr_key = &htr_slot.keys[trie_key_hash]

        # no l1 match
        if (htr_key.len == EMPTY_CONTAINER):
            return NO_MATCH

        cdef size_t i
        for i in range(htr_key.len):

            # this is needed because collisions are possible by design.
            # matching the original key will guarantee the correct range is being evaluated.
            if (htr_key.multi_val[i].key != trie_key):
                continue

            if (htr_key.multi_val[i].netid <= host_id <= htr_key.multi_val[i].bcast):
                return htr_key.multi_val[i].country

        # iteration completed with no l2 match
        return NO_MATCH
