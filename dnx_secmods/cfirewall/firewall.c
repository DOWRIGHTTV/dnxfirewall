#include "stdlib.h"
#include "pthread.h"


#define FW_TABLE_COUNT 4
#define FW_SYSTEM_MAX_RULE_COUNT  50
#define FW_BEFORE_MAX_RULE_COUNT 100
#define FW_MAIN_MAX_RULE_COUNT   500
#define FW_AFTER_MAX_RULE_COUNT  100

#define FW_MAX_ATTACKERS  250
#define FW_MAX_ZONE_COUNT  16

#define FW_SYSTEM_RANGE_START 0
#define FW_RULE_RANGE_START   1
#define FW_RULE_RANGE_END     4

#define SECURITY_PROFILE_COUNT 3
#define PROFILE_SIZE   4  // bits
#define PROFILE_START 12
#define PROFILE_STOP  (SECURITY_PROFILE_COUNT * 4) + 8 // + 1  // +1 for range

// nfq alias for iteration range
//cdef enum: NFQA_RANGE = NFQA_MAX + 1

// ================================== //
// Firewall tables access lock
// ================================== //
// Must be held to read from or make
// changes to "*firewall_tables[]"
// ---------------------------------- //
const pthread_mutex_t     FWtableslock;
const pthread_mutex_t    *FWlock_ptr = &FWtableslock;

pthread_mutex_init(FWlock_ptr, NULL);

// ==================================
// ARRAY INITIALIZATION
// ==================================
FWtable *firewall_tables[FW_TABLE_COUNT];

// arrays of pointers to FWrules
firewall_tables[FW_SYSTEM_RULES] = { 0, <FWrule*>calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(FWrule)) };
firewall_tables[FW_BEFORE_RULES] = { 0, <FWrule*>calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(FWrule)) };
firewall_tables[FW_MAIN_RULES]   = { 0, <FWrule*>calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(FWrule)) };
firewall_tables[FW_AFTER_RULES]  = { 0, <FWrule*>calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(FWrule)) };

// consider moving to stack and using memset to zeroize
uintf16_t *FW_CUR_RULE_COUNTS = (uintf16_t*) calloc(FW_TABLE_COUNT, sizeof(uintf16_t))

// ==================================
// PRIMARY FIREWALL LOGIC
// ==================================
int
firewall_recv(const nlmsghdr *nlh, void *data)
{
    cfdata     *cfd = <cfdata*>data;
    nlattr     *netlink_attrs[NFQA_RANGE];

    nl_pkt_hdr *nlhdr;
    nl_pkt_hw  *_hw;

    uint32_t    _iif, _oif, _mark, ct_info;

    dnx_pktb    pkt;

    srange      fw_tables;

    nullset(<void**>netlink_attrs, NFQA_RANGE);
    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = <nl_pkt_hdr*>mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);
    // ======================
    // CONNTRACK
    // this should be checked as soon as feasibly possible for performance.
    // this will be used to allow for stateless inspection policies later.
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    if (ct_info != IP_CT_NEW) {
        dnx_send_verdict_fast(cfd.queue, ntohl(nlhdr.packet_id), NF_ACCEPT);

        return OK;
    }
    // ======================
    // INTERFACE, NL, AND HW
    _mark = netlink_attrs[NFQA_MARK] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) : 0;
    _iif  = netlink_attrs[NFQA_IFINDEX_INDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) : 0;
    _oif  = netlink_attrs[NFQA_IFINDEX_OUTDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) : 0;

    if (netlink_attrs[NFQA_HWADDR]) {
        _hw = <nl_pkt_hw*>mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR]);

        pkt.hw.m_addr = <char*>_hw.hw_addr;
    }

    pkt.hw.timestamp = time(NULL);
    pkt.hw.in_zone   = INTF_ZONE_MAP[_iif];
    pkt.hw.out_zone  = INTF_ZONE_MAP[_oif];

    // ======================
    // PACKET DATA / LEN
    pkt.data = mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD]); // <uint8_t*>
    pkt.tlen = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD]);
    // ======================
    // FW TABLE ASSIGNMENT
    // ordered by system priority
    switch (ntohl(nlhdr.hook)) {
        case NF_IP_FORWARD:
            fw_tables = { FW_RULE_RANGE_START, FW_RULE_RANGE_END };
            break;
        case NF_IP_LOCAL_IN:
            fw_tables = { FW_SYSTEM_RANGE_START, FW_RULE_RANGE_END };
    }

    // ===================================
    // LOCKING ACCESS TO FIREWALL RULES
    // prevents the manager thread from updating firewall rules during packet inspection
    pthread_mutex_lock(FWlock_ptr)
    // --------------------
    cfirewall_inspect(&fw_tables, &pkt)
    // --------------------
    pthread_mutex_unlock(FWlock_ptr)
    // UNLOCKING ACCESS TO FIREWALL RULES
    // ===================================

    // --------------------
    // NFQUEUE VERDICT
    // --------------------
    // only SYSTEM RULES will have cfirewall invoke action directly
    if (fw_tables.start != FW_SYSTEM_RANGE_START) {

        // if PROXY_BYPASS, cfirewall will invoke the rule action without forwarding to another queue.
        // if not PROXY_BYPASS, forward to ip proxy regardless of action for geolocation log or IPS
        if (!PROXY_BYPASS) {
            pkt.action = IP_PROXY << TWO_BYTES | NF_QUEUE;
        }
    }

    dnx_send_verdict(cfd.queue, ntohl(nlhdr.packet_id), &pkt);

    // verdict is being used to eval whether the packet matched a system rule.
    // a 0 verdict infers this also, but for ease of reading, ill use both.
    if (VERBOSE) {
        // pkt_print(&hw, ip_header, proto_header)

        printf('[C/packet] hook->%u, mark->%u, action->%u, ', ntohl(nlhdr.hook), _mark, pkt.action);
        printf('ipp->%u, dns->%u, ips->%u\n', pkt.mark >> 12 & 15, pkt.mark >> 16 & 15, pkt.mark >> 20 & 15);
        printf('=====================================================================\n');
    }

    // return heirarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    // < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK;
}

inline void
firewall_inspect(srange *fw_tables, dnx_pktb *pkt) {

    // iphdr and protohdr
    parse_pkt_headers(pkt);

    FWrule     *rule_table;
    FWrule     *rule;
//    uintf16_t   table_idx, rule_idx;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt.iphdr.saddr);
    uint32_t    iph_dst_ip = ntohl(pkt.iphdr.daddr);

    // ip address to country code
    uint8_t     src_country = GEOLOCATION.search(iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = GEOLOCATION.search(iph_dst_ip & MSB, iph_dst_ip & LSB);

    // general direction of the packet and ip addr normalized to always be the external host/ip
    uint8_t     direction = pkt.hw.in_zone != WAN_IN ? OUTBOUND : INBOUND;
    uint16_t    tracked_geo = direction == INBOUND ? src_country : dst_country;

    // loops
    uintf8_t    i, idx;

    // is the end index +1?
    for (i = fw_tables.start; i < fw_tables.end; i++) {

        firewall_table = firewall_tables[i];

        if (firewall_table.len == 0) { continue; }

        for rule_idx in range(firewall_table.len)

        // same as above
        for (idx = 0; idx < firewall_table.len; idx ++) {

            rule = &rule_table[rule_idx]

            // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (not rule.enabled):
                continue

            // ------------------------------------------------------------------
            // ZONE MATCHING
            // ------------------------------------------------------------------
            // currently tied to interface and designated LAN, WAN, DMZ
            if (zone_match(rule, pkt.hw.in_zone, SRC_MATCH) != MATCH) { continue; }
            if (zone_match(rule, pkt.hw.out_zone, DST_MATCH) != MATCH) { continue; }

            // ------------------------------------------------------------------
            // GEOLOCATION or IP/NETMASK
            // ------------------------------------------------------------------
            if (network_match(s_networks, iph_src_ip, src_country) != MATCH) { continue; }
            if (network_match(d_networks, iph_dst_ip, dst_country) != MATCH) { continue; }

            // ------------------------------------------------------------------
            // PROTOCOL / PORT
            // ------------------------------------------------------------------
            Svc pkt_svc = {}

            if (service_match(&rule.s_services, pkt, SRC_MATCH) != MATCH) { continue; }
            if (service_match(&rule.d_services, pkt, DST_MATCH) != MATCH) { continue; }

            // ------------------------------------------------------------------
            // MATCH ACTION | return rule options
            // ------------------------------------------------------------------
            // drop will inherently forward to the ip proxy for geo inspection and local dns records.
            pkt.fw_table = table_idx;
            pkt.rule_num = rule_num; // if logging, this needs to be +1
            pkt.action   = rule.action;
            pkt.mark     = tracked_geo << FOUR_BITS | direction << TWO_BITS | rule.action;

            for (i = 0; i < 3; i++) {
                pkt.mark |= rule.sec_profiles[i] << (i*4)+12;
            }

            return;

    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt.fw_section = NO_SECTION;
    pkt.action     = DNX_DROP;
    pkt.mark       = tracked_geo << FOUR_BITS | direction << TWO_BITS | DNX_DROP;