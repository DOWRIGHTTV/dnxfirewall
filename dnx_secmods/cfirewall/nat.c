#include "stdlib.h"
#include "pthread.h"
#include "netinet/in.h"

#define NAT_TABLE_COUNT 2
#define NAT_PRE_MAX_RULE_COUNT  100
#define NAT_POST_MAX_RULE_COUNT 100

#define NAT_PRE_TABLE  0
#define NAT_POST_TABLE 1

// ================================== #
// NAT tables access lock
// ================================== #
// Must be held to read from or make
// changes to "*firewall_tables[]"
// ---------------------------------- #
const pthread_mutex_t     NATtableslock;
const pthread_mutex_t    *NATlock_ptr = &NATtableslock;

pthread_mutex_init(NATlock_ptr, NULL);

// ==================================
// ARRAY INITIALIZATION
// ==================================
// contains pointers to arrays of pointers to NATrule
NATtable *nat_tables[NAT_TABLE_COUNT];

// arrays of pointers to NATrule
nat_tables[NAT_PRE_RULES]  = { 0, <NATrule*>calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(NATrule))] };
nat_tables[NAT_POST_RULES] = { 0, <NATrule*>calloc(NAT_POST_MAX_RULE_COUNT, sizeof(NATrule)) };

// consider moving to stack and using memset to zeroize
uintf16_t *NAT_CUR_RULE_COUNTS = (uintf16_t*) calloc(NAT_TABLE_COUNT, sizeof(uintf16_t));

// ==================================
// PRIMARY NAT LOGIC
// ==================================
int
nat_recv(const nlmsghdr *nlh, void *data)
{
    cfdata     *cfd = <cfdata*>data;
    nlattr     *netlink_attrs[NFQA_RANGE];

    nl_pkt_hdr *nlhdr;

    uint32_t    _iif, _oif, _mark;

    int         table_idx;
    uintf16_t   rule_count;

    dnx_pktb    pkt;

    nullset(<void**>netlink_attrs, NFQA_RANGE);
    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = <nl_pkt_hdr*>mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);

    switch(ntohl(nlhdr.hook)) {
        case NF_IP_POST_ROUTING:
            table_idx = NAT_POST_TABLE;
            break;
        case NF_IP_PRE_ROUTING:
            table_idx = NAT_PRE_TABLE;
    }

    // ======================
    // NO NAT QUICK PATH
    rule_count = NAT_CUR_RULE_COUNTS[table_idx];
    if (rule_count == 0) {
        dnx_send_verdict_fast(cfd.queue, ntohl(nlhdr.packet_id), NF_ACCEPT);

        return OK;
    }
    // ======================
    // _mark = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) if netlink_attrs[NFQA_MARK] else 0
    pkt.hw.in_zone  = netlink_attrs[NFQA_IFINDEX_INDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) : 0;
    pkt.hw.out_zone = netlink_attrs[NFQA_IFINDEX_OUTDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) : 0;

    // ======================
    // PACKET DATA / LEN
    pkt.data = <uint8_t*>mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD]);
    pkt.tlen = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD]);
    // ===================================
    // LOCKING ACCESS TO NAT RULES
    // prevents the manager thread from updating nat rules during packet inspection
    pthread_mutex_lock(NATlock_ptr);
    // --------------------
    cnat_inspect(table_idx, rule_count, &pkt);
    // --------------------
    pthread_mutex_unlock(NATlock_ptr);
    // UNLOCKING ACCESS TO NAT RULES
    // ===================================

    // --------------------
    // NAT / MANGLE
    // --------------------
    // NOTE: it looks like it will be better if we manually NAT the packet contents.
    // the alternative is to allocate a pktb and user the proper mangler.
    // this would auto manage the header checksums, but we would need alloc/free every time we mangle.
    // i have alot of experience with nat and checksum calculations so its probably easier and more efficient to use
    // the on stack buffer to mangle. (this is unless we need to retain a copy of the original packet)
    if (pkt.action & DNX_NAT_FLAGS) {
        dnx_mangle_pkt(&pkt);
    }
}

inline void
nat_inspect(int table_idx, int rule_count, dnx_pktb *pkt)
{
    parse_pkt_headers(pkt);

    NATrule    *nat_table;
    NATrule    *rule;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt.iphdr.saddr);
    uint32_t    iph_dst_ip = ntohl(pkt.iphdr.daddr);

    // ip address to country code
    uint8_t     src_country = GEOLOCATION.search(iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = GEOLOCATION.search(iph_dst_ip & MSB, iph_dst_ip & LSB);

    uintf16_t   i;

    for (i = 0; i < rule_count; i++) {

        rule = &nat_tables[table_idx][rule_idx];
        // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
        if (rule.enabled == 0) { continue; }

        // ------------------------------------------------------------------
        // ZONE MATCHING
        // ------------------------------------------------------------------
        // currently tied to interface and designated LAN, WAN, DMZ
        if (zone_match(rule, pkt.hw.in_zone, SRC_MATCH) != MATCH) { continue; }
        if (zone_match(rule, pkt.hw.out_zone, DST_MATCH): != MATCH) { continue; }

        // ------------------------------------------------------------------
        // GEOLOCATION or IP/NETMASK
        // ------------------------------------------------------------------
        if (network_match(rule, iph_src_ip, src_country, SRC_MATCH) != MATCH) { continue; }
        if (network_match(rule, iph_dst_ip, dst_country, DST_MATCH) != MATCH) { continue; }

        // ------------------------------------------------------------------
        // PROTOCOL / PORT
        // ------------------------------------------------------------------
        if (service_match(rule, pkt, SRC_MATCH) != MATCH) { continue; }
        if (service_match(rule, pkt, DST_MATCH) != MATCH) { continue; }

        // ------------------------------------------------------------------
        // MATCH ACTION | rule details
        // ------------------------------------------------------------------
        pkt.fw_table   = table_idx;
        pkt.rule_num   = rule_idx; // if logging, this needs to be +1
        pkt.action     = rule.action;

        return;

    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt.fw_section = NO_SECTION;
    pkt.action     = DNX_ACCEPT;
}
