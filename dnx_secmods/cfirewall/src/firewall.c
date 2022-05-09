#include "config.h"
#include "firewall.h"
#include "cfirewall.h"
#include "rules.h"

#include <stdio.h>

//#include "linux/netlink.h" //nlmsghdr

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

struct FWtable firewall_tables[FW_TABLE_COUNT];

pthread_mutex_t     FWtableslock;
pthread_mutex_t    *FWlock_ptr = &FWtableslock;

void
firewall_init(void) {
    pthread_mutex_init(FWlock_ptr, NULL);

    // arrays of pointers to FWrules
    firewall_tables[FW_SYSTEM_RULES].len = 0;
    firewall_tables[FW_SYSTEM_RULES].rules = calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(struct FWrule));  // (struct FWrule*)

    firewall_tables[FW_BEFORE_RULES].len = 0;
    firewall_tables[FW_BEFORE_RULES].rules = calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(struct FWrule)); // (struct FWrule*)

    firewall_tables[FW_MAIN_RULES].len = 0;
    firewall_tables[FW_MAIN_RULES].rules = calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(struct FWrule)); // (struct FWrule*)

    firewall_tables[FW_AFTER_RULES].len = 0;
    firewall_tables[FW_AFTER_RULES].rules = calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(struct FWrule)); // (struct FWrule*)
}

// ==================================
// PRIMARY FIREWALL LOGIC
// ==================================
int
firewall_recv(const struct nlmsghdr *nlh, void *data)
{
    struct cfdata     *cfd = (struct cfdata*) data;
    struct nlattr     *netlink_attrs[NFQA_MAX+1] = {};

    nl_pkt_hdr *nlhdr;
    nl_pkt_hw  *_hw;

    uint32_t    _iif, _oif, _mark, ct_info;

    struct dnx_pktb    pkt;

    struct table_range      fw_tables;

//    nullset(<void**>netlink_attrs, NFQA_RANGE);
    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = (nl_pkt_hdr*) mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);
    // ======================
    // CONNTRACK
    // this should be checked as soon as feasibly possible for performance.
    // this will be used to allow for stateless inspection policies later.
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    if (ct_info != IP_CT_NEW) {
        dnx_send_verdict_fast(cfd->queue, ntohl(nlhdr->packet_id), NF_ACCEPT);

        return OK;
    }
    // ======================
    // INTERFACE, NL, AND HW
    _mark = netlink_attrs[NFQA_MARK] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_MARK])) : 0;
    _iif  = netlink_attrs[NFQA_IFINDEX_INDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) : 0;
    _oif  = netlink_attrs[NFQA_IFINDEX_OUTDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) : 0;

    if (netlink_attrs[NFQA_HWADDR]) {
        _hw = (nl_pkt_hw*) mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR]);

        pkt.hw.mac_addr = (char*) _hw->hw_addr;
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
    switch (nlhdr->hook) {
        case NF_IP_FORWARD:
            fw_tables.start = FW_RULE_RANGE_START;
            break;
        case NF_IP_LOCAL_IN:
            fw_tables.start = FW_SYSTEM_RANGE_START;
            break;
        default: return ERR;
    }
    fw_tables.end = FW_RULE_RANGE_END;
    // ===================================
    // LOCKING ACCESS TO FIREWALL RULES
    // prevents the manager thread from updating firewall rules during packet inspection
    firewall_lock();
    // --------------------
    firewall_inspect(&fw_tables, &pkt, cfd);
    // --------------------
    firewall_unlock();
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

    dnx_send_verdict(cfd->queue, ntohl(nlhdr->packet_id), &pkt);

    // verdict is being used to eval whether the packet matched a system rule.
    // a 0 verdict infers this also, but for ease of reading, ill use both.
    if (VERBOSE) {
        // pkt_print(&hw, ip_header, proto_header)

        printf("[C/packet] hook->%u, mark->%u, action->%u, ", ntohl(nlhdr->hook), _mark, pkt.action);
        printf("ipp->%u, dns->%u, ips->%u\n", pkt.mark >> 12 & 15, pkt.mark >> 16 & 15, pkt.mark >> 20 & 15);
        printf("=====================================================================\n");
    }

    // return heirarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    // < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK;
}

inline void
firewall_inspect(struct table_range *fw_tables, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    // iphdr and protohdr
    dnx_parse_pkt_headers(pkt);

    struct FWrule     *rule;
//    uintf16_t   table_idx, rule_idx;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = cfd->geo_search(iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = cfd->geo_search(iph_dst_ip & MSB, iph_dst_ip & LSB);

    // general direction of the packet and ip addr normalized to always be the external host/ip
    uint8_t     direction   = pkt->hw.in_zone != WAN_IN ? OUTBOUND : INBOUND;
    uint16_t    tracked_geo = direction == INBOUND ? src_country : dst_country;

    // loops
    uintf8_t    idx, table_idx, rule_idx;

    // is the end index +1?
    for (table_idx = fw_tables->start; table_idx < fw_tables->end; table_idx++) {

        if (firewall_tables[table_idx].len == 0) { continue; }

        // same as above
        for (rule_idx = 0; rule_idx < firewall_tables[table_idx].len; rule_idx++) {

            rule = &firewall_tables[table_idx].rules[rule_idx];

            // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (!rule->enabled) { continue; }

            // ------------------------------------------------------------------
            // ZONE MATCHING
            // ------------------------------------------------------------------
            // currently tied to interface and designated LAN, WAN, DMZ
            if (zone_match(&rule->s_zones, pkt->hw.in_zone) != MATCH) { continue; }
            if (zone_match(&rule->d_zones, pkt->hw.out_zone) != MATCH) { continue; }

            // ------------------------------------------------------------------
            // GEOLOCATION or IP/NETMASK
            // ------------------------------------------------------------------
            if (network_match(&rule->s_networks, iph_src_ip, src_country) != MATCH) { continue; }
            if (network_match(&rule->d_networks, iph_dst_ip, dst_country) != MATCH) { continue; }

            // ------------------------------------------------------------------
            // PROTOCOL / PORT
            // ------------------------------------------------------------------
            if (service_match(&rule->s_services, pkt->iphdr->protocol, pkt->protohdr->sport) != MATCH) { continue; }

            //icmp checked in source only.
            if (pkt->iphdr->protocol != IPPROTO_ICMP) {
                if (service_match(&rule->d_services, pkt->iphdr->protocol, pkt->protohdr->dport) != MATCH) { continue; }
            }
            // ------------------------------------------------------------------
            // MATCH ACTION | return rule options
            // ------------------------------------------------------------------
            // drop will inherently forward to the ip proxy for geo inspection and local dns records.
            pkt->fw_table = table_idx;
            pkt->rule_num = rule_idx; // if logging, this needs to be +1
            pkt->action   = rule->action;
            pkt->mark     = tracked_geo << FOUR_BITS | direction << TWO_BITS | rule->action;

            for (idx = 0; idx < 3; idx++) {
                pkt->mark |= rule->sec_profiles[idx] << ((idx*4)+12);
            }

            return;
        }
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->fw_table   = NO_SECTION;
    pkt->action     = DNX_DROP;
    pkt->mark       = tracked_geo << FOUR_BITS | direction << TWO_BITS | DNX_DROP;
}

void
firewall_lock(void)
{
    pthread_mutex_lock(FWlock_ptr);
}

void
firewall_unlock(void)
{
    pthread_mutex_unlock(FWlock_ptr);
}

void
firewall_update_count(uint8_t table_idx, uint16_t rule_count)
{
    firewall_tables[table_idx].len = rule_count;
}

int
firewall_set_rule(uint8_t table_idx, uint16_t rule_idx, struct FWrule *rule)
{
    firewall_tables[table_idx].rules[rule_idx] = *rule;

    return OK;
}

void
firewall_rule_print(uint8_t table_idx, uint16_t rule_idx)
{
    int     i;
    FWrule  rule = firewall_tables[table_idx].rules[rule_idx];

    printf("<<FIREWALL RULE [%u][%u]>>\n", table_idx, rule_idx);
    printf("enabled->%d\n", rule.enabled);

    printf("src_zones->[ ");
    for (i = 0; i < rule.s_zones.len; i++) {
        printf("%u ", rule.s_zones[i]);
    }
    printf(" ]\n");

    printf("src_networks->[ ");
    for (i = 0; i < rule.s_zones.len; i++) {
        printf("(%u, %u, %u) ", rule.s_networks[i].type, rule.s_networks[i].netid, rule.s_networks[i].netmask);
    }
    printf(" ]\n");

    // SRC SERVICES

    printf("dst_zones->[ ");
    for (i = 0; i < rule.d_zones.len; i++) {
        printf("%u ", rule.d_zones[i]);
    }
    printf(" ]\n");

    printf("dst_networks->[ ");
    for (i = 0; i < rule.d_zones.len; i++) {
        printf("(%u, %u, %u) ", rule.d_networks[i].type, rule.d_networks[i].netid, rule.d_networks[i].netmask);
    }
    printf(" ]\n");

    // DST SERVICES

    printf("action->%u\n", rule.action);
    printf("log->%u\n", rule.log);
    printf("ipp->%u, dns->%u, ips->%u\n", rule.sec_profiles[0], rule.sec_profiles[1], rule.sec_profiles[2])

//    SvcArray    s_services
//    SvcArray    d_services
}