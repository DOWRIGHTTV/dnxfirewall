#include "config.h"
#include "firewall.h"
#include "cfirewall.h"
#include "rules.h"

#include "hash_trie.h"

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


struct FWtable firewall_tables[FW_TABLE_COUNT];

pthread_mutex_t     FWtableslock;
pthread_mutex_t    *FWlock_ptr = &FWtableslock;

// Python converted data will be placed here. This will allow the GIL to be released
// before copying the data into the active rules. This comes at a somewhat substantial
// hit to memory usage, but it will save alot of programming time by moving the need
// for the fw socket/api to be implemented to correct the deadlock issue between the
// Python GIL and the firewall or nat rule locks.
struct FWtable fw_tables_swap[FW_TABLE_COUNT];


void
firewall_init(void) {
    pthread_mutex_init(FWlock_ptr, NULL);

    // arrays of pointers to FWrules
    firewall_tables[FW_SYSTEM_RULES].len = 0;
    firewall_tables[FW_SYSTEM_RULES].rules = calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(struct FWrule));

    firewall_tables[FW_BEFORE_RULES].len = 0;
    firewall_tables[FW_BEFORE_RULES].rules = calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(struct FWrule));

    firewall_tables[FW_MAIN_RULES].len = 0;
    firewall_tables[FW_MAIN_RULES].rules = calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(struct FWrule));

    firewall_tables[FW_AFTER_RULES].len = 0;
    firewall_tables[FW_AFTER_RULES].rules = calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(struct FWrule));

    // SWAP STORAGE
    fw_tables_swap[FW_SYSTEM_RULES].len = 0;
    fw_tables_swap[FW_SYSTEM_RULES].rules = calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(struct FWrule));

    fw_tables_swap[FW_BEFORE_RULES].len = 0;
    fw_tables_swap[FW_BEFORE_RULES].rules = calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(struct FWrule));

    fw_tables_swap[FW_MAIN_RULES].len = 0;
    fw_tables_swap[FW_MAIN_RULES].rules = calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(struct FWrule));

    firewall_tables[FW_AFTER_RULES].len = 0;
    firewall_tables[FW_AFTER_RULES].rules = calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(struct FWrule));


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

    printf("< [++] FW RECV QUEUE(%u) - PARSING [++] >\n", cfd->queue);

    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = (nl_pkt_hdr*) mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);
    // ======================
    // CONNTRACK
    // this should be checked as soon as feasibly possible for performance.
    // this will be used to allow for stateless inspection policies later.
    // NTOHL on id is because kernel will apply HTONL on receipt
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    if (ct_info != IP_CT_NEW) {
        dnx_send_verdict_fast(cfd, ntohl(nlhdr->packet_id), NF_ACCEPT);

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
        default:
            printf("< [--!] FW HOOK MISMATCH (%u) - EXITING [!--] >\n", nlhdr->hook);
            return ERR;
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
    dnx_send_verdict(cfd, ntohl(nlhdr->packet_id), &pkt);

    if (FW_V && VERBOSE) {
        printf("< -- FIREWALL VERDICT -- >\n");
        printf("packet_id->%u, hook->%u, mark->%u, action->%u", ntohl(nlhdr->packet_id), nlhdr->hook, _mark, pkt.action);
        if (!PROXY_BYPASS) {
            printf(", ipp->%u, dns->%u, ips->%u", pkt.mark >> 12 & 15, pkt.mark >> 16 & 15, pkt.mark >> 20 & 15);
        }
        printf("\n=====================================================================\n");
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

    struct HashTrie_Range *geolocation = cfd->geolocation;

    struct FWrule     *rule;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = geolocation->lookup(geolocation, iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = geolocation->lookup(geolocation, iph_dst_ip & MSB, iph_dst_ip & LSB);

    // general direction of the packet and ip addr normalized to always be the external host/ip
    uint8_t     direction   = pkt->hw.in_zone != WAN_IN ? OUTBOUND : INBOUND;
    uint16_t    tracked_geo = direction == INBOUND ? src_country : dst_country;

    // loops
    uintf8_t    idx, table_idx, rule_idx;

    if (FW_V && VERBOSE) {
        printf("< ++ FIREWALL INSPECTION ++ >\n");
        printf("src->%u(%u):%u, dst->%u(%u):%u, direction->%u, tracked->%u\n",
            iph_src_ip, src_country, ntohs(pkt->protohdr->sport),
            iph_dst_ip, dst_country, ntohs(pkt->protohdr->dport),
            direction, tracked_geo
            );
    }

    // is the end index +1?
    for (table_idx = fw_tables->start; table_idx < fw_tables->end; table_idx++) {

        if (firewall_tables[table_idx].len == 0) { continue; }

        // same as above
        for (rule_idx = 0; rule_idx < firewall_tables[table_idx].len; rule_idx++) {

            rule = &firewall_tables[table_idx].rules[rule_idx];

            // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
            if (!rule->enabled) { continue; }

            if (FW_V && VERBOSE2) {
                firewall_print_rule(table_idx, rule_idx);
            }
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
            if (service_match(&rule->s_services, pkt->iphdr->protocol, ntohs(pkt->protohdr->sport)) != MATCH) { continue; }

            //icmp checked in source only.
            if (pkt->iphdr->protocol != IPPROTO_ICMP) {
                if (service_match(&rule->d_services, pkt->iphdr->protocol, ntohs(pkt->protohdr->dport)) != MATCH) { continue; }
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

    printf("< [!] FW LOCK ACQUIRED [!] >\n");
}

void
firewall_unlock(void)
{
    pthread_mutex_unlock(FWlock_ptr);

    printf("< [!] FW LOCK RELEASED [!] >\n");
}

int
firewall_stage_count(uintf8_t table_idx, uintf16_t rule_count)
{
    firewall_tables[table_idx].len = rule_count;

    printf("< [!] FW TABLE (%u) COUNT STAGED [!] >\n", table_idx);

    return OK;
}

int
firewall_stage_rule(uintf8_t table_idx, uintf16_t rule_idx, struct FWrule *rule)
{
    firewall_tables[table_idx].rules[rule_idx] = *rule;

    return OK;
}

int
firewall_push_rules(uintf8_t table_idx)
{
    firewall_lock();
    // iterating over each rule in FW table
    for (uintf8_t rule_idx = 0; rule_idx < fw_tables_swap[table_idx].len; rule_idx++) {

        // copy swap structure to active structure. alignment is already set as they are idential structures.
        firewall_tables[table_idx].rules[rule_idx] = fw_tables_swap[table_idx].rules[rule_idx];
    }
    firewall_unlock();

    printf("< [!] FW TABLE (%u) RULES UPDATED [!] >\n", table_idx);

    return OK;
}

int
firewall_push_zones(uintf8_t *zone_map)
{
    firewall_lock();

    for (intf8_t zone_idx = 0; zone_idx < FW_MAX_ZONES; zone_idx++) {
        INTF_ZONE_MAP[zone_idx] = zone_map[zone_idx];
    }

    firewall_unlock();

    return OK;
}

void
firewall_print_rule(uintf8_t table_idx, uintf16_t rule_idx)
{
    int    i, ix;
    struct FWrule  rule = firewall_tables[table_idx].rules[rule_idx];

    printf("<<FIREWALL RULE [%u][%u]>>\n", table_idx, rule_idx);
    printf("enabled->%d\n", rule.enabled);

    // SRC ZONES
    printf("src_zones->[ ");
    for (i = 0; i < rule.s_zones.len; i++) {
        printf("%u ", rule.s_zones.objects[i]);
    }
    printf(" ]\n");

    // SRC NETWORKS
    printf("src_networks->[ ");
    for (i = 0; i < rule.s_networks.len; i++) {
        printf("(%u, %u, %u) ",
            rule.s_networks.objects[i].type,
            rule.s_networks.objects[i].netid,
            rule.s_networks.objects[i].netmask);
    }
    printf(" ]\n");

    // SRC SERVICES
    for (i = 0; i < rule.s_services.len; i++) {
        printf("src_services->[ ");
        // TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (rule.s_services.objects[i].type == SVC_ICMP) {
            printf("(1, %u, %u) ",
                rule.s_services.objects[i].icmp.type,
                rule.s_services.objects[i].icmp.code);
        }
        // TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        else if (rule.s_services.objects[i].type == SVC_SOLO || rule.s_services.objects[i].type == SVC_RANGE) {
            printf("(%u, %u, %u) ",
                rule.s_services.objects[i].svc.protocol,
                rule.s_services.objects[i].svc.start_port,
                rule.s_services.objects[i].svc.end_port);
        }
        // TYPE 3 (LIST) OBJECT ASSIGNMENT
        else {
            printf("< ");
            for (ix = 0; ix < rule.s_services.objects[i].svc_list.len; ix++) {
                // [0] START INDEX ON FW RULE SIZE
                // [1] START INDEX PYTHON DICT SIDE (to first index for size)
                printf("(%u, %u, %u) ",
                    rule.s_services.objects[i].svc_list.services[ix].protocol,
                    rule.s_services.objects[i].svc_list.services[ix].start_port,
                    rule.s_services.objects[i].svc_list.services[ix].end_port);
            }
            printf(">");
        }
    }
    printf("]\n");

    // DST ZONES
    printf("dst_zones->[ ");
    for (i = 0; i < rule.d_zones.len; i++) {
        printf("%u ", rule.d_zones.objects[i]);
    }
    printf(" ]\n");

    // DST NETWORK
    printf("dst_networks->[ ");
    for (i = 0; i < rule.d_networks.len; i++) {
        printf("(%u, %u, %u) ",
            rule.d_networks.objects[i].type,
            rule.d_networks.objects[i].netid,
            rule.d_networks.objects[i].netmask);
    }
    printf(" ]\n");

    // DST SERVICES
    for (i = 0; i < rule.s_services.len; i++) {
        printf("dst_services->[ ");
        // TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (rule.d_services.objects[i].type == SVC_ICMP) {
            printf("(1, %u, %u) ",
                rule.d_services.objects[i].icmp.type,
                rule.d_services.objects[i].icmp.code);
        }
        // TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        else if (rule.d_services.objects[i].type == SVC_SOLO || rule.d_services.objects[i].type == SVC_RANGE) {
            printf("(%u, %u, %u) ",
                rule.d_services.objects[i].svc.protocol,
                rule.d_services.objects[i].svc.start_port,
                rule.d_services.objects[i].svc.end_port);
        }
        // TYPE 3 (LIST) OBJECT ASSIGNMENT
        else {
            printf("< ");
            for (ix = 0; ix < rule.d_services.objects[i].svc_list.len; ix++) {
                // [0] START INDEX ON FW RULE SIZE
                // [1] START INDEX PYTHON DICT SIDE (to first index for size)
                printf("(%u, %u, %u) ",
                    rule.d_services.objects[i].svc_list.services[ix].protocol,
                    rule.d_services.objects[i].svc_list.services[ix].start_port,
                    rule.d_services.objects[i].svc_list.services[ix].end_port);
            }
            printf("> ");
        }
    }
    printf("]\n");

    // POLICIES
    printf("action->%u\n", rule.action);
    printf("log->%u\n", rule.log);
    printf("ipp->%u, dns->%u, ips->%u\n",
        rule.sec_profiles[0],
        rule.sec_profiles[1],
        rule.sec_profiles[2]);
}

int
firewall_print_zones(void)
{
    return OK;
}