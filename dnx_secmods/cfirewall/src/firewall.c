#include "config.h"
#include "firewall.h"
#include "cfirewall.h"
#include "rules.h"

#include "hash_trie.h"

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

pthread_mutex_t     FWtableslock;
pthread_mutex_t    *FWlock_ptr = &FWtableslock;

struct FWtable firewall_tables[FW_TABLE_COUNT];

/* FIREWALL RULES SWAP STORAGE
Python converted data will be placed here. This will allow the GIL to be released
before copying the data into the active rules. This comes at a somewhat substantial
hit to memory usage, but it will save alot of programming time by moving the need
for the fw socket/api to be implemented to correct the deadlock issue between the
Python GIL and the firewall or nat rule locks.
*/
struct FWtable fw_tables_swap[FW_TABLE_COUNT];

void
firewall_init(void) {
    pthread_mutex_init(FWlock_ptr, NULL);

    // arrays of pointers to FWrules
    firewall_tables[FW_SYSTEM_RULES].rules = calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(struct FWrule));
    firewall_tables[FW_BEFORE_RULES].rules = calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(struct FWrule));
    firewall_tables[FW_MAIN_RULES].rules   = calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(struct FWrule));
    firewall_tables[FW_AFTER_RULES].rules  = calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(struct FWrule));

    // SWAP STORAGE
    fw_tables_swap[FW_SYSTEM_RULES].rules = calloc(FW_SYSTEM_MAX_RULE_COUNT, sizeof(struct FWrule));
    fw_tables_swap[FW_BEFORE_RULES].rules = calloc(FW_BEFORE_MAX_RULE_COUNT, sizeof(struct FWrule));
    fw_tables_swap[FW_MAIN_RULES].rules   = calloc(FW_MAIN_MAX_RULE_COUNT, sizeof(struct FWrule));
    fw_tables_swap[FW_AFTER_RULES].rules  = calloc(FW_AFTER_MAX_RULE_COUNT, sizeof(struct FWrule));

    log_init(&Log[FW_LOG_IDX], "firewall");
}

// ==================================
// PRIMARY FIREWALL LOGIC
// ==================================
int
firewall_recv(nl_msg_hdr *nl_msgh, void *data)
{
    struct cfdata      *cfd = (struct cfdata*) data;
    struct nlattr      *netlink_attrs[NFQA_MAX+1] = {};
    struct dnx_pktb     pkt = {.logger = &Log[FW_LOG_IDX]};
    struct clist_range  fw_clist;

    nl_pkt_hdr     *nl_pkth = NULL;
//    nl_pkt_hw  *_hw;
    uint32_t        ct_info;

//    printf("< [++] FW RECV QUEUE(%u) - PARSING [++] >\n", cfd->queue);
    dnx_parse_nl_headers(nl_msgh, &nl_pkth, netlink_attrs, &pkt);
    /*
    CONNTRACK LOOKUP
    this should be checked as soon as feasibly possible for performance.
    this will be used to allow for stateless inspection policies later.
    NTOHL on id is because kernel will apply HTONL on receipt.
    */
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    if (ct_info != IP_CT_NEW) {
        dnx_send_verdict_fast(cfd, ntohl(nl_pkth->packet_id), 0, NF_ACCEPT);

        return OK;
    }
    /*
    SYSTEM RULES and PROXY_BYPASS will skip proxies and invoke the rule action directly
    otherwise will forward to ip proxy regardless of action for geolocation log or IPS
    */
    if (nl_pkth->hook == NF_IP_FORWARD) {
        fw_clist.start = FW_RULE_RANGE_START;
        if (!PROXY_BYPASS) {
            pkt.action = IP_PROXY << TWO_BYTES | NF_QUEUE;
        }
    }
    else if (nl_pkth->hook == NF_IP_LOCAL_IN) {
        fw_clist.start = FW_SYSTEM_RANGE_START;
    }

    fw_clist.end = FW_RULE_RANGE_END;
    // ===================================
    // FIREWALL RULES LOCK
    // prevents the manager thread from updating firewall rules during packet inspection.
    // consider locking around each control list. this would weave control list updates with inspection.
    firewall_lock();
    firewall_inspect(&fw_clist, &pkt, cfd);
    firewall_unlock();
    // UNLOCKING ACCESS TO FIREWALL RULES
    // ===================================

    // NFQUEUE VERDICT
    dnx_send_verdict(cfd, ntohl(nl_pkth->packet_id), &pkt);

    if (FW_V && VERBOSE) {
        printf("< -- FIREWALL VERDICT -- >\n");
        printf("packet_id->%u, hook->%u, mark->%u, action->%u", ntohl(nl_pkth->packet_id), nl_pkth->hook, pkt.mark, pkt.action);
        if (!PROXY_BYPASS) {
            printf(", ipp->%u, dns->%u, ips->%u", pkt.mark >> 12 & 15, pkt.mark >> 16 & 15, pkt.mark >> 20 & 15);
        }
        printf("\n=====================================================================\n");
    }

    // return hierarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    // < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK;
}

inline void
firewall_inspect(struct clist_range *fw_clist, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

    struct FWrule           *rule;
    struct HashTrie_Range   *geolocation = cfd->geolocation;

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
    uintf8_t    idx, cntrl_list, rule_idx;

    if (FW_V && VERBOSE) {
        printf("< ++ FIREWALL INSPECTION ++ >\n");
        printf("src->[%u]%u(%u):%u, dst->[%u]%u(%u):%u, direction->%u, tracked->%u\n",
            pkt->hw.in_zone, iph_src_ip, src_country, ntohs(pkt->protohdr->sport),
            pkt->hw.out_zone, iph_dst_ip, dst_country, ntohs(pkt->protohdr->dport),
            direction, tracked_geo);
    }

    for (cntrl_list = fw_clist->start; cntrl_list < fw_clist->end; cntrl_list++) {

        if (firewall_tables[cntrl_list].len == 0) { continue; }

        // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
        for (rule_idx = 0; rule_idx < firewall_tables[cntrl_list].len; rule_idx++) {

            rule = &firewall_tables[cntrl_list].rules[rule_idx];
            if (!rule->enabled) { continue; }

            if (FW_V && VERBOSE2) {
                firewall_print_rule(cntrl_list, rule_idx);
            }
            // ------------------------------------------------------------------
            // ZONE MATCHING
            // ------------------------------------------------------------------
            // currently tied to interface and designated LAN, WAN, DMZ
            if (zone_match(&rule->s_zones, pkt->hw.in_zone.id) != MATCH) { continue; }
            if (zone_match(&rule->d_zones, pkt->hw.out_zone.id) != MATCH) { continue; }

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
            pkt->rule_clist = cntrl_list;
            pkt->rule_num   = rule_idx+1; // if logging, this needs to be +1
            pkt->rule_name  = rule->name;
            pkt->action     = rule->action;
            pkt->mark       = tracked_geo << FOUR_BITS | direction << TWO_BITS | rule->action;

            for (idx = 0; idx < 3; idx++) {
                pkt->mark |= rule->sec_profiles[idx] << ((idx * 4) + 12);
            }

            goto logging;
        }
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->rule_clist = NO_SECTION;
    pkt->action     = DNX_DROP;
    pkt->mark       = tracked_geo << FOUR_BITS | direction << TWO_BITS | DNX_DROP;

    logging:
    if (rule->log) {
        // log file rotation logic
        log_enter(pkt->logger);
        log_write_firewall(pkt, direction, src_country, dst_country);
        log_exit(pkt->logger);
    }

//        pkt.hw.timestamp = time(NULL);
//        if (netlink_attrs[NFQA_HWADDR]) {
//            pkt.hw.mac_addr = ((nl_pkt_hw*) mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR]))->hw_addr;
//        }
//    }

}

void
firewall_lock(void)
{
    pthread_mutex_lock(FWlock_ptr);

    if (FW_V && VERBOSE) {
        printf("< [!] FW LOCK ACQUIRED [!] >\n");
    }
}

void
firewall_unlock(void)
{
    pthread_mutex_unlock(FWlock_ptr);

    if (FW_V && VERBOSE) {
        printf("< [!] FW LOCK RELEASED [!] >\n");
    }
}

int
firewall_stage_count(uintf8_t cntrl_list, uintf16_t rule_count)
{
    firewall_tables[cntrl_list].len = rule_count;

    if (FW_V && VERBOSE) {
        printf("< [!] FW TABLE (%u) COUNT STAGED [!] >\n", cntrl_list);
    }
    return OK;
}

int
firewall_stage_rule(uintf8_t cntrl_list, uintf16_t rule_idx, struct FWrule *rule)
{
    firewall_tables[cntrl_list].rules[rule_idx] = *rule;

    return OK;
}

int
firewall_push_rules(uintf8_t cntrl_list)
{
    firewall_lock();
    // iterating over each rule in FW table
    for (uintf16_t rule_idx = 0; rule_idx < fw_tables_swap[cntrl_list].len; rule_idx++) {

        // copy swap structure to active structure. alignment is already set as they are identical structures.
        firewall_tables[cntrl_list].rules[rule_idx] = fw_tables_swap[cntrl_list].rules[rule_idx];
    }
    firewall_unlock();

    if (FW_V && VERBOSE) {
        printf("< [!] FW TABLE (%u) RULES UPDATED [!] >\n", cntrl_list);
    }
    return OK;
}

int
firewall_push_zones(ZoneMap *zone_map)
{
    firewall_lock();

    for (intf8_t zone_idx = 0; zone_idx < FW_MAX_ZONES; zone_idx++) {
        INTF_ZONE_MAP[zone_idx] = zone_map[zone_idx];
    }

    firewall_unlock();

    return OK;
}

// casting to clamp uintfast to set unsigned ints to shut the warnings up.
void
firewall_print_rule(uintf8_t ctrl_list, uintf16_t rule_idx)
{
    int    i, ix;
    struct FWrule  rule = firewall_tables[ctrl_list].rules[rule_idx];

    printf("<<FIREWALL RULE [%u][%u]>>\n", (uint8_t) ctrl_list, (uint16_t) rule_idx);
    printf("enabled->%d\n", (uint8_t) rule.enabled);

    // SRC ZONES
    printf("src_zones->[ ");
    for (i = 0; i < rule.s_zones.len; i++) {
        printf("%u ", (uint8_t) rule.s_zones.objects[i]);
    }
    printf(" ]\n");

    // SRC NETWORKS
    printf("src_networks->[ ");
    for (i = 0; i < rule.s_networks.len; i++) {
        printf("(%u, %u, %u) ",
            (uint8_t) rule.s_networks.objects[i].type,
            (uint32_t) rule.s_networks.objects[i].netid,
            (uint32_t) rule.s_networks.objects[i].netmask);
    }
    printf(" ]\n");

    // SRC SERVICES
    for (i = 0; i < rule.s_services.len; i++) {
        printf("src_services->[ ");
        // TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (rule.s_services.objects[i].type == SVC_ICMP) {
            printf("(1, %u, %u) ",
                (uint8_t) rule.s_services.objects[i].icmp.type,
                (uint8_t) rule.s_services.objects[i].icmp.code);
        }
        // TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        else if (rule.s_services.objects[i].type == SVC_SOLO || rule.s_services.objects[i].type == SVC_RANGE) {
            printf("(%u, %u, %u) ",
                (uint16_t) rule.s_services.objects[i].svc.protocol,
                (uint16_t) rule.s_services.objects[i].svc.start_port,
                (uint16_t) rule.s_services.objects[i].svc.end_port);
        }
        // TYPE 3 (LIST) OBJECT ASSIGNMENT
        else {
            printf("< ");
            for (ix = 0; ix < rule.s_services.objects[i].svc_list.len; ix++) {
                // [0] START INDEX ON FW RULE SIZE
                // [1] START INDEX PYTHON DICT SIDE (to first index for size)
                printf("(%u, %u, %u) ",
                    (uint16_t) rule.s_services.objects[i].svc_list.services[ix].protocol,
                    (uint16_t) rule.s_services.objects[i].svc_list.services[ix].start_port,
                    (uint16_t) rule.s_services.objects[i].svc_list.services[ix].end_port);
            }
            printf(">");
        }
    }
    printf("]\n");

    // DST ZONES
    printf("dst_zones->[ ");
    for (i = 0; i < rule.d_zones.len; i++) {
        printf("%u ", (uint8_t) rule.d_zones.objects[i]);
    }
    printf(" ]\n");

    // DST NETWORK
    printf("dst_networks->[ ");
    for (i = 0; i < rule.d_networks.len; i++) {
        printf("(%u, %u, %u) ",
            (uint8_t) rule.d_networks.objects[i].type,
            (uint32_t) rule.d_networks.objects[i].netid,
            (uint32_t) rule.d_networks.objects[i].netmask);
    }
    printf(" ]\n");

    // DST SERVICES
    for (i = 0; i < rule.s_services.len; i++) {
        printf("dst_services->[ ");
        // TYPE 4 (ICMP) OBJECT ASSIGNMENT
        if (rule.d_services.objects[i].type == SVC_ICMP) {
            printf("(1, %u, %u) ",
                (uint8_t) rule.d_services.objects[i].icmp.type,
                (uint8_t) rule.d_services.objects[i].icmp.code);
        }
        // TYPE 1/2 (SOLO, RANGE) OBJECT ASSIGNMENT
        else if (rule.d_services.objects[i].type == SVC_SOLO || rule.d_services.objects[i].type == SVC_RANGE) {
            printf("(%u, %u, %u) ",
                (uint16_t) rule.d_services.objects[i].svc.protocol,
                (uint16_t) rule.d_services.objects[i].svc.start_port,
                (uint16_t) rule.d_services.objects[i].svc.end_port);
        }
        // TYPE 3 (LIST) OBJECT ASSIGNMENT
        else {
            printf("< ");
            for (ix = 0; ix < rule.d_services.objects[i].svc_list.len; ix++) {
                printf("(%u, %u, %u) ",
                    (uint16_t) rule.d_services.objects[i].svc_list.services[ix].protocol,
                    (uint16_t) rule.d_services.objects[i].svc_list.services[ix].start_port,
                    (uint16_t) rule.d_services.objects[i].svc_list.services[ix].end_port);
            }
            printf("> ");
        }
    }
    printf("]\n");

    // POLICIES
    printf("action->%u\n", (uint8_t) rule.action);
    printf("log->%u\n", (uint8_t) rule.log);
    printf("ipp->%u, dns->%u, ips->%u\n",
        (uint8_t) rule.sec_profiles[0],
        (uint8_t) rule.sec_profiles[1],
        (uint8_t) rule.sec_profiles[2]);
}

int
firewall_print_zones(void)
{
    return OK;
}