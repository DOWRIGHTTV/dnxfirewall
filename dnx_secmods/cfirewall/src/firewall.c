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
#define FW_RULE_RANGE_END     3 // inclusive

#define SECURITY_PROFILE_COUNT 3
#define PROFILE_SIZE   4  // bits
#define PROFILE_START 12
#define PROFILE_STOP  (SECURITY_PROFILE_COUNT * 4) + 8 // + 1  // +1 for range

#define PACKET_ACTION_MASK 3 // first 2 bits

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

    // verdict default defers to IP_PROXY for logging geolocation
    // TODO: see if we can get the geo only log moved to cfirewall to prevent denies from needing to be forwarded
    struct dnx_pktb     pkt = {};
    struct clist_range  fw_clist;

    nl_pkt_hdr     *nl_pkth = NULL; // TODO: see if we can skip initialization since dnx_nfqueue will set this value
    uint32_t        ct_info;

    dnx_parse_nl_headers(nl_msgh, &nl_pkth, netlink_attrs, &pkt);
    /*
    CONNTRACK LOOKUP
    this should be checked as soon as feasibly possible for performance.
    later, this will be used to allow for stateless inspection policies.
    NTOHL on id is because kernel will apply HTONL on receipt.
    */
    ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    if (ct_info != IP_CT_NEW) {
        dnx_send_verdict_fast(cfd, ntohl(nl_pkth->packet_id), 0, NF_ACCEPT);

        return OK;
    }
    // PASSTHROUGH TRAFFIC
    if (nl_pkth->hook == NF_IP_FORWARD) {
        fw_clist.start = FW_RULE_RANGE_START;
    }
    // LOCAL SYSTEM TRAFFIC
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
#if DEVELOPMENT
    if (PROXY_BYPASS) {
        pkt.verdict = pkt.fw_rule->action; // this tells cfirewall to take control instead of forward to proxy
        dprint(FW_V & VERBOSE, " PROXY BYPASS ON");
    }
#endif

    dprint(FW_V & VERBOSE, "<0=FW VERDICT=0>\npkt_id->%u, hook->%u, mark->%u, verdict->%u, ipp->%u, dns->%u, ips->%u",
        ntohl(nl_pkth->packet_id), nl_pkth->hook, pkt.mark, pkt.verdict,
        pkt.mark >> 12 & FOUR_BITS, pkt.mark >> 16 & FOUR_BITS, pkt.mark >> 20 & FOUR_BITS
    );

    dprint(FW_V & VERBOSE, " (VERDICT SENT)\n");

    // NFQUEUE VERDICT
    // drops will inherently forward to the ip proxy for geo inspection and local dns records.
    dnx_send_verdict_fast(cfd, ntohl(nl_pkth->packet_id), pkt.mark, pkt.verdict);
    // ===================================

    // return hierarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    // < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK;
}

inline void
firewall_inspect(struct clist_range *fw_clist, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

    struct timeval timestamp;

    struct FWrule           *rule;
    struct HashTrie_Range   *geolocation = cfd->geolocation;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = geolocation->lookup(geolocation, iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = geolocation->lookup(geolocation, iph_dst_ip & MSB, iph_dst_ip & LSB);

    // general direction of the packet and ip addr normalized to always be the external host/ip
    uint8_t     direction   = pkt->hw.in_zone.id != WAN_IN ? OUTBOUND : INBOUND;
    uint16_t    tracked_geo = direction == INBOUND ? src_country : dst_country;

    // local flag to mark for traffic logging
    uintf8_t    log_packet = 0;

    dprint(FW_V & VERBOSE, "< ++ FIREWALL INSPECTION ++ >\nsrc->[%u]%u(%u):%u, dst->[%u]%u(%u):%u, direction->%u, tracked->%u\n",
        pkt->hw.in_zone.id, iph_src_ip, src_country, ntohs(pkt->protohdr->sport),
        pkt->hw.out_zone.id, iph_dst_ip, dst_country, ntohs(pkt->protohdr->dport),
        direction, tracked_geo);

    for (uintf8_t cntrl_list = fw_clist->start; cntrl_list < fw_clist->end; cntrl_list++) {

        for (uintf8_t rule_idx = 0; rule_idx <= firewall_tables[cntrl_list].len; rule_idx++) {

            rule = &firewall_tables[cntrl_list].rules[rule_idx];
            if (!rule->enabled) { continue; }

#if DEVELOPMENT
            // TODO: find a better/ more useful way to show this info without being too spammy and uses dprint
            if (FW_V & VERBOSE2) firewall_print_rule(cntrl_list, rule_idx);
#endif
            // inspection order: src > dst | zone, ip_addr, protocol, port
            // ------------------------------------------------------------------
            // ZONE MATCHING
            // ------------------------------------------------------------------
            // currently tied to interface and designated LAN, WAN, DMZ
            if (zone_match(&rule->s_zones, pkt->hw.in_zone.id)  != MATCH) { continue; }
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
            pkt->rule_clist = cntrl_list;
            pkt->fw_rule    = rule;
            pkt->mark      |= (tracked_geo << FOUR_BITS) | (direction << TWO_BITS) | rule->action;

            for (uintf8_t idx = 0; idx < 3; idx++) {
                pkt->mark |= rule->sec_profiles[idx] << ((idx * 4) + 12);
            }

            // 0. SYSTEM RULE -> direct invocation || 1-3. STANDARD RULE -> forward to IP_PROXY
            pkt->verdict = (cntrl_list == FW_SYSTEM_RANGE_START) ? rule->action : (IP_PROXY << TWO_BYTES) | NF_QUEUE;

            log_packet = rule->log;

            goto logging;
        }
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->rule_clist = NO_SECTION;
    pkt->verdict    = (IP_PROXY << TWO_BYTES) | NF_QUEUE
    pkt->mark       = (tracked_geo << FOUR_BITS) | (direction << TWO_BITS) | DNX_DROP;

    logging:
    if (log_packet) {
        gettimeofday(&timestamp, NULL);

        // log file rotation logic
        log_enter(&timestamp, &Log[FW_LOG_IDX]);
        log_write_firewall(&timestamp, pkt, direction, src_country, dst_country);
        log_exit(&Log[FW_LOG_IDX]);
    }

//    if (netlink_attrs[NFQA_HWADDR]) {
//        pkt.hw.mac_addr = ((nl_pkt_hw*) mnl_attr_get_payload(netlink_attrs[NFQA_HWADDR]))->hw_addr;
//    }
}

void
firewall_lock(void)
{
    pthread_mutex_lock(FWlock_ptr);

    dprint(FW_V & VERBOSE, "< [!] FW LOCK ACQUIRED [!] >\n");
}

void
firewall_unlock(void)
{
    pthread_mutex_unlock(FWlock_ptr);

    dprint(FW_V & VERBOSE, "< [!] FW LOCK RELEASED [!] >\n");
}

int
firewall_stage_count(uintf8_t cntrl_list, uintf16_t rule_count)
{
    fw_tables_swap[cntrl_list].len = rule_count;

    dprint(FW_V & VERBOSE, "< [!] FW TABLE (%u) COUNT STAGED [!] >\n", cntrl_list);

    return OK;
}

int
firewall_stage_rule(uintf8_t cntrl_list, uintf16_t rule_idx, struct FWrule *rule)
{
    fw_tables_swap[cntrl_list].rules[rule_idx] = *rule;

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
    firewall_tables[cntrl_list].len = fw_tables_swap[cntrl_list].len;

    firewall_unlock();

    dprint(FW_V & VERBOSE, "< [!] FW TABLE (%u) RULES UPDATED [!] >\n", cntrl_list);

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