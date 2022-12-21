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
#define IP_PROXY_MASK  15
#define DNS_PROXY_MASK 240
#define IPS_IDS_MASK   3840

#define PACKET_ACTION_MASK 3 // first 2 bits
#define PACKET_DIR_MASK    12 // 2nd 2 bits

#define SEND_TO_IP_PROXY  (IP_PROXY  << TWO_BYTES) | NF_QUEUE)
#define SEND_TO_IPS_IDS   (IPS_IDS   << TWO_BYTES) | NF_QUEUE)
#define SEND_TO_DNS_PROXY (DNS_PROXY << TWO_BYTES) | NF_QUEUE)

// ==================================
// Firewall tables access lock
// ==================================
// Must be held to read from or make
// changes to "*firewall_tables[]"
pthread_mutex_t     FWtableslock;
pthread_mutex_t    *FWlock_ptr = &FWtableslock;

// ==================================
// FIREWALL TABLES
// ==================================
// contains pointers to arrays of pointers to FWrule and its length
struct FWtable firewall_tables[FW_TABLE_COUNT];

// ==================================
// FIREWALL RULES SWAP STORAGE
// ==================================
// Python converted data will be placed here. This will allow the GIL to be released before copying the data into the
// active rules. This comes at a somewhat substantial hit to memory usage, but it will save alot of programming time by
// moving the need for the fw socket/api to be implemented to correct the deadlock issue between the Python GIL and the
// firewall or nat rule locks.
struct FWtable fw_tables_swap[FW_TABLE_COUNT];

// global reference to the firewalls logger struct
struct LogHandle *FW_LOG_HANDLER = &Log[FW_LOG_IDX];

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

    log_init(FW_LOG_HANDLER, "firewall");

    log_db_init();
}

// ==================================
// PRIMARY FIREWALL LOGIC
// ==================================
int
firewall_recv(nl_msg_hdr *nl_msgh, void *data)
{
    struct cfdata      *cfd = (struct cfdata*) data;
    struct nlattr      *netlink_attrs[NFQA_MAX+1] = {};
    nl_pkt_hdr         *nl_pkth = NULL;

    struct dnx_pktb     pkt = {};

    dnx_parse_nl_headers(nl_msgh, &nl_pkth, netlink_attrs, &pkt);

    // TODO: we need to do more research into this and whether its necessary or just masking a bug
    if (!netlink_attrs[NFQA_CT_INFO]) {
        dnx_send_verdict(cfd, ntohl(nl_pkth->packet_id), NF_DROP);
        dprint(FW_V & VERBOSE, "NO CONNTRACK INFO - PACKET DISCARDED\n");

        return OK;
    }
    // note: this should no longer be needed since we went back to kernel offloading for stateful via connmarks
    /* ===================================
       CONNTRACK LOOKUP
    =================================== */
    //uint32_t  ct_info;
    // this should be checked as soon as feasibly possible for performance. later, this will be used to allow for
    // stateless inspection policies. NTOHL on id is because kernel will apply HTONL on receipt.
    //ct_info = ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_CT_INFO]));
    //if (ct_info != IP_CT_NEW) {
    //    dnx_send_verdict(cfd, ntohl(nl_pkth->packet_id), NF_ACCEPT);

    //    return OK;
    //}

    /* ===================================
       FIREWALL INSPECTION
    =================================== */
    struct clist_range  fw_clist = { .end = FW_RULE_RANGE_END };
    if (nl_pkth->hook == NF_IP_FORWARD)
        fw_clist.start = FW_RULE_RANGE_START;

    // the lock prevents the manager thread from updating firewall rules during packet inspection.
    // consider locking around each control list. this would weave control list updates with inspection.
    firewall_lock();
    firewall_inspect(&fw_clist, &pkt, cfd);
    firewall_unlock();

    dprint(FW_V & VERBOSE, "pkt_id->%u, hook->%u, action->%u, log->%u, ipp->%u, dns->%u, ips->%u ", ntohl(nl_pkth->packet_id),
        nl_pkth->hook, pkt.action, pkt.log, pkt.sec_profiles & 4, pkt.sec_profiles >> 4 & 4, pkt.sec_profiles >> 8 & 4);

    /* ===================================
       NFQUEUE VERDICT LOGIC
    =================================== */
    // PACKET MARK -> X (16b, reserved) | X (4b) | geo loc (8b) | direction (2b) | action (2b)
    uint16_t pkt_mark = (pkt.geo.remote << FOUR_BITS) | (pkt.geo.dir << TWO_BITS) | pkt.action;

    // SEND TO IP PROXY - criteria: accepted, inbound or outbound
    if (pkt.action == DNX_ACCEPT // primary match
            && pkt.sec_profiles & IP_PROXY_MASK ) {

        dnx_send_deferred_verdict(cfd, ntohl(nl_pkth->packet_id),
            (pkt.sec_profiles << TWO_BYTES) | pkt_mark, SEND_TO_IP_PROXY;
    }
    // SEND TO IPS/IDS - criteria: accepted or dropped, inbound
    else if (pkt.geo.dir == INBOUND // primary match
            && pkt.sec_profiles & IPS_IDS_MASK ) {

        dnx_send_deferred_verdict(cfd, ntohl(nl_pkth->packet_id),
            (pkt.sec_profiles << TWO_BYTES) | pkt_mark, SEND_TO_IPS_IDS;
    }
    // SEND TO DNS PROXY - criteria: accepted, outbound, udp/53
    else if (pkt.action == DNX_ACCEPT // primary match
            && pkt.geo.dir == OUTBOUND
            && pkt.sec_profiles & DNS_PROXY_MASK
            && pkt.iphdr->protocol == IPPROTO_UDP
            && pkt.protohdr->dport == UDPPROTO_DNS ) {

        dnx_send_deferred_verdict(cfd, ntohl(nl_pkth->packet_id),
            (pkt.sec_profiles << TWO_BYTES) | pkt_mark, SEND_TO_DNS_PROXY;
    }
    // default: accept w/o sec policy, system rules, drop action w/o ips
    else {
        dnx_send_verdict(cfd, ntohl(nl_pkth->packet_id), pkt.action);
    }

    dprint(FW_V & VERBOSE, "(verdict)");

    /* ===================================
       GEOLOCATION MONITORING - GENERAL
    =================================== */
    // non system traffic only. remote country to or from and packet action
    if (fw_clist.start != FW_SYSTEM_RANGE_START) {
        log_db_geolocation(&pkt.geo, pkt.action);

        dprint(FW_V & VERBOSE, "[geo]");
    }

    /* ===================================
       TRAFFIC LOGGING
    =================================== */
    struct timeval  timestamp; // used only when packet is marked for logging
    // logs entry for packet on disk
    // todo: see about running a threaded logger queue so packet processing can continue immediately.
    //   - this might be more pain than whats its worth since we use stack allocation for pktb struct.
    if (pkt.log) {
        gettimeofday(&timestamp, NULL);

        // log file rotation logic
        log_enter(FW_LOG_HANDLER, &timestamp);
        log_write_firewall(FW_LOG_HANDLER, &timestamp, &pkt);
        log_exit(FW_LOG_HANDLER);
    }

    dprint(FW_V & VERBOSE, "\n");

    // return hierarchy -> libnfnetlink.c >> libnetfiler_queue >> process_traffic.
    // < 0 vals are errors, but return is being ignored by CFirewall._run.
    return OK;
}

void
firewall_inspect(struct clist_range *fw_clist, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

    struct FWtable          *control_list;
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

    dprint(FW_V & VERBOSE, "<PACKET> src->[%u]%u(%u):%u, dst->[%u]%u(%u):%u, direction->%u, tracked->%u\n",
        pkt->hw.in_zone.id, iph_src_ip, src_country, ntohs(pkt->protohdr->sport),
        pkt->hw.out_zone.id, iph_dst_ip, dst_country, ntohs(pkt->protohdr->dport),
        direction, tracked_geo);

    // iterating over specified control lists
    for (uintf8_t clist_idx = fw_clist->start; clist_idx < fw_clist->end; clist_idx++) {

        control_list = &firewall_tables[clist_idx];

        // iterating over each rule in the list
        for (uintf8_t rule_idx = 0; rule_idx <= control_list->len; rule_idx++) {

            rule = &control_list->rules[rule_idx];

            if (!rule->enabled) { continue; }

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

            // icmp checked in source only.
            if (pkt->iphdr->protocol != IPPROTO_ICMP) {
                if (service_match(&rule->d_services, pkt->iphdr->protocol, ntohs(pkt->protohdr->dport)) != MATCH) { continue; }
            }
            // ------------------------------------------------------------------
            // MATCH ACTION | return rule options
            // ------------------------------------------------------------------
            pkt->rule_clist = clist_idx;
            pkt->rule_name  = rule->name;
            pkt->action     = rule->action; // required to allow for default action
            pkt->log        = rule->log;

            for (uintf8_t idx = 0; idx < SECURITY_PROFILE_COUNT; idx++) {
                pkt->sec_profiles |= rule->sec_profiles[idx] << ((idx * 4));
            }
            goto geolocation;
        }
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->rule_clist = NO_SECTION;
    pkt->action     = DNX_DROP;
    pkt->log        = 0;

geolocation:
    pkt->geo.src    = src_country;
    pkt->geo.dst    = dst_country;
    pkt->geo.dir    = direction;
    pkt->geo.remote = tracked_geo;
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

    dprint(FW_V & VERBOSE, "< [!] FW TABLE (%u) RULES UPDATED [!] >\n", cntrl_list);

    firewall_unlock();

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