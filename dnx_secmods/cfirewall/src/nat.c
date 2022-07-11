#include "config.h"
#include "nat.h"
#include "cfirewall.h"
#include "rules.h"
#include "conntrack.h"

#include "hash_trie.h"

#define NAT_PRE_MAX_RULE_COUNT  100
#define NAT_POST_MAX_RULE_COUNT 100

#define NAT_PRE_TABLE  0
#define NAT_POST_TABLE 1

pthread_mutex_t     NATtableslock;
pthread_mutex_t    *NATlock_ptr = &NATtableslock;

struct NATtable nat_tables[NAT_TABLE_COUNT];

/* FIREWALL RULES SWAP STORAGE */
struct NATtable nat_tables_swap[NAT_TABLE_COUNT];

void
nat_init(void) {
    pthread_mutex_init(NATlock_ptr, NULL);

    // arrays of pointers to NATrule
    nat_tables[NAT_PRE_RULES].rules = calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(struct NATrule));
    nat_tables[NAT_POST_RULES].rules = calloc(NAT_POST_MAX_RULE_COUNT, sizeof(struct NATrule));

    // SWAP STORAGE
    nat_tables_swap[NAT_PRE_RULES].rules = calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(struct NATrule));
    nat_tables_swap[NAT_POST_RULES].rules = calloc(NAT_POST_MAX_RULE_COUNT, sizeof(struct NATrule));

    // conntrack socket
    ct_nat_init();
}

/*================================
  PRIMARY NAT LOGIC
==================================
SRC_NAT - this will be done in the post_route hook, but pass through the pre_route hook first.
because of this we can pass up the in-interface to pull the source zone for nat rule matching logic.
the interface index will be passed up through the packet mark.

MASQUERADE - follows all SRC_NAT logic, but it will use the ip of the outbound interface as the nat source.

DST_NAT - this will be done in the pre_route hook. since we cannot determine the outbound interface until the
destination has been changed, we cannot use the zone as for destination matching criteria.
the corresponding firewall rule needs to use the destination zone for matching criteria since it is post_route.

NOTES: we should try moving the nat logic to mangle/ forward hook. this would give us access to in/out inteface
for src/dst nat rules, but at the cost of having to manually check state of each packet and accept. the performance
hit might not be worth it for what our current goals are. also, though we would be able to have an dst zone on src nat,
the dst zone would need to be set to the zone for the dst pre nat, which would be equally wonky to no zone at all.
*/
int
nat_recv(nl_msg_hdr *nl_msgh, void *data)
{
    struct cfdata      *cfd = (struct cfdata*) data;
    struct nlattr      *netlink_attrs[NFQA_MAX+1] = {};
    struct dnx_pktb     pkt;

    nl_pkt_hdr         *nl_pkth = NULL;
    int                 cntrl_list = 0;

    printf("< [++] NAT RECV QUEUE(%u) - PARSING [++] >\n", cfd->queue);
//    memset(&pkt, 0, sizeof(struct dnx_pktb));
    dnx_parse_nl_headers(nl_msgh, &nl_pkth, netlink_attrs, &pkt);

    // made if block to expand logic, but unsure how to handle that for now.
    if (nl_pkth->hook == NF_IP_PRE_ROUTING) {
        cntrl_list = NAT_PRE_TABLE;
    }
    else if (nl_pkth->hook == NF_IP_POST_ROUTING) {
        cntrl_list = NAT_POST_TABLE;
    }
    // NO RULES CONFIGURED QUICK PATH
    // in-intf needs to be put into network order before sending to netfilter.
    if (nat_tables[cntrl_list].len == 0) {
        dnx_send_verdict_fast(cfd, ntohl(nl_pkth->packet_id), 0, NF_ACCEPT);

        return OK;
    }
    // ===================================
    // LOCKING ACCESS TO NAT RULES
    // prevents the manager thread from updating nat rules during packet inspection
    nat_lock();
    nat_inspect(cntrl_list, &pkt, cfd);
    nat_unlock();
    // UNLOCKING ACCESS TO NAT RULES
    // ===================================

    // NAT / MANGLE
    // MASQUERADE needs to mangle before
    if (pkt.action == DNX_MASQ) {
        pkt.mangled = dnx_mangle_pkt(&pkt);
        ct_nat_update(&pkt);

        // masquerade requires a deferred mangle to not conflict with conntrack tuple
        pkt.iphdr->saddr = pkt.nat.saddr;
    }
    else if (pkt.action > DNX_NO_NAT) {
        ct_nat_update(&pkt);
        pkt.mangled = dnx_mangle_pkt(&pkt);
    }
    // need to reduce DNX_* to DNX_ACCEPT on nat rule matches.
    if (pkt.action >= DNX_NO_NAT) {
        pkt.action = DNX_ACCEPT;
    }

    dnx_send_verdict(cfd, ntohl(nl_pkth->packet_id), &pkt);

    if (NAT_V && VERBOSE) {
        printf("< [--] NAT VERDICT [--] >\n");
        printf("packet_id->%u, hook->%u, rule->%s, action->%u\n",
            ntohl(nl_pkth->packet_id), nl_pkth->hook, pkt.rule->name, pkt.action);
        printf("=====================================================================\n");
    }

    return OK;
}

inline void
nat_inspect(int cntrl_list, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

    struct NATrule  *rule;

    struct HashTrie_Range *geolocation = cfd->geolocation;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = geolocation->lookup(geolocation, iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = geolocation->lookup(geolocation, iph_dst_ip & MSB, iph_dst_ip & LSB);

    if (NAT_V && VERBOSE) {
        printf("< [**] NAT INSPECTION [**] >\n");
        printf("src->[%u]%u:%u, dst->[%u]%u:%u\n",
            pkt->hw.in_zone, iph_src_ip, ntohs(pkt->protohdr->sport),
            pkt->hw.out_zone, iph_dst_ip, ntohs(pkt->protohdr->dport)
            );
    }

    for (uintf16_t rule_idx = 0; rule_idx < nat_tables[cntrl_list].len; rule_idx++) {

        rule = &nat_tables[cntrl_list].rules[rule_idx];
        if (!rule->enabled) { continue; }

        if (NAT_V && VERBOSE2) {
            nat_print_rule(cntrl_list, rule_idx);
        }

        // inspection order: src > dst | zone, ip_addr, protocol, port
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
        // MATCH ACTION | rule details
        // ------------------------------------------------------------------
        pkt->rule_clist = cntrl_list;
        pkt->rule       = rule; // if logging, this needs to be +1 to reflect true rule number
        pkt->action     = rule->action;

        pkt->nat = rule->nat;

        return;
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->rule_clist = NO_SECTION;
    pkt->rule_num   = 0;
    pkt->action     = DNX_ACCEPT;
}

void
nat_lock(void)
{
    pthread_mutex_lock(NATlock_ptr);

    printf("< [!] NAT LOCK ACQUIRED [!] >\n");
}

void
nat_unlock(void)
{
    pthread_mutex_unlock(NATlock_ptr);

    if (NAT_V && VERBOSE) {
        printf("< [!] NAT LOCK RELEASED [!] >\n");
    }
}

int
nat_stage_count(uintf8_t cntrl_list, uintf16_t rule_count)
{
    nat_tables[cntrl_list].len = rule_count;

    if (NAT_V && VERBOSE) {
        printf("< [!] NAT TABLE (%u) COUNT STAGED [!] >\n", cntrl_list);
    }
    return OK;
}

int
nat_stage_rule(uintf8_t cntrl_list, uintf16_t rule_idx, struct NATrule *rule)
{
    nat_tables[cntrl_list].rules[rule_idx] = *rule;

    return OK;
}

int
nat_push_rules(uintf8_t cntrl_list)
{
    nat_lock();
    // iterating over each rule in NAT table
    for (uintf16_t rule_idx = 0; rule_idx < nat_tables_swap[cntrl_list].len; rule_idx++) {

        // copy swap structure to active structure. alignment is already set as they are idential structures.
        nat_tables[cntrl_list].rules[rule_idx] = nat_tables_swap[cntrl_list].rules[rule_idx];
    }
    nat_unlock();

    if (NAT_V && VERBOSE) {
        printf("< [!] NAT TABLE (%u) RULES UPDATED [!] >\n", cntrl_list);
    }
    return OK;
}

// casting to clamp uintfast to set unsigned ints to shut the warnings up.
void
nat_print_rule(uintf8_t cntrl_list, uintf16_t rule_idx)
{
    int    i, ix;
    struct NATrule  rule = nat_tables[cntrl_list].rules[rule_idx];

    printf("<<---NAT RULE [%u][%u]--->>\n", (uint8_t) cntrl_list, (uint16_t) rule_idx);
    printf("enabled->%d\n", (uint8_t) rule.enabled);

    // SRC ZONES
    printf("src_z - ct->%u, zones->[ ", (uint8_t) rule.s_zones.len);
    for (i = 0; i < rule.s_zones.len; i++) {
        printf("%u ", (uint8_t) rule.s_zones.objects[i]);
    }
    printf(" ]\n");

    // SRC NETWORKS
    printf("src_net - ct->%u, networks->[ ", (uint8_t) rule.s_networks.len);
    for (i = 0; i < rule.s_networks.len; i++) {
        printf("(%u, %u, %u) ",
            (uint8_t) rule.s_networks.objects[i].type,
            (uint32_t) rule.s_networks.objects[i].netid,
            (uint32_t) rule.s_networks.objects[i].netmask);
    }
    printf(" ]\n");

    // SRC SERVICES
    printf("src_svc - ct->%u, services->[ ", (uint8_t) rule.s_services.len);
    for (i = 0; i < rule.s_services.len; i++) {
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
                    (uint16_t)  rule.s_services.objects[i].svc_list.services[ix].protocol,
                    (uint16_t)  rule.s_services.objects[i].svc_list.services[ix].start_port,
                    (uint16_t)  rule.s_services.objects[i].svc_list.services[ix].end_port);
            }
            printf(">");
        }
    }
    printf("]\n");

    // DST ZONES
    printf("dst_z - ct->%u, zones->[ ", (uint8_t) rule.d_zones.len);
    for (i = 0; i < rule.d_zones.len; i++) {
        printf("%u ", (uint8_t) rule.d_zones.objects[i]);
    }
    printf("]\n");

    // DST NETWORK
    printf("dst_net - ct->%u, networks->[ ", (uint8_t) rule.d_networks.len);
    for (i = 0; i < rule.d_networks.len; i++) {
        printf("(%u, %u, %u) ",
            (uint8_t) rule.d_networks.objects[i].type,
            (uint32_t) rule.d_networks.objects[i].netid,
            (uint32_t) rule.d_networks.objects[i].netmask);
    }
    printf("]\n");

    // DST SERVICES
    printf("dst_svc - ct->%u, services->[ ", (uint8_t) rule.d_services.len);
    for (i = 0; i < rule.d_services.len; i++) {
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
                // [0] START INDEX ON FW RULE SIZE
                // [1] START INDEX PYTHON DICT SIDE (to first index for size)
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
    printf("src_t->%u:%u\n", (uint32_t) rule.nat.saddr, (uint16_t) rule.nat.sport);
    printf("dst_t->%u:%u\n", (uint32_t) rule.nat.daddr, (uint16_t) rule.nat.dport);
}
