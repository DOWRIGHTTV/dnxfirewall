#include "config.h"
#include "nat.h"
#include "cfirewall.h"
#include "rules.h"

#include "hash_trie.h"

#define NAT_PRE_MAX_RULE_COUNT  100
#define NAT_POST_MAX_RULE_COUNT 100

#define NAT_PRE_TABLE  0
#define NAT_POST_TABLE 1


struct NATtable nat_tables[NAT_TABLE_COUNT];

pthread_mutex_t     NATtableslock;
pthread_mutex_t    *NATlock_ptr = &NATtableslock;

struct NATtable nat_tables_swap[NAT_TABLE_COUNT];


void
nat_init(void) {
    pthread_mutex_init(NATlock_ptr, NULL);

    // arrays of pointers to NATrule
    nat_tables[NAT_PRE_RULES].len = 0;
    nat_tables[NAT_PRE_RULES].rules = calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(struct NATrule));

    nat_tables[NAT_POST_RULES].len = 0;
    nat_tables[NAT_POST_RULES].rules = calloc(NAT_POST_MAX_RULE_COUNT, sizeof(struct NATrule));

    // SWAP STORAGE
    nat_tables_swap[NAT_PRE_RULES].len = 0;
    nat_tables_swap[NAT_PRE_RULES].rules = calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(struct NATrule));

    nat_tables_swap[NAT_POST_RULES].len = 0;
    nat_tables_swap[NAT_POST_RULES].rules = calloc(NAT_POST_MAX_RULE_COUNT, sizeof(struct NATrule));
}

// ==================================
// PRIMARY NAT LOGIC
// ==================================
int
nat_recv(const struct nlmsghdr *nlh, void *data)
{
    struct cfdata     *cfd = (struct cfdata*) data;
    struct nlattr     *netlink_attrs[NFQA_MAX+1] = {};

    nl_pkt_hdr *nlhdr;

    uint32_t    _iif, _oif; // , _mark; (not needed at this time)

    int         table_idx;

    struct dnx_pktb    pkt;

    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = (nl_pkt_hdr*) mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);

    printf("< [++] NAT RECV - PARSING [++] >\n");

    switch(nlhdr->hook) {
        case NF_IP_POST_ROUTING:
            table_idx = NAT_POST_TABLE;
            break;
        case NF_IP_PRE_ROUTING:
            table_idx = NAT_PRE_TABLE;
            break;
        case NF_IP_LOCAL_IN:
        case NF_IP_LOCAL_OUT:
            dnx_send_verdict_fast(cfd->queue, ntohl(nlhdr->packet_id), NF_ACCEPT);
            return OK;
        default:
            printf("< [++] NAT HOOK MISMATCH (%u) [++] >\n", nlhdr->hook);
            return ERR;
    }

    // ======================
    // NO NAT QUICK PATH
    if (nat_tables[table_idx].len == 0) {
        dnx_send_verdict_fast(cfd->queue, ntohl(nlhdr->packet_id), NF_ACCEPT);

        return OK;
    }
    // ======================
    _iif = netlink_attrs[NFQA_IFINDEX_INDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) : 0;
    _oif = netlink_attrs[NFQA_IFINDEX_OUTDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) : 0;

    pkt.hw.in_zone  = INTF_ZONE_MAP[_iif];
    pkt.hw.out_zone = INTF_ZONE_MAP[_oif];
    // ======================
    // PACKET DATA / LEN
    pkt.data = mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD]);
    pkt.tlen = mnl_attr_get_payload_len(netlink_attrs[NFQA_PAYLOAD]);
    // ===================================
    // LOCKING ACCESS TO NAT RULES
    // prevents the manager thread from updating nat rules during packet inspection
    nat_lock();
    // --------------------
    nat_inspect(table_idx, &pkt, cfd);
    // --------------------
    nat_unlock();
    // UNLOCKING ACCESS TO NAT RULES
    // ===================================

    // --------------------
    // NAT / MANGLE
    // --------------------
    // NOTE: it looks like it will be better if we manually NAT the packet contents.
    // the alternative is to allocate a pktb and use the netfilter provided mangler.
    // this would auto manage the header checksums, but we would need alloc/free every time we mangle.
    // i have alot of experience with nat and checksum calculations so its probably easier and more efficient to use
    // the on stack buffer to mangle. (this is unless we need to retain a copy of the original packet -> but then again
    // we could just memcpy the original and still not use pktb)
    if (pkt.action > DNX_NO_NAT) {
        pkt.mangled = dnx_mangle_pkt(&pkt);
    }

    dnx_send_verdict(cfd->queue, ntohl(nlhdr->packet_id), &pkt);

    if (NAT_V && VERBOSE) {
        printf("< [--] NAT VERDICT [--] >\n");
        printf("packet_id->%u, hook->%u, action->%u, ", ntohl(nlhdr->packet_id), nlhdr->hook, pkt.action);
        printf("=====================================================================\n");
    }

    return OK;
}

inline void
nat_inspect(int table_idx, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

    struct HashTrie_Range *geolocation = cfd->geolocation;

    struct NATrule    *rule;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = geolocation->lookup(geolocation, iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = geolocation->lookup(geolocation, iph_dst_ip & MSB, iph_dst_ip & LSB);

    uintf16_t   rule_idx;

    if (NAT_V && VERBOSE) {
        printf("< [**] NAT INSPECTION [**] >\n");
        printf("src->%u:%u, dst->%u:%u\n",
            iph_src_ip, ntohs(pkt->protohdr->sport),
            iph_dst_ip, ntohs(pkt->protohdr->dport)
            );
    }

    for (rule_idx = 0; rule_idx < nat_tables[table_idx].len; rule_idx++) {

        rule = &nat_tables[table_idx].rules[rule_idx];
        // NOTE: inspection order: src > dst | zone, ip_addr, protocol, port
        if (!rule->enabled) { continue; }

        if (NAT_V && VERBOSE2) {
            nat_print_rule(table_idx, rule_idx);
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
        // MATCH ACTION | rule details
        // ------------------------------------------------------------------
        pkt->fw_table = table_idx;
        pkt->rule_num = rule_idx; // if logging, this needs to be +1
        pkt->action   = rule->action;

        return;
    }
    // ------------------------------------------------------------------
    // DEFAULT ACTION
    // ------------------------------------------------------------------
    pkt->fw_table = NO_SECTION;
    pkt->action   = DNX_ACCEPT;
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

    printf("< [!] NAT LOCK RELEASED [!] >\n");
}

int
nat_stage_count(uintf8_t table_idx, uintf16_t rule_count)
{
    nat_tables[table_idx].len = rule_count;

    printf("< [!] NAT TABLE (%u) COUNT UPDATED [!] >\n", table_idx);

    return OK;
}

int
nat_stage_rule(uintf8_t table_idx, uintf16_t rule_idx, struct NATrule *rule)
{
    nat_tables[table_idx].rules[rule_idx] = *rule;

    return OK;
}

int
nat_push_rules(uintf8_t table_idx)
{
    nat_lock();
    // iterating over each rule in NAT table
    for (uintf8_t rule_idx = 0; rule_idx < nat_tables_swap[table_idx].len; rule_idx++) {

        // copy swap structure to active structure. alignment is already set as they are idential structures.
        nat_tables[table_idx].rules[rule_idx] = nat_tables_swap[table_idx].rules[rule_idx];
    }
    nat_unlock();

    printf("< [!] NAT TABLE (%u) RULES UPDATED [!] >\n", table_idx);

    return OK;
}

void
nat_print_rule(uintf8_t table_idx, uintf16_t rule_idx)
{
    int    i, ix;
    struct NATrule  rule = nat_tables[table_idx].rules[rule_idx];

    printf("<<NAT RULE [%u][%u]>>\n", table_idx, rule_idx);
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
    printf("src_t->%u:%u\n", rule.saddr, rule.sport);
    printf("dst_t->%u:%u\n", rule.daddr, rule.dport);
}
