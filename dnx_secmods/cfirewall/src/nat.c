#include "config.h"
#include "nat.h"
#include "cfirewall.h"
#include "rules.h"

//#include "linux/netlink.h" //nlmsghdr

#define NAT_PRE_MAX_RULE_COUNT  100
#define NAT_POST_MAX_RULE_COUNT 100

#define NAT_PRE_TABLE  0
#define NAT_POST_TABLE 1


struct NATtable nat_tables[NAT_TABLE_COUNT];

pthread_mutex_t     NATtableslock;
pthread_mutex_t    *NATlock_ptr = &NATtableslock;

void
nat_init(void) {
    pthread_mutex_init(NATlock_ptr, NULL);

    // arrays of pointers to NATrule
    nat_tables[NAT_PRE_RULES].len = 0;
    nat_tables[NAT_PRE_RULES].rules = calloc(NAT_PRE_MAX_RULE_COUNT, sizeof(struct NATrule)); // (NATrule*)

    nat_tables[NAT_POST_RULES].len = 0;
    nat_tables[NAT_POST_RULES].rules = calloc(NAT_POST_MAX_RULE_COUNT, sizeof(struct NATrule)); // (NATrule*)
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

//    nullset(<void**>netlink_attrs, NFQA_RANGE);
    nfq_nlmsg_parse(nlh, netlink_attrs);

    nlhdr = (nl_pkt_hdr*) mnl_attr_get_payload(netlink_attrs[NFQA_PACKET_HDR]);

    switch(ntohl(nlhdr->hook)) {
        case NF_IP_POST_ROUTING:
            table_idx = NAT_POST_TABLE;
            break;
        case NF_IP_PRE_ROUTING:
            table_idx = NAT_PRE_TABLE;
            break;
        default: return ERR;
    }

    // ======================
    // NO NAT QUICK PATH
    if (nat_tables[table_idx].len == 0) {
        dnx_send_verdict_fast(cfd->queue, ntohl(nlhdr->packet_id), NF_ACCEPT);

        return OK;
    }
    // ======================
    _iif  = netlink_attrs[NFQA_IFINDEX_INDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_INDEV])) : 0;
    _oif  = netlink_attrs[NFQA_IFINDEX_OUTDEV] ? ntohl(mnl_attr_get_u32(netlink_attrs[NFQA_IFINDEX_OUTDEV])) : 0;

    pkt.hw.in_zone   = INTF_ZONE_MAP[_iif];
    pkt.hw.out_zone  = INTF_ZONE_MAP[_oif];
    // ======================
    // PACKET DATA / LEN
    pkt.data = mnl_attr_get_payload(netlink_attrs[NFQA_PAYLOAD]); // <uint8_t*>
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
    // the alternative is to allocate a pktb and user the proper mangler.
    // this would auto manage the header checksums, but we would need alloc/free every time we mangle.
    // i have alot of experience with nat and checksum calculations so its probably easier and more efficient to use
    // the on stack buffer to mangle. (this is unless we need to retain a copy of the original packet)
    if (pkt.action > DNX_NO_NAT) {
        pkt.mangled = dnx_mangle_pkt(&pkt);
    }

    return OK;
}

inline void
nat_inspect(int table_idx, struct dnx_pktb *pkt, struct cfdata *cfd)
{
    dnx_parse_pkt_headers(pkt);

//    NATrule    *nat_table;
    struct NATrule    *rule;

    // normalizing src/dst ip in header to host order
    uint32_t    iph_src_ip = ntohl(pkt->iphdr->saddr);
    uint32_t    iph_dst_ip = ntohl(pkt->iphdr->daddr);

    // ip address to country code
    uint8_t     src_country = cfd->geo_search(iph_src_ip & MSB, iph_src_ip & LSB);
    uint8_t     dst_country = cfd->geo_search(iph_dst_ip & MSB, iph_dst_ip & LSB);

    uintf16_t   rule_idx;

    for (rule_idx = 0; rule_idx < nat_tables[table_idx].len; rule_idx++) {

        rule = &nat_tables[table_idx].rules[rule_idx];
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
        if (service_match(&rule->d_services, pkt->iphdr->protocol, pkt->protohdr->dport) != MATCH) { continue; }

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
}

void
nat_unlock(void)
{
    pthread_mutex_unlock(NATlock_ptr);
}

void
nat_update_count(uint8_t table_idx, uint16_t rule_count)
{
    nat_tables[table_idx].len = rule_count;
}

int
nat_set_rule(uint8_t table_idx, uint16_t rule_idx, struct NATrule *rule)
{
    nat_tables[table_idx].rules[rule_idx] = *rule;

    return OK;
}
