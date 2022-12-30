#ifndef FIREWALL_H
#define FIREWALL_H

#define FW_TABLE_COUNT 4

// extended protocol definitions
#define UDPPROTO_DNS 53

//struct ZoneMap;
//struct FWrule; // NOTE: this might just need to be included here, but wait until we see if it will be elsewhere.
//struct nlmsghdr;
//struct cfdata;
//struct dnx_pktb;
//struct clist_range;

// contains pointers to arrays of pointers to FWrule
struct FWtable {
    uintf16_t       len;
    struct FWrule  *rules;
};

enum fw_tables {
    FW_SYSTEM_RULES,
    FW_BEFORE_RULES,
    FW_MAIN_RULES,
    FW_AFTER_RULES
};

extern void firewall_init(void);
extern int  firewall_stage_count(uintf8_t cntrl_list, uintf16_t rule_count);
extern int  firewall_stage_rule(uintf8_t cntrl_list, uintf16_t rule_idx, struct FWrule *rule);
extern int  firewall_push_rules(uintf8_t cntrl_list);
extern int  firewall_stage_rule(uintf8_t cntrl_list, uintf16_t rule_idx, struct FWrule *rule);
extern int  firewall_push_zones(struct ZoneMap *zone_map);

int  firewall_recv(const struct nlmsghdr *nlh, void *data);
void firewall_inspect(struct clist_range *fw_clist, struct dnx_pktb *pkt);

void firewall_lock(void);
void firewall_unlock(void);
void firewall_print_rule(uintf8_t cntrl_list, uintf16_t rule_idx);
int  firewall_print_zones(void);

#endif
