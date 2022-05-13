#ifndef FIREWALL_H
#define FIREWALL_H

#define FW_TABLE_COUNT 4


struct FWrule; // NOTE: this might just need to be included here, but wait until we see if it will be elsewhere.
struct nlmsghdr;
struct cfdata;
struct dnx_pktb;
struct table_range;

// contains pointers to arrays of pointers to FWrule
struct FWtable {
    uintf16_t   len;
    struct FWrule     *rules;
};

enum fw_tables {
    FW_SYSTEM_RULES,
    FW_BEFORE_RULES,
    FW_MAIN_RULES,
    FW_AFTER_RULES
};

// ================================== //
// Firewall tables access lock
// ================================== //
// Must be held to read from or make
// changes to "*firewall_tables[]"
// ---------------------------------- //
extern pthread_mutex_t     FWtableslock;
extern pthread_mutex_t    *FWlock_ptr;
// ==================================
// FIREWALL TABLES
// ==================================
// contains pointers to arrays of pointers to FWrule and its length
extern struct FWtable firewall_tables[FW_TABLE_COUNT];

extern struct FWtable fw_tables_swap[FW_TABLE_COUNT];

extern void firewall_init(void);
extern int  firewall_stage_count(uintf8_t table_idx, uintf16_t rule_count);
extern int  firewall_stage_rule(uintf8_t table_idx, uintf16_t rule_idx, struct FWrule *rule);
extern int  firewall_push_rules(uintf8_t table_idx);
extern int  firewall_push_zones(uintf8_t *zone_map);

int  firewall_recv(const struct nlmsghdr *nlh, void *data);
void firewall_inspect(struct table_range *fw_tables, struct dnx_pktb *pkt, struct cfdata *cfd);

void firewall_lock(void);
void firewall_unlock(void);
void firewall_print_rule(uintf8_t table_idx, uintf16_t rule_idx);
int  firewall_print_zones(void);

#endif
