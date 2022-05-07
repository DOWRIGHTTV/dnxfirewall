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

extern void firewall_init(void);
extern void firewall_lock(void);
extern void firewall_unlock(void);
extern void firewall_update_count(uint8_t table_idx, uint16_t rule_count);
extern int  firewall_set_rule(uint8_t table_idx, uint16_t rule_idx, struct FWrule *rule);

int  firewall_recv(const struct nlmsghdr *nlh, void *data);
void firewall_inspect(struct table_range *fw_tables, struct dnx_pktb *pkt, struct cfdata *cfd);

#endif
