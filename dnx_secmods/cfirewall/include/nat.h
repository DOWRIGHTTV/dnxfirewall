#ifndef NAT_H
#define NAT_H

#define NAT_TABLE_COUNT 2


struct NATrule; // NOTE: this might just need to be included here, but wait until we see if it will be elsewhere.
struct nlmsghdr;
struct cfdata;
struct dnx_pktb;

struct NATtable {
    uintf16_t       len;
    struct NATrule *rules;
};

enum nat_tables {
    NAT_PRE_RULES,
    NAT_POST_RULES,
};

// ================================== #
// NAT tables access lock
// ================================== #
// Must be held to read from or make
// changes to "*firewall_tables[]"
// ---------------------------------- #
extern pthread_mutex_t     NATtableslock;
extern pthread_mutex_t    *NATlock_ptr;

// ==================================
// NAT TABLES
// ==================================
// contains pointers to arrays of pointers to NATrule and its length
extern struct NATtable nat_tables[NAT_TABLE_COUNT];

extern struct NATtable nat_tables_swap[NAT_TABLE_COUNT];

extern void nat_init(void);
extern int  nat_stage_count(uintf8_t table_idx, uintf16_t rule_count);
extern int  nat_stage_rule(uintf8_t table_idx, uintf16_t rule_idx, struct NATrule *rule);
extern int  nat_push_rules(uintf8_t table_idx);

int  nat_recv(const struct nlmsghdr *nlh, void *data);
void nat_inspect(int table_idx, struct dnx_pktb *pkt, struct cfdata *cfd);

void nat_lock(void);
void nat_unlock(void);
void nat_print_rule(uintf8_t table_idx, uintf16_t rule_idx);

#endif
