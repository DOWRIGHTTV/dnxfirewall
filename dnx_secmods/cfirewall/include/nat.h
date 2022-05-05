#ifndef NAT_H
#define NAT_H

#include <stdint.h>

typedef uint_fast16_t uintf16_t;

struct NATrule; // NOTE: this might just need to be included here, but wait until we see if it will be elsewhere.

struct NATtable {
    uintf16_t   len;
    NATrule     *rules;
};

enum nat_tables {
    NAT_PRE_RULES,
    NAT_POST_RULES,
};

extern const pthread_mutex_t *NATlock_ptr;

extern NATtable *nat_tables[NAT_TABLE_COUNT];
extern uintf16_t *NAT_CUR_RULE_COUNTS;

int  nat_recv(const nlmsghdr *nlh, void *data)
void nat_inspect(int table_idx, int rule_count, dnx_pktb *pkt)

#endif