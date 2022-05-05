#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>

typedef uint_fast16_t uintf16_t;

struct FWrule; // NOTE: this might just need to be included here, but wait until we see if it will be elsewhere.

// contains pointers to arrays of pointers to FWrule
struct FWtable {
    uintf16_t   len;
    FWrule     *rules;
};

enum fw_tables {
    FW_SYSTEM_RULES,
    FW_BEFORE_RULES,
    FW_MAIN_RULES,
    FW_AFTER_RULES
};
enum sec_profiles {
    NONE,
    IP_PROXY,
    DNS_PROXY,
    IPS_IDS
};

extern pthread_mutex_t *FWlock_ptr;
extern FWtable *firewall_tables[FW_TABLE_COUNT];

int  firewall_recv(const nlmsghdr *nlh, void *data)
void firewall_inspect(srange *fw_tables, dnx_pktb *pkt)

#endif