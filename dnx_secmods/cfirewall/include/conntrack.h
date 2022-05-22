#ifndef CONNTRACK_H
#define CONNTRACK_H

struct dnx_pktb;
struct Nat;

extern struct nfct_handle *nfct;

int ct_nat_init(void);
int ct_nat_update(struct dnx_pktb *pkt, struct Nat *nat);


#endif
