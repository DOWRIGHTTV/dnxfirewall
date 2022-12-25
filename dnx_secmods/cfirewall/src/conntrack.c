#include "config.h"
#include "cfirewall.h"
#include "conntrack.h"

struct nfct_handle *nfct;

int
ct_nat_init(void) {
    nfct = nfct_open(CONNTRACK, 0);
    if (!nfct)
        return ERR;

    return OK;
}

int
ct_nat_update(struct dnx_pktb *pkt)
{
    int    ret;
    struct nf_conntrack *ct;

    // using basic API here to be consistent with "_destroy".
    ct = nfct_new();
    if (!ct)
         return ERR;

    // identify the connection - L3
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, pkt->iphdr->saddr);
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, pkt->iphdr->daddr);

    nfct_set_attr_u8(ct, ATTR_L4PROTO, pkt->iphdr->protocol);
    // identify the connection - L4
    switch (pkt->iphdr->protocol) {
        case IPPROTO_ICMP:
            nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, (uint8_t) (pkt->protohdr->sport >> 8));
            nfct_set_attr_u8(ct, ATTR_ICMP_CODE, (uint8_t) pkt->protohdr->sport);
            break;
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, pkt->protohdr->sport);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, pkt->protohdr->dport);
    }
    // flip the original
    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

    // updating any field set within the nat rule
    if (pkt->nat.saddr)
        nfct_set_attr_u32(ct, ATTR_SNAT_IPV4, pkt->nat.saddr);

    if (pkt->nat.daddr)
        nfct_set_attr_u32(ct, ATTR_DNAT_IPV4, pkt->nat.daddr);

    // icmp rules will never have these set so this is safe
    if (pkt->nat.sport)
        nfct_set_attr_u16(ct, ATTR_SNAT_PORT, pkt->nat.sport);

    if (pkt->nat.dport)
        nfct_set_attr_u16(ct, ATTR_DNAT_PORT, pkt->nat.dport);

    // does not wait for response
    ret = nfct_send(nfct, NFCT_Q_UPDATE, ct);

    // cannot call free direct because nested structs will not get freed.
    nfct_destroy(ct);

    return ret;
}
