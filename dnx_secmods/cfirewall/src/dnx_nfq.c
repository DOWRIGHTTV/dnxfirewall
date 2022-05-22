#include "config.h"
#include "dnx_nfq.h"
#include "cfirewall.h"

#include <stdio.h>

static void mangle_src_addr(struct dnx_pktb *pkt);
static void mangle_src_port(struct dnx_pktb *pkt);
static void mangle_dst_addr(struct dnx_pktb *pkt);
static void mangle_dst_port(struct dnx_pktb *pkt);


// initial header parse and assignment to dnx_pktb struct
inline void
dnx_parse_pkt_headers(struct dnx_pktb *pkt)
{
    /* ---------------------
       L3 - IP HEADER
    --------------------- */
    pkt->iphdr     = (struct IPhdr*) pkt->data;
    pkt->iphdr_len = (pkt->iphdr->ver_ihl & FOUR_BIT_MASK) * 4;

    /* ---------------------
       L4 - PROTOCOL HEADER
    --------------------- */
    // ICMP type/code will be contained in src port. dst port contain checksum.
    pkt->protohdr = (struct Protohdr*) (pkt->iphdr + 1);
}

/* NO NAT fast call.
reduced pointer deference.
does not check for mangling.
does set non 0 mark values.
*/
inline void
dnx_send_verdict_fast(struct cfdata *cfd, uint32_t pktid, uint32_t mark, int action)
{
    char                buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr    *nlh;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, cfd->queue);

    nfq_nlmsg_verdict_put(nlh, pktid, action);
    if (mark) {
        nfq_nlmsg_verdict_put_mark(nlh, mark);
    }
    mnl_socket_sendto(nl[cfd->idx], nlh, nlh->nlmsg_len);
}

int
dnx_send_verdict(struct cfdata *cfd, uint32_t pktid, struct dnx_pktb *pkt)
{
    char                buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr    *nlh;

    ssize_t     ret;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, cfd->queue);

    nfq_nlmsg_verdict_put(nlh, pktid, pkt->action);
    nfq_nlmsg_verdict_put_mark(nlh, pkt->mark);
    if (pkt->mangled) {
        nfq_nlmsg_verdict_put_pkt(nlh, pkt->data, pkt->tlen);
    }

    ret = mnl_socket_sendto(nl[cfd->idx], nlh, nlh->nlmsg_len);

    return ret < 0 ? ERR : OK;
}

/* currently it will be possible to configure a source port to be natted to. this will lead to source port collisions,
but iirc netfilter uses the conn tuple (hashed value) for uniqueness so it would only collide if overloading an existing
connections conn tuple. in this case i feel like netfilter would identify that when updating the conntrack entry and be
able to dynamically change the source port to one available.

source port manipulation will be expanded in the future to allow for much more customized values so having this so open
is important to not restrict feature growth. This will just need to be understood by the user that a source port should
not be specified under normal conditions, unless there is an explicit reason to do so.
*/
bool
dnx_mangle_pkt(struct dnx_pktb *pkt, uint32_t oif)
{
    if (pkt->action == DNX_MASQ) {
        pkt->iphdr->saddr = intf_masquerade(oif);
    }
    else if (pkt->action == DNX_SRC_NAT || pkt->action == DNX_FULL_NAT) {
        mangle_src_addr(pkt);
        mangle_src_port(pkt);
    }
    else if (pkt->action == DNX_DST_NAT || pkt->action == DNX_FULL_NAT) {
        mangle_dst_addr(pkt);
        mangle_dst_port(pkt);
    }
    else { return false; }

    // try without checksum
    //pkt->iphdr->check = 0;
    //pkt->iphdr->check = calc_checksum((const uint8_t*) pkt->iphdr, pkt->iphdr_len);

    return true;
}

/* these functions are to clean up mangling logic.
we need to check whether the nat values have been set by the nat rule before mangling the packet, otherwise we could
overwrite the packet field with a 0, making the packet malformed (invalid)
*/
static inline void
mangle_src_addr(struct dnx_pktb *pkt)
{
    if (pkt->nat.saddr)
        pkt->iphdr->saddr = pkt->nat.saddr;
}

static inline void
mangle_src_port(struct dnx_pktb *pkt)
{
    if (pkt->nat.sport)
        pkt->protohdr->sport = pkt->nat.sport;
}

static inline void
mangle_dst_addr(struct dnx_pktb *pkt)
{
    if (pkt->nat.daddr)
        pkt->iphdr->daddr = pkt->nat.daddr;
}

static inline void
mangle_dst_port(struct dnx_pktb *pkt)
{
    if (pkt->nat.dport)
        pkt->protohdr->dport = pkt->nat.dport;
}