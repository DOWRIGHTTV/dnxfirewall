// probably not needed
#include "config.h"
#include "dnx_nfq.h"
#include "cfirewall.h"

#include <stdio.h>

inline void
dnx_parse_pkt_headers(struct dnx_pktb *pkt)
{
    // initial header parse and assignment to dnx_pktb struct
    // ---------------------
    // L3 - IP HEADER
    // ---------------------
    pkt->iphdr     = (struct IPhdr*) pkt->data;
    pkt->iphdr_len = (pkt->iphdr->ver_ihl & FOUR_BIT_MASK) * 4;
    // ---------------------
    // L4 - PROTOCOL HEADER
    // ---------------------
    // ICMP type/code will be contained in src port. dst port contain checksum.
    pkt->protohdr = (struct Protohdr*) (pkt->iphdr + 1);

//    switch (pkt->iphdr->protocol) {
//        case IPPROTO_ICMP:
//            pkt->protohdr.icmp = (struct P1*) (pkt->iphdr + 1);
//            break;
//        default:
//            pkt->protohdr.std = (struct P2*) (pkt->iphdr + 1)
//    }
}

inline void
dnx_send_verdict_fast(struct cfdata *cfd, uint32_t pktid, int action)
{
    char                buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr    *nlh;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, cfd.queue);
    nfq_nlmsg_verdict_put(nlh, pktid, action);
    mnl_socket_sendto(cfd.nl, nlh, nlh->nlmsg_len);
}

int
dnx_send_verdict(struct cfdata *cfd, uint32_t pktid, struct dnx_pktb *pkt)
{
    char                buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr    *nlh;

    ssize_t     ret;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, cfd.queue);

    nfq_nlmsg_verdict_put(nlh, pktid, pkt->action);
    nfq_nlmsg_verdict_put_mark(nlh, pkt->mark);
    if (pkt->mangled) {
        nfq_nlmsg_verdict_put_pkt(nlh, pkt->data, pkt->tlen);
    }

    ret = mnl_socket_sendto(cfd.nl, nlh, nlh->nlmsg_len);

    return ret < 0 ? ERR : OK;
}

bool
dnx_mangle_pkt(struct dnx_pktb *pkt)
{
    // MAKE SURE WE RECALCULATE THE PROPER CHECKSUMS.
    // we can probably use the nfq checksum functions if they are publicly available, otherwise use cprotocol_tools.

    // NOTE: ip manip only. we will deal with the port issue later.
    switch (pkt->action) {
        case DNX_MASQ:
            pkt->iphdr->saddr = intf_masquerade(pkt->hw.out_zone);
            pkt->iphdr->check = 0;
            pkt->iphdr->check = calc_checksum((const uint8_t*) pkt->iphdr, pkt->iphdr_len);

            return true;

        // changing dst ip and/or port pre route
        case DNX_DST_NAT:
        // changing src ip and/or port post route
        case DNX_SRC_NAT:
        // changing dst ip and/or port pre route
        case DNX_FULL_NAT:
        default:;
    }
    return false;
}
