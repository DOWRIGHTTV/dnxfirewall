#ifndef DNX_NFQ_H
#define DNX_NFQ_H

typedef struct nfqnl_msg_packet_timestamp nl_pkt_ts;
typedef const struct nlmsghdr nl_msg_hdr;
typedef struct nfqnl_msg_packet_hdr nl_pkt_hdr;
struct nlattr;
struct dnx_pktb;
struct cfdata;

void dnx_parse_nl_headers(nl_msg_hdr *nlmsgh, nl_pkt_hdr **nl_pkth, struct nlattr **netlink_attrs, struct dnx_pktb *pkt);
void dnx_parse_pkt_headers(struct dnx_pktb *pkt);
void dnx_send_verdict_fast(struct cfdata *cfd, uint32_t pktid, uint32_t mark, int action);
int  dnx_send_verdict(struct cfdata *cfd, uint32_t pktid, struct dnx_pktb *pkt);
bool dnx_mangle_pkt(struct dnx_pktb *pkt);

#endif
