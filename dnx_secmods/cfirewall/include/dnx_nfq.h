#ifndef DNX_NFQ_H
#define DNX_NFQ_H


struct dnx_pktb;
struct cfdata;

void dnx_parse_pkt_headers(struct dnx_pktb *pkt);
void dnx_send_verdict_fast(struct cfdata *cfd, uint32_t pktid, uint32_t mark, int action);
int  dnx_send_verdict(struct cfdata *cfd, uint32_t pktid, struct dnx_pktb *pkt);
bool dnx_mangle_pkt(struct dnx_pktb *pkt, uint32_t oif);

#endif
