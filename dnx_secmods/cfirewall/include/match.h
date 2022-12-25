#ifndef MATCH_H
#define MATCH_H


struct ZoneArray;
struct NetArray;
struct SvcArray;
struct Protohdr;

extern int zone_match(struct ZoneArray *zone_array, uint8_t pkt_zone);
extern int network_match(struct NetArray *net_array, uint32_t iph_ip, uint8_t country);
extern int service_match(struct SvcArray *svc_array, uint8_t pkt_protocol, uint16_t pkt_svc);

#endif
