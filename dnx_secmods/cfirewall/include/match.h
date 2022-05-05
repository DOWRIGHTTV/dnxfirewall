#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>

struct ZoneArray;
struct NetArray;
struct SvcArray;

int zone_match(ZoneArray *zone_array, uint8_t pkt_zone)
int network_match(NetArray *net_array, uint32_t iph_ip, uint8_t country)
int service_match(SvcArray *svc_array, uint8_t pkt_protocol, uint16_t pkt_svc)

#endif