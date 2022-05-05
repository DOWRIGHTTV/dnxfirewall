#include "rules.h"

// compile time def because vals are assigned by the external webui
// network object types.
#define IP_ADDRESS 1
#define IP_NETWORK 2
#define IP_RANGE   3
#define IP_GEO     6
#define INV_IP_ADDRESS 11
#define INV_IP_NETWORK 12
#define INV_IP_RANGE   13
#define INV_IP_GEO     16

// service object types.
#define SVC_SOLO  1
#define SVC_RANGE 2
#define SVC_LIST  3
#define SVC_ICMP  4

#define NO_MATCH 0
#define MATCH    1
#define END_OF_ARRAY 0


//generic function for src/dst zone matching
inline int
zone_match(ZoneArray *zone_array, uint8_t pkt_zone)
{
    uintf8_t    i;

    // any zone def is a guaranteed match
    if (zone_array->objects[0] == ANY_ZONE) { return MATCH; }

    // iterating over all zones defined in the rule
    for (i = 0; i < zone_array->len; i++) {

        if (pkt_zone != zone_array->objects[i]) {
            continue;
        }
        return MATCH;
    }
    return NO_MATCH;
}

// generic function for source OR destination network obj matching
inline int
network_match(NetArray *net_array, uint32_t iph_ip, uint8_t country)
{
    uintf8_t    i;
    NetObject   net;

    for (i = 0; i < net_array->len; i++) {

        net = net_array->objects[i];
        switch (net->type) {
            // --------------------
            // TYPE -> HOST (1)
            // --------------------
            case IP_ADDRESS:
                if (iph_ip == net->netid) { return MATCH; }
                break;
            // --------------------
            // TYPE -> NETWORK (2)
            // --------------------
            case IP_NETWORK:
                // using the rule defs netmask to floor the packet ip and matching netid
                if (iph_ip & net->netmask == net->netid) { return MATCH; }
                break;
            // --------------------
            // TYPE -> GEO (6)
            // --------------------
            case IP_GEO:
                if (net->netid == country) { return MATCH; }
                break;
            // -----------------------------
            // TYPE -> INVERSE HOST (11)
            // -----------------------------
            case INV_IP_ADDRESS:
                if (iph_ip != net->netid) { return MATCH; }
                break;
            // -----------------------------
            // TYPE -> INVERSE NETWORK (12)
            // -----------------------------
            case INV_IP_NETWORK:
                // using the rule defs netmask to floor the packet ip and matching netid
                if (iph_ip & net->netmask != net->netid) { return MATCH; }
                break;
            // -----------------------------
            // TYPE -> INVERSE GEO (16)
            // -----------------------------
            case INV_IP_GEO:
                if (net->netid != country) { return MATCH; }
                break;
        }

    // default action
    return NO_MATCH;
}

// generic function that can handle source OR destination proto/port matching
inline int
service_match(SvcArray *svc_array, uint8_t pkt_protocol, uint16_t pkt_svc)
{
    uintf16_t   i;
    SvcObject   svc_object;
    S2          svc;
    uint8_t     pkt_type, pkt_code;

    for (i = 0; i < svc_array.len; i++) {

        svc_object = svc_array->objects[i];
        switch (svc_object.type) {
            // --------------------
            // TYPE -> SOLO (1)
            // --------------------
            case SVC_SOLO:
                if (pkt_protocol != svc_object->svc->protocol && svc_object->svc->protocol != ANY_PROTOCOL) { continue; }
                if (pkt_svc == svc->start_port) { return MATCH; }
                break;
            // --------------------
            // TYPE -> RANGE (2)
            // --------------------
            case SVC_RANGE:
                if (pkt_protocol != svc_object->svc->protocol && svc_object->svc->protocol != ANY_PROTOCOL) { continue; }
                if (svc->start_port <= pkt_svc <= svc->end_port) { return MATCH; }
                break;

            // --------------------
            // TYPE -> LIST (3)
            // --------------------
            case SVC_LIST:
                for (i = 0; i < svc_object->svc_list->len; i++) {
                    svc = svc_object->svc_list->services[i]
                    if (svc->protocol != pkt_protocol && svc->protocol != ANY_PROTOCOL) { continue; }
                    if (svc->start_port <= pkt_svc <= svc->end_port) { return MATCH; }
                }
                break;
            }
            // --------------------
            // TYPE -> ICMP (4)
            // --------------------
            case SVC_ICMP:
                pkt_type = (uint8_t) (pkt_svc >> 8) // can C implicitly cast this?
                pkt_code = (uint8_t) pkt_svc

                if (pkt_protocol != IPPROTO_ICMP) { continue; }
                if (svc_object->icmp->type == pkt_type && svc_object->icmp->code == pkt_code) { return MATCH; }
        }
    }

    //default action
    return NO_MATCH;
}
