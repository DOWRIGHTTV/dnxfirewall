#ifndef CFIREWALL_H
#define CFIREWALL_H

// netfilter
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"
#include "linux/netfilter/nf_conntrack_common.h" // enum ip_conntrack_info
#include "linux/netfilter/nfnetlink.h" // struct nfgenmsg
#include "linux/netfilter/nfnetlink_queue.h" // nfqnl structs and attr enums
#include "libmnl/libmnl.h"
#include "libnetfilter_queue/linux_nfnetlink_queue.h"
#include "libnetfilter_queue/libnetfilter_queue.h"

// dxnfirewall
#include "config.h"
#include "inet_tools.h"
#include "rules.h" // firewall and nat rule structs/ defs
#include "match.h" // zone, network, service matching helpers
#include "dnx_nfq.h" // packet verdict, mangle, etc.

//#include "hash_trie.h" // for structure / type info

// bit shifting helpers
#define TWO_BITS     2
#define FOUR_BITS    4
#define ONE_BYTE     8
#define TWELVE_BITS 12
#define TWO_BYTES   16

#define TWO_BIT_MASK   3
#define FOUR_BIT_MASK 15

#define OUTBOUND 1
#define INBOUND 2

#define WAN_IN 10

#define FW_MAX_ZONES  16

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


extern struct mnl_socket *nl;

extern uint32_t MSB, LSB;

// cli args
extern bool PROXY_BYPASS;
extern bool VERBOSE;

// stores zone(integer value) at index, which is mapped Fto if_nametoindex() (value returned from get_in/outdev)
// memset will be performed in Cython prior to changing the values.
extern uintf16_t INTF_ZONE_MAP[FW_MAX_ZONES];

extern uintf16_t zone_map_swap[FW_MAX_ZONES];

//cdef extern from "inet_tools.h" nogil:
//    uint32_t intf_masquerade(uint32_t idx)
//
//cdef extern from "std_tools.h" nogil:
//    void nullset(void **data, uintf16_t dlen)

// dxnfirewall typedef helpers
typedef struct nfqnl_msg_packet_hdr   nl_pkt_hdr;
typedef struct nfqnl_msg_packet_hw    nl_pkt_hw;

//typedef uint8_t (*hash_trie_search_t)(uint32_t msb, uint32_t lsb);

struct cfdata {
    uint32_t    queue;
    mnl_cb_t    queue_cb;
    void       *geolocation;
};

struct table_range {
  uintf8_t  start;
  uintf8_t  end;
};

struct HWinfo {
    double      timestamp;
    uintf8_t    in_zone;
    uintf8_t    out_zone;
    char*       mac_addr;
};

struct IPhdr {
    uint8_t     ver_ihl;
    uint8_t     tos;
    uint16_t    tot_len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    check;
    uint32_t    saddr;
    uint32_t    daddr;
};

// ICMP
//struct P1 {
//    uint8_t     type;
//    uint8_t     code;
//};

// TCP/UDP
struct Protohdr {
    uint16_t    sport;
    uint16_t    dport;
};

// for argument defs
//union Protohdr {
//    struct P1  *icmp;
//    struct P2  *proto;
//};

struct dnx_pktb {
    uint8_t            *data;
    uint16_t            tlen;
    struct HWinfo       hw;
    struct IPhdr       *iphdr;
    uint16_t            iphdr_len; // header only
    struct Protohdr    *protohdr;
    uint16_t            protohdr_len; // header only
    bool                mangled;
    uintf16_t           fw_table;
    uintf16_t           rule_num;
    uint32_t            action;
    uint32_t            mark;
};

#endif
