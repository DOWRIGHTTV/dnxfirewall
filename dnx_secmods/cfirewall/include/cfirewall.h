#ifndef CFIREWALL_H
#define CFIREWALL_H

// netfilter
#include <linux/netfilter.h> // enum nf_inet_hooks
#include <linux/netfilter_ipv4.h> // IP hooks (NF_IP_FORWARD)
#include <linux/netfilter/nfnetlink.h> // struct nfgenmsg
#include <linux/netfilter/nfnetlink_queue.h> // nfqnl structs and attr enums (nfqnl_msg_pkt_hw/hdr)
#include <linux/netfilter/nf_conntrack_common.h> // enum ip_conntrack_info
#include <libmnl/libmnl.h> // nl attr parsing
#include <libnetfilter_queue/libnetfilter_queue.h> // nfqueue interface for libmnl
#include <libnetfilter_conntrack/libnetfilter_conntrack.h> // nfct - conntrack updates (used by nat mod through dnx_nfq)

// dnxfirewall setup
#include "config.h"
#include "debug.h"
#include "inet_tools.h"
#include "std_tools.h"

// forward declarations so extension headers dont need them
struct cfdata;
struct clist_range;
struct HWinfo;
struct IPhdr;
struct Protohdr;
struct geolocation;
struct dnx_pktb;

// dnxfirewall extensions
#include "fw_main.h"    // primary cython file, needed for geolocation lookup
#include "rules.h"      // firewall and nat rule structs/ defs
#include "match.h"      // zone, network, service matching helpers
#include "dnx_nfq.h"    // packet verdict, mangle, etc.
#include "traffic_log.h"

#define OUTBOUND 1
#define INBOUND  2

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

// geolocation vars
extern uint32_t MSB, LSB;
extern int      HTR_IDX;

// cli args
extern bool     VERBOSE;
extern bool     VERBOSE2;

extern bool     FW_V;
extern bool     NAT_V;

extern struct mnl_socket *nl[2];

//extern uint8_t dnx_pkt_id;
//extern struct dnx_pktb *dnx_pkt_tracker[UINT8_MAX];

// stores zone(integer value) at index, which is mapped to if_nametoindex() (value returned from get_in/outdev)
// memset will be performed in Cython prior to changing the values.
extern ZoneMap INTF_ZONE_MAP[FW_MAX_ZONES];

// dnxfirewall typedef helpers
typedef const struct nlmsghdr     nl_msg_hdr;

typedef struct nfqnl_msg_packet_hdr     nl_pkt_hdr;
typedef struct nfqnl_msg_packet_hw      nl_pkt_hw;

typedef struct nfqnl_msg_packet_timestamp      nl_pkt_ts;

struct cfdata {
    uintf8_t    idx;
    uint32_t    queue;

    mnl_cb_t    queue_cb;
};

struct clist_range {
  uintf8_t      start;
  uintf8_t      end;
};

struct HWinfo {
    nl_pkt_ts  *timestamp;
    uintf8_t    iif;
    ZoneMap     in_zone;
    uintf8_t    oif;
    ZoneMap     out_zone;
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

struct geolocation {
    uint8_t     src;
    uint8_t     dst;
    uint8_t     dir;
    uint8_t     remote;
};

struct dnx_pktb {
    uint8_t             confirmed;
    uint8_t            *data;
    uint16_t            tlen;
    struct HWinfo       hw;
    struct IPhdr       *iphdr;
    uint16_t            iphdr_len;      // header only
    struct Protohdr    *protohdr;
    uint16_t            protohdr_len;   // header only
    struct Nat          nat;            // not used by FW. copied over from nat rule on match
    bool                mangled;
    uintf16_t           rule_clist;     // CONTROL LIST. recent change from fw_table to be module agnostic
    char*               rule_name;
    uint8_t             log;
    struct geolocation  geo;
    uint16_t            sec_profiles;   // X (4b) | ips (4b) | dns (4b) | ipp (4b) -- will be placed in upper 16b of mark
    uint8_t             action;
};

#endif
