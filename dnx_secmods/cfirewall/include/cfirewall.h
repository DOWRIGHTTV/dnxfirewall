#ifndef CFIREWALL_H
#define CFIREWALL_H

#include <stdbool.h>
#include <stdint.h>

// bit shifting helpers
#define TWO_BITS     2
#define FOUR_BITS    4
#define ONE_BYTE     8
#define TWELVE_BITS 12
#define TWO_BYTES   16

#define TWO_BIT_MASK   3
#define FOUR_BIT_MASK 15

// function return values
#define OK   0
#define ERR -1
#define Py_OK  0
#define Py_ERR 1

#define OUTBOUND 1
#define INBOUND 2

#define WAN_IN 10


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
struct P1 {
    uint8_t     type;
    uint8_t     code;
};

// TCP/UDP
struct P2 {
    uint16_t    s_port;
    uint16_t    d_port;
};

struct dnx_pktb {
    uint8_t    *data;
    uint16_t    tlen;
    HWinfo      hw;
    IPhdr      *iphdr;
    uint16_t    iphdr_len; // header only

    union {
        P1  *icmp;
        P2  *proto;
    };

    uint16_t    protohdr_len; // header only
    bool        mangled;
    uintf16_t   fw_table;
    uintf16_t   rule_num;
    uint32_t    action;
    uint32_t    mark;
};

#endif