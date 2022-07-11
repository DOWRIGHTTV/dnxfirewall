#ifndef RULES_H
#define RULES_H

// matching options
#define NO_MATCH 0
#define MATCH    1

#define ANY_ZONE    99
#define NO_SECTION  99
#define ANY_PROTOCOL 0
#define COUNTRY_NOT_DEFINED 0

// PER FIELD AND RULE LIMITS
#define FIELD_MAX_ZONES   16
#define FIELD_MAX_NETWORKS 8
#define FIELD_MAX_SERVICES 8
#define FIELD_MAX_SVC_LIST_MEMBERS 8

#define SECURITY_PROFILE_COUNT 3


enum rule_actions {
    DNX_DROP,
    DNX_ACCEPT,
    DNX_REJECT,

    DNX_NO_NAT,
    // > 3 means NAT is set
    DNX_MASQ,
    DNX_SRC_NAT,
    DNX_DST_NAT,
    DNX_FULL_NAT
};

enum sec_profiles {
    NONE,
    IP_PROXY,
    DNS_PROXY,
    IPS_IDS
};

typedef struct ZoneMap {
    uintf8_t    id;
    char        name[17];
} ZoneMap;

// STANDARD ZONE ARRAY - ex. [10, 11]
typedef struct ZoneArray {
    uintf8_t    len;
    uintf8_t    objects[FIELD_MAX_ZONES];
} ZoneArray;

// STANDARD NETWORK OBJECT (HOST, NETWORK, RANGE, GEO)
typedef struct NetObject {
    uintf8_t    type;
    uintf32_t   netid;
    uintf32_t   netmask;
} NetObject;

// MAIN NETWORK ARRAY
typedef struct NetArray {
    uintf8_t    len;
    NetObject   objects[FIELD_MAX_NETWORKS];
} NetArray;

// ICMP
struct S1 {
    uint8_t     type;
    uint8_t     code;
};

// STANDARD SERVICE OBJECT (TCP/UDP) (SOLO or RANGE)
struct S2 {
    uintf16_t   protocol;
    uintf16_t   start_port;
    uintf16_t   end_port;
};

// SERVICE OBJECT LIST (tcp/80:tcp/443)
struct S3 {
    uintf8_t    len;
    struct S2   services[FIELD_MAX_SVC_LIST_MEMBERS];
};

typedef struct SvcObject {
    uintf8_t    type;
    union {
        struct S1  icmp;
        struct S2  svc;
        struct S3  svc_list;
    };
} SvcObject;

// MAIN SERVICE ARRAY
typedef struct SvcArray {
    uintf8_t    len;
    SvcObject   objects[FIELD_MAX_SERVICES];
} SvcArray;

// COMPLETE RULE STRUCTS - NO POINTERS
struct FWrule {
    char        name[33]; // 32 character max
    bool        enabled;

    // SOURCE
    ZoneArray   s_zones;
    NetArray    s_networks;
    SvcArray    s_services;

    // DESTINATION
    ZoneArray   d_zones;
    NetArray    d_networks;
    SvcArray    d_services;

    // PROFILES
    uintf8_t    action;
    uintf8_t    log;
    uintf8_t    sec_profiles[SECURITY_PROFILE_COUNT];
};

struct Nat {
    uint32_t    masq;
    uint32_t    saddr;
    uint16_t    sport;
    uint32_t    daddr;
    uint16_t    dport;
};

struct NATrule {
    char        name[33]; // 32 character max
    bool        enabled;

    // SOURCE
    ZoneArray   s_zones;
    NetArray    s_networks;
    SvcArray    s_services;

    // DESTINATION
    ZoneArray   d_zones;
    NetArray    d_networks;
    SvcArray    d_services;

    // PROFILES
    uintf8_t    action;
    uintf8_t    log;

    // TRANSLATION
    struct Nat  nat;
};

#endif
