# matching options
#define ANY_ZONE    99
#define NO_SECTION  99
#define ANY_PROTOCOL 0
#define COUNTRY_NOT_DEFINED 0


// PER FIELD AND RULE LIMITS
#define FIELD_MAX_ZONES   16
#define FIELD_MAX_NETWORKS 8
#define FIELD_MAX_SERVICES 8
#define FIELD_MAX_SVC_LIST_MEMBERS 8

struct table_range {
  uintf8_t  start;
  uintf8_t  end;
};

enum rule_actions {
    DNX_DROP,
    DNX_ACCEPT,
    DNX_REJECT,

    DNX_NO_NAT,
    // > 4 means NAT is set
    DNX_MASQ,
    DNX_SRC_NAT,
    DNX_DST_NAT,
    DNX_FULL_NAT,

    DNX_NAT_FLAGS = DNX_SRC_NAT | DNX_DST_NAT | DNX_FULL_NAT
};

// STANDARD ZONE ARRAY - ex. [10, 11]
struct ZoneArray {
    uintf8_t    len;
    uintf8_t    objects[FIELD_MAX_ZONES];
};

// STANDARD NETWORK OBJECT (HOST, NETWORK, RANGE, GEO)
struct NetObject {
    uintf8_t    type;
    uintf32_t   netid;
    uintf32_t   netmask;
};

// MAIN NETWORK ARRAY
struct NetArray {
    uintf8_t    len;
    NetObject   objects[FIELD_MAX_NETWORKS];
};

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
    Service     services[FIELD_MAX_SVC_LIST_MEMBERS];
}

struct SvcObject {
    uintf8_t    type;
    union {
        S1  icmp;
        S2  svc;
        S3  svc_list;
    };
};

// MAIN SERVICE ARRAY
struct SvcArray {
    uintf8_t    len;
    SvcObject   objects[FIELD_MAX_SERVICES];
};

// COMPLETE RULE STRUCTS - NO POINTERS
struct FWrule {
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

struct NATrule {
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
    uint32_t    saddr;
    uint16_t    sport;
    uint32_t    daddr;
    uint16_t    dport;
};