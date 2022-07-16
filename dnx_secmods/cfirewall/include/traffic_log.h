#ifndef TRAFFIC_LOG_H
#define TRAFFIC_LOG_H

#define TRAFFIC_LOG_DIR  "/home/dnx/dnxfirewall/dnx_profile/log/traffic/" // 46
// 20220628 // 8
//src_mac="%s" dst_mac="%s"
#define FW_LOG_FORMAT "timestamp=\"%lu.%lu\" log_type=\"firewall\" log_component=\"rule\" "\
    "rule=\"%s\" action=\"%s\" conn_direction=\"%s\" protocol=\"%u\" "\
    "in_intf=\"%u\" src_zone=\"%s\" src_country=\"%u\" src_ip=\"%s\" src_port=\"%u\" "\
    "out_intf=\"%u\" dst_zone=\"%s\" dst_country=\"%u\" dst_ip=\"%s\" dst_port=\"%u\"\n"

#define LOG_BUFFER_LIMIT 8

#define FW_LOG_IDX  0
#define NAT_LOG_IDX 1

// ================================== //
// LOG HANDLE STRUCT
// ================================== //
// this holds the file object, id (date), and write counters
struct LogHandle {
    char    label[16]; // subdir of traffic, eg. firewall, nat (also used to name file properly)
    char    id[9]; // date in YYYYMMDD format
    FILE   *buf;
    time_t  rotate;
    int     cnt;
};

struct LogHandle Log[2];

extern void log_init(struct LogHandle *logger, char *label);
extern void log_enter(struct timeval *ts, struct LogHandle *logger);
extern void log_write_firewall(struct timeval *ts, struct dnx_pktb *pkt, uint8_t direction, uint8_t src_country, uint8_t dst_country);
extern void log_write_nat(struct dnx_pktb *pkt);
extern void log_exit(struct LogHandle *logger);

int  log_rotate(struct LogHandle *logger, struct timeval *ts);

#endif
