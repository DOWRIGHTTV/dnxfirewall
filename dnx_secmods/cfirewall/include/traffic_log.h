#ifndef TRAFFIC_LOG_H
#define TRAFFIC_LOG_H

#define TRAFFIC_LOG_DIR  "/home/dnx/dnxfirewall/dnx_system/logs/traffic/" // 46
#define TRAFFIC_LOG_NAME "-traffic.log" // 12
// 20220628 // 8
#define FW_LOG_FORMAT "log_type=\"firewall\" log_component=\"firewall rule\" fw_rule_name=\"%u\" "
    "action=\"%s\" conn_direction=\"%s\" protocol=\"%u\" " //src_mac="%s" dst_mac="%s"
    "in_intf=\"%u\" in_intf_name=\"%s\" src_zone=\"%u\" src_country=\"$s\" src_ip=\"%s\" src_port=\"%u\" "
    "out_intf=\"%u\" out_intf_name=\"%s\" dst_zone=\"%u\" dst_country=\"%s\" dst_ip=\"%s\" dst_port=\"%u\""

#define LOG_BUFFER_LIMIT 8


struct LogHandle {
    char    id[9]; // date in YYYYMMDD format
    FILE   *buf;
    int     cnt;
};

struct TrafficLog {
    void NULL
};

// ================================== //
// LOG HANDLE STRUCT
// ================================== //
// this holds the file object, id (date), and write counters
extern struct LogHandle Log;


extern void log_init();
extern void log_enter();
extern void log_write(struct dnx_pktb *pkt, uint8_t direction, uint8_t src_country, uint8_t dst_country);
extern void log_exit();

int  log_rotate(char* current_date);
void check_current_date(char* buf);

#endif