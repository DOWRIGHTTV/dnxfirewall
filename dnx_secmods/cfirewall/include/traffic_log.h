#ifndef TRAFFIC_LOG_H
#define TRAFFIC_LOG_H

#define TRAFFIC_LOG_DIR  "/home/dnx/dnxfirewall/dnx_system/log/traffic/" // 46
#define TRAFFIC_LOG_NAME "-traffic.log" // 12
// 20220628 // 8
#define FW_LOG_FORMAT "log_type=\"firewall\" log_component=\"firewall rule\" fw_rule_name=\"%u\" "\
    "action=\"%u\" conn_direction=\"%u\" protocol=\"%u\" "\ //src_mac="%s" dst_mac="%s"
    "in_intf=\"%u\" src_zone=\"%u\" src_country=\"%u\" src_ip=\"%s\" src_port=\"%u\" "\
    "out_intf=\"%u\" dst_zone=\"%u\" dst_country=\"%u\" dst_ip=\"%s\" dst_port=\"%u\"\n"

#define LOG_BUFFER_LIMIT 8


struct LogHandle {
    char    id[9]; // date in YYYYMMDD format
    FILE   *buf;
    int     cnt;
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
