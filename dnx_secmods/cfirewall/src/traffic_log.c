#include "config.h"
#include "cfirewall.h"
#include "traffic_log.h"

struct LogHandle Log;

void
log_init()
{
    Log.id  = "XXXXXXXX\0";
    Log.cnt = 0;
}

void
log_enter()
{
    char today[9];

    // open new file if day has changed. this might be changes to 8 hour blocks or something in the future
    check_current_date(today);
    if (Log.id != today) {
        log_rotate(rotate);
    }
}

void
log_write(struct dnx_pktb *pkt, uint8_t direction, uint8_t src_country, uint8_t dst_country)
{
    char saddr[18];
    char daddr[18];

    // converting ip as interger to string eg. 192.168.1.1
    itoip(pkt->iphdr.saddr, saddr);
    itoip(pkt->iphdr.daddr, daddr);

    fprintf(Log.buf, FW_LOG_FORMAT,
        pkt->rule_num, pkt->action, direction, pkt->iphdr->protocol,
        pkt->hw.iif, pkt->hw.in_zone, src_country, saddr, pkt->iphdr.sport,
        pkt->hw.oif, pkt->hw.out_zone, dst_country, daddr, pkt->iphdr.dport
    );

    Log.cnt++;
}

void
log_exit()
{
    if (Log.cnt == LOG_BUFFER_LIMIT) {
        fflush(Log.buf);
        Log.cnt = 0
    }
}

int
// since the date will be checked before every message (for now), we will require it to be passed in here.
log_rotate(char* current_date)
{
    char file_path[64]; // 46 + 12 + 8 + 1

    // closing current file object
    fclose(Log.buf);
    snprintf(file_path, sizeof(file_path), "%s%s%s", TRAFFIC_LOG_DIR, current_date, TRAFFIC_LOG_NAME);

    memcpy(Log.active_id, current_date, 8)

    // creating and storing new file object.
    Log->buf = fopen(file_path, "a");

    return 0;
}


void
check_current_date(char* buf)
{
    time_t      epoch;
    struct tm  *time_info;

    epoch = time(NULL);
    info  = localtime(&epoch);

    strftime(buf, 9, "%Y%m%d", info);
}
