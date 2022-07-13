#include "config.h"
#include "cfirewall.h"
#include "traffic_log.h"

struct LogHandle Log[2];

char*   action_map[3] = {"deny", "accept", "reject"};
char*   dir_map[2]    = {"inbound", "outbound"};

void
log_init(struct LogHandle *logger, char *label)
{
    strcpy(logger->label, label); // eg. firewall, nat
    memset(logger->id, 0, 1); // eg. 20220704

    logger->buf    = fopen("/dev/null", "a");
    logger->rotate = 0;
    logger->cnt    = 0;
}

void
log_enter(struct timeval *ts, struct LogHandle *logger)
{
    // open a new file if the day has changed. this might be changes to 8 hour blocks or something in the future
    if (ts->tv_sec >= logger->rotate) {
        log_rotate(logger, ts);
    }
}

// consider making the countries a tuple as struct
void
log_write_firewall(struct timeval *ts, struct dnx_pktb *pkt, uint8_t direction, uint8_t src_country, uint8_t dst_country)
{
    char    saddr[18];
    char    daddr[18];
    char*   dir;
    char*   action;

    // converting ip as integer to a dot notation string eg. 192.168.1.1
    itoip(pkt->iphdr->saddr, saddr);
    itoip(pkt->iphdr->daddr, daddr);

    fprintf(pkt->logger->buf, FW_LOG_FORMAT, ts->tv_sec, ts->tv_usec,
        pkt->fw_rule->name, action_map[pkt->action], dir_map[direction], pkt->iphdr->protocol,
        pkt->hw.iif, pkt->hw.in_zone.name, src_country, saddr, ntohs(pkt->protohdr->sport),
        pkt->hw.oif, pkt->hw.out_zone.name, dst_country, daddr, ntohs(pkt->protohdr->dport)
    );

    pkt->logger->cnt++;
}

void
log_write_nat(struct dnx_pktb *pkt) //, uint8_t direction, uint8_t src_country, uint8_t dst_country)
{};

void
log_exit(struct LogHandle *logger)
{
    if (logger->cnt == LOG_BUFFER_LIMIT) {
        fflush(logger->buf);
        logger->cnt = 0;
    }
}

int
log_rotate(struct LogHandle *logger, struct timeval *ts)
{
    struct tm  *time_info;
    char        file_path[128]; // 46 + label_len + 8 + 1
    char        today[9];

    // closing current file object
    fclose(logger->buf);

    // setting time info to midnight of current date
    time_info = localtime(&ts->tv_sec);
    time_info->tm_hour = 0;
    time_info->tm_min = 0;
    time_info->tm_sec = 0;

    // setting id (date) string to be quickly referenced in log_write function
    strftime(today, 9, "%Y%m%d", time_info);

    // the label is listed twice because the folder is named after the label and filename also contains the label.
    snprintf(file_path, sizeof(file_path), "%s/%s/%s-%s.log", TRAFFIC_LOG_DIR, logger->label, today, logger->label);
    memcpy(logger->id, today, 8);

    // setting rotate time to next day at 00:00:01.
    // the extra second is just to make sure it is the next day
    logger->rotate = mktime(time_info) + 86401;

    // creating and storing new file object
    logger->buf = fopen(file_path, "a");

    return 0;
}
