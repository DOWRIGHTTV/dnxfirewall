#include "config.h"
#include "cfirewall.h"
#include "traffic_log.h"

struct LogHandle Log[2];

void
log_init(struct LogHandle *logger, char *label)
{
    strcpy(logger->label, label);
    memset(logger->id, 0, 1);

    logger->buf = fopen("/dev/null", "a");
    logger->cnt = 0;
}

void
log_enter(struct LogHandle *logger)
{
    char today[9];

    // open a new file if the day has changed. this might be changes to 8 hour blocks or something in the future
    check_current_date(today);
    if (logger->id != today) {
        log_rotate(logger, today);
    }
}

void
log_write_firewall(struct dnx_pktb *pkt, uint8_t direction, uint8_t src_country, uint8_t dst_country)
{
    char saddr[18];
    char daddr[18];

    // converting ip as integer to a dot notation string eg. 192.168.1.1
    itoip(pkt->iphdr->saddr, saddr);
    itoip(pkt->iphdr->daddr, daddr);

    fprintf(pkt->logger->buf, FW_LOG_FORMAT,
        (uint8_t) pkt->rule->name, pkt->action, direction, pkt->iphdr->protocol,
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
// since the date will be checked before every message (for now), we will require it to be passed in here.
log_rotate(struct LogHandle *logger, char* current_date)
{
    char file_path[128]; // 46 + label_len + 8 + 1

    // closing current file object
    fclose(logger->buf);

    // the label is listed twice because the folder is named after the label and filename also contains the label.
    snprintf(file_path, sizeof(file_path), "%s/%s/%s-%s.log", TRAFFIC_LOG_DIR, logger->label, current_date, logger->label);
    memcpy(logger->id, current_date, 8);

    // creating and storing new file object
    logger->buf = fopen(file_path, "a");

    return 0;
}

void
check_current_date(char* buf)
{
    time_t      epoch;
    struct tm  *time_info;

    epoch     = time(NULL);
    time_info = localtime(&epoch);

    strftime(buf, 9, "%Y%m%d", time_info);
}
