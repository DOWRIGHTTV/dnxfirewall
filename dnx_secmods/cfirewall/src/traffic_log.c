#include "config.h"
#include "cfirewall.h"
#include "traffic_log.h"

FILENUM(8);

struct LogHandle Log[2];
struct dnx_db_service db_service;

char*   action_map[] = { "deny", "accept", "reject" };
char*   dir_map[]    = { "unknown", "outbound", "inbound" };

void
log_init(int logger_idx, char *label)
{
    struct LogHandle *logger = &Log[logger_idx];

    strcpy(logger->label, label); // eg. firewall, nat
    memset(logger->id, 0, 1); // eg. 20220704

    logger->buf    = fopen("/dev/null", "a");
    logger->rotate = 0;
    logger->cnt    = 0;
}

inline void
log_enter(struct LogHandle *logger, struct timeval *ts)
{
    dprint(VERBOSE, "<-log enter\n");
    // open a new file if the day has changed. this might be changes to 8 hour blocks or something in the future
    if (ts->tv_sec >= logger->rotate) {
        log_rotate(logger, ts);
    }
}

void
log_write_firewall(int logger_idx, struct dnx_pktb *pkt)
{
    struct LogHandle *logger = &Log[logger_idx];

    struct timeval  timestamp;

    char    saddr[18];
    char    daddr[18];

    gettimeofday(&timestamp, NULL);

    log_enter(logger, &timestamp);

    // converting ip as integer to a dot notation string eg. 192.168.1.1
    itoip(pkt->iphdr->saddr, saddr);
    itoip(pkt->iphdr->daddr, daddr);

    fprintf(logger->buf, FW_LOG_FORMAT, timestamp.tv_sec, timestamp.tv_usec,
        pkt->rule_name, action_map[pkt->action], dir_map[pkt->geo.dir], pkt->iphdr->protocol,
        pkt->hw.iif, pkt->hw.in_zone.name, pkt->geo.src, saddr, ntohs(pkt->protohdr->sport),
        pkt->hw.oif, pkt->hw.out_zone.name, pkt->geo.dst, daddr, ntohs(pkt->protohdr->dport)
    );
    logger->cnt++;

    dprint(FW_V & VERBOSE, "|logged|");

    log_exit(logger);
}

//void
//log_write_nat(struct LogHandle *logger, struct dnx_pktb *pkt) //, uint8_t direction, uint8_t src_country, uint8_t dst_country)
//{};

inline void
log_exit(struct LogHandle *logger)
{
    if (logger->cnt == LOG_BUFFER_LIMIT) {
        fflush(logger->buf);
        logger->cnt = 0;
    }
    dprint(VERBOSE, "log exit-->\n");
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
    time_info->tm_min  = 0;
    time_info->tm_sec  = 0;

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

/* this will be used on cfirewall deny OR if an accept doesnt have an ip proxy profile set
this will prevent the packet from needing to be redirected to the IPP queue and reprocessed unless the ip proxy
was configured with an inspection module.

-- i feel like this will drastically improve throughput because deferred action requires a full re parse of the packet
through netfilter queue, then converted transferred a python object and send through the proxy logger client instance.

NOTE: overriding SCM_CREDENTIALS with the dnxfirewall system user (vs root) for explicit authentication of receiving end
which also reduces authorization code complexity.
*/
void
log_db_init(void)
{
    db_service.addr.sun_family = AF_UNIX;
    // copy sock filepath to struct
    strncpy(db_service.addr.sun_path, DATABASE_SERVICE, sizeof(db_service.addr.sun_path) - 1);

    struct passwd *pwd = getpwnam(DNX_USER);
       //char   *pw_name;       /* username */
       //char   *pw_passwd;     /* user password */
       //uid_t   pw_uid;        /* user ID */
       //gid_t   pw_gid;        /* group ID */
       //char   *pw_gecos;      /* user information */
       //char   *pw_dir;        /* home directory */
       //char   *pw_shell;      /* shell program */

    db_service.creds.pid = getpid();
    db_service.creds.uid = pwd->pw_uid;
    db_service.creds.gid = pwd->pw_gid;

    db_service.fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    // dont care about return value. if connect fails it will retried before sending log message.
    log_db_connect();
}

inline int
log_db_connect(void)
{
    int ret = connect(db_service.fd, &db_service.addr, sizeof(db_service.addr));

    // updating conn tracker value. this is used to determine if we need to attempt a reconnect.
    db_service.connected = ret != ERR ? true : false;

    return ret;
}

void
log_db_geolocation(struct geolocation *geo, uint8_t pkt_action)
{
    if (!db_service.connected) {
        // returns if unable to reconnect so we dont waste cycles
        if (log_db_connect() == ERR) return;
    }
    /* ===========================================
    DEFINING LOG MESSAGE DATA
    =========================================== */
    char log_data[68];
    struct iovec log_msg;

    log_msg.iov_base = log_data;
    log_msg.iov_len  = snprintf(log_data, sizeof(log_data), DB_LOG_FORMAT, geo->remote, geo->dir, pkt_action);
    /* ===========================================
    BUILDING SOCKET MESSAGE HEADER
    includes: packet/log data, ancillary data
    =========================================== */
    union {
        char buf[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr align;
    } u;

    struct msghdr db_message = {
        //void          *msg_name        Optional address.
        //socklen_t      msg_namelen     Size of address.
        //struct iovec  *msg_iov         Scatter/gather array.
        //int            msg_iovlen      Members in msg_iov.
        //void          *msg_control     Ancillary data; see below.
        //socklen_t      msg_controllen  Ancillary data buffer len.
        //int            msg_flags       Flags on received message.
        .msg_iov = &log_msg,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = sizeof(u.buf)
    };
    /* ===========================================
    DEFINING CONTROL MESSAGE DATA
    =========================================== */
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&db_message);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_CREDENTIALS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct ucred));

    memcpy(CMSG_DATA(cmsg), &db_service.creds, sizeof(struct ucred));
    /* ===========================================
    SEND TO SERVICE SOCKET
    =========================================== */
    // blindly sending since it is a local socket and we do not expect a confirmation of receipt.
    sendmsg(db_service.fd, &db_message, 0);
}
