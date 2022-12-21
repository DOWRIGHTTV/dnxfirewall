#include "config.h"
#include "cfirewall.h"
#include "traffic_log.h"

struct sockaddr_un database_service = { .sun_family = AF_UNIX };

int database_service_sock;
struct ucred database_creds;

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
log_enter(struct LogHandle *logger, struct timeval *ts)
{
    dprint(VERBOSE, "<-log enter\n");
    // open a new file if the day has changed. this might be changes to 8 hour blocks or something in the future
    if (ts->tv_sec >= logger->rotate) {
        log_rotate(logger, ts);
    }
}

// consider making the countries a tuple as struct
void
log_write_firewall(struct LogHandle *logger, struct timeval *ts, struct dnx_pktb *pkt)
{
    char    saddr[18];
    char    daddr[18];

    // converting ip as integer to a dot notation string eg. 192.168.1.1
    itoip(pkt->iphdr->saddr, saddr);
    itoip(pkt->iphdr->daddr, daddr);

    fprintf(pkt->logger->buf, FW_LOG_FORMAT, ts->tv_sec, ts->tv_usec,
        pkt->fw_rule->name, action_map[pkt->action], dir_map[pkt->geo.dir], pkt->iphdr->protocol,
        pkt->hw.iif, pkt->hw.in_zone.name, pkt->geo.src, saddr, ntohs(pkt->protohdr->sport),
        pkt->hw.oif, pkt->hw.out_zone.name, pkt->geo.dst, daddr, ntohs(pkt->protohdr->dport)
    );

    logger->cnt++;

    dprint(FW_V & VERBOSE, "|logged|");
}

//void
//log_write_nat(struct LogHandle *logger, struct dnx_pktb *pkt) //, uint8_t direction, uint8_t src_country, uint8_t dst_country)
//{};

void
log_exit(struct LogHandle *logger)
{
    dprint(VERBOSE, "log exit-->\n");
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
log_db_init()
{
    struct passwd *pwd = getpwnam(DNX_USER);
       //char   *pw_name;       /* username */
       //char   *pw_passwd;     /* user password */
       //uid_t   pw_uid;        /* user ID */
       //gid_t   pw_gid;        /* group ID */
       //char   *pw_gecos;      /* user information */
       //char   *pw_dir;        /* home directory */
       //char   *pw_shell;      /* shell program */

    database_creds.pid = getpid();
    database_creds.uid = pwd->pw_uid;
    database_creds.gid = pwd->pw_gid;

    // copy sock filepath to struct
    strncpy(database_service.sun_path, DATABASE_SERVICE, sizeof(database_service.sun_path) - 1);

    database_service_sock = socket(AF_UNIX, SOCK_DGRAM, 0);

    connect(database_service_sock, &database_service, sizeof(struct sockaddr_un));
}

// required data is encoded in the packet mark per dnx standard
// (country (8b) | (direction (2b) | action (2b)
void
log_db_geolocation(struct geolocation *geo, uint8_t pkt_action)
{
    /* ===========================================
    DEFINING LOG MESSAGE DATA
    =========================================== */
    char log_data[96]; // 3 spaces for country, 1 for null term
    struct iovec log_msg = { log_data, sizeof(log_data) };

    snprintf(log_data, sizeof(log_data), DB_LOG_FORMAT, geo->remote, geo->dir, pkt_action);

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

    memcpy(CMSG_DATA(cmsg), &database_creds, sizeof(struct ucred));

    /* ===========================================
    SEND TO SERVICE SOCKET
    blindly sending since it is a local socket
    and we do not expect a confirmation of receipt.
    =========================================== */
    sendmsg(database_service_sock, &db_message, 0);
}
