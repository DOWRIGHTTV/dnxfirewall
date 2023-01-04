#define MQ_PERMISSIONS  0600
#define MQ_MESSAGE_SIZE 2048

#define MQ_CFIREWALL    0;
#define MQ_IP_PROXY     1;
#define MQ_DNS_PROXY    2;
#define MQ_IDS_IPS      3;


struct mq_handle {
    int     ro;  // 0/1 flag for whether this process owns the queue and is responsible for cleanup
    int     id;
    char    key[32];
}

extern int attach(self, int mq_idx, bool ro);
extern int send_msg(int mq_idx, void *data, uint32_t prio);
extern int recv_msg(int mq_idx, char *data, uint32_t prio);
