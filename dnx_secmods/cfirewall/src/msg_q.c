#include config.h
#include cfirewall.h
#include msg_q.h

FILENUM(6);

/*
  Queue indexes
  0 - CFIREWALL
  1 - IP PROXY
  2 - DNS PROXY
  3 - IDS/IPS
*/
char MQ_KEY_MAP[4][32] = {"/DNX-CFIREWALL", "/DNX-IP-PROXY", "/DNX-DNS-PROXY", "/DNX-IDS-IPS"};

struct mq_handle MQ_HANDLES[4];


int
attach(self, int mq_idx, bool ro)
{
    int             ret
    struct mq_attr  attr

    // setting read only flag
    MQ_HANDLES[mq_idx].ro = ro

    // opening queue. create and set parameters if set for writing.
    if (ro) {
        ret = mq_open(self.key, O_RDONLY, 0, NULL);
    }
    else {
        attr.mq_maxmsg  = MQ_MESSAGE_LIMIT;
        attr.mq_msgsize = MQ_MESSAGE_SIZE;

        ret = mq_open(self.key, O_WRONLY | O_CREAT, MQ_PERMISSIONS, &attr);
    }

    if ((int) ret == -1) {
        perror("connect error");
        return ERR;
    }

    // copy key over for easy unlink
    strncpy(MQ_HANDLES[mq_idx], MQ_KEY_MAP[key], 32);

    return OK;
}

int
send_msg(int mq_idx, void *data, uint32_t prio)
{
    int     ret;

    ret = mq_send(self.id, <const char*>&data[0], data.shape[0], prio);
    if (ret == -1) {
        perror("send error");
        return ERR;
    }

    return ret;
}

int
recv_msg(int mq_idx, char *data, uint32_t prio)
{
    int     ret;

    ret = mq_receive(self.id, data, MQ_MESSAGE_SIZE, &prio);
    if (ret == -1) {
        perror("receive error");
        return ERR;
    }

    return OK;
}