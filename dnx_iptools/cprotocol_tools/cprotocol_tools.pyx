#!/usr/bin/env Cython

from libc.stdio cimport snprintf
from libc.stdint cimport uint8_t, uint32_t, uint_fast16_t

DEF OK  = 1
DEF ERR = 0


cdef uint8_t  UINT8_MAX  = 0b11111111
cdef uint16_t UINT16_MAX = 0b1111111111111111

# TODO: make a biptoi for bytestring to integer conversion

# ==============
# PYTHON ONLY
# ==============
def default_route():
    with open('/proc/net/route', 'r') as f:
        f = f.readlines()[1:]
        for line in f:
            l = line.split()
            if int(l[1], 16) or int(l[7], 16):
                continue

            return ntohl(int(l[2], 16))

        return 0

# ==============
# PYTHON/CYTHON
# ==============
cpdef uint32_t btoia(const uint8_t[:] cb):

    cdef:
        uint32_t i
        uint32_t num = 0

    for i in range(cb.shape[0]):
        num += cb[i]

    return num

cpdef uint32_t iptoi(unicode ipa):

    bipa = ipa.encode('utf-8')

    cdef:
        char* cipa = bipa

        in_addr_t ip_int = inet_addr(cipa)

    return htonl(ip_int)

cpdef unicode itoip(uint32_t ip):

    cdef:
        uint8_t octets[4]
        char ip_addr[18]

    octets[0] = <uint8_t>(ip >> 24) & 255
    octets[1] = <uint8_t>(ip >> 16) & 255
    octets[2] = <uint8_t>(ip >> 8) & 255
    octets[3] = <uint8_t>ip & 255

    snprintf(ip_addr, sizeof(ip_addr), '%d.%d.%d.%d', octets[0], octets[1], octets[2], octets[3])

    return ip_addr.decode('utf-8')

cpdef bytes calc_checksum(const uint8_t[:] data):

    cdef:
        # 16 bit integer is ip packet max
        uint_fast16_t   i
        uint8_t         ubytes[2]

        uint32_t        csum = 0
        uint_fast16_t   dlen = data.shape[0]

    for i in range(0, dlen, 2):
        csum += (data[i] << 8 | data[i + 1])

    # adding trailing byte for odd byte strings
    if (dlen & 1):
        csum += <uint8_t>(data[dlen] << 8)

    while csum >> 16:
        csum = (csum & UINT16_MAX) + (csum >> 16)

    csum ^= UINT16_MAX

    #flipping bytes to network order
    ubytes[0] = (csum >> 8)
    ubytes[1] = csum & UINT8_MAX

    return ubytes


def py_ftok(unicode filepath, int id):
    fpath = filepath.encode('utf-8')

    cdef:
        key_t   ret
        char*   path = fpath

    ret = ftok(path, id)
    if (ret == -1):
        return 0

    return ret

#define PERMS 0644
DEF MQ_PERMISSIONS  = 0o600
DEF MQ_MESSAGE_SIZE = 2048

cdef struct mq_message:
   long int     type
   uint8_t     *data

cdef class MessageQueue:

    cdef:
        int     id

    def __dealloc__(self):
        msgctl(self.id, IPC_RMID, NULL)

    def connect(self, pkey):

        cdef key_t key = <key_t> pkey

        self.id = msgget(key, MQ_PERMISSIONS)
        if (self.id == -1):
            return ERR

        return OK

    def create_queue(self, pkey):

        cdef key_t key = <key_t> pkey

        self.id = msgget(key, MQ_PERMISSIONS | IPC_CREAT)
        if (self.id == -1):
            return ERR

        return OK

    def send_msg(self, const uint8_t[:] data, int type):
        cdef:
            int         ret
            mq_message  mq_msg

        mq_msg.type = type
        mq_msg.data = &data[0]

        ret = msgsnd(self.id, &mq_msg, data.shape[0], 0)
        if (ret == -1):
            return ERR

        return ret

    def recv_msg(self):
        cdef:
            int         ret
            mq_message  mq_msg
            uint8_t     data[MQ_MESSAGE_SIZE]

        mq_msg.data = data

        ret = msgrcv(self.id, &mq_msg, MQ_MESSAGE_SIZE, 0, 0)
        if (ret == -1):
            return ERR

        return data[:ret]
