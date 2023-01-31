#!/usr/bin/env Cython

from libc.errno cimport *
from libc.stdio cimport snprintf, perror, printf
from libc.stdint cimport uint8_t,  uint16_t, uint32_t, uint_fast16_t
from libc.string cimport strncpy  # memset, memcpy

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

    # TODO: if we slice[:2], shouldnt it compile to string and size?
    return ubytes

# dont need category, proxy will know which one it each based on filter container passed in
def check_filters(uint8_t[:] cat_filter, int sig_ct, unicode domain):

    domain_b = domain.encode('utf-8')

    # START    ->  ">"
    # END      ->  "<"
    # AT       ->  ":" (i1:i2 slice)
    # IN       ->  "?"
    # IN START ->  "]" (:i1 slice)
    # IN END   ->  "[" (-i1: slice)

    # domain rewrites
    # no TLD   ->  "@"

    cdef:
        uint8_t    *search_str = domain_b

        uint8_t     length
        bytes       match_str
        uint8_t     rw, op, i1, i2

        char        i, ix

        uint16_t    offset = 0
        uint8_t     rw_idx = len(domain)

    for i in range(sig_ct):

        length = cat_filter[offset]
        if (length == 0): # can probably get rid of this with the for loop coverage now
            return

        match_str = bytes(cat_filter[offset + 1:offset + length + 1])

        rw = cat_filter[offset + length + 1] # rewrite
        op = cat_filter[offset + length + 2] # operator
        i1 = cat_filter[offset + length + 3] # primary index   (all slices)
        i2 = cat_filter[offset + length + 4] # secondary index (middle slices only, as end index)

        # remove TLD
        if (rw == ord('@')):
            for ix in range(rw_idx, 0, -1):
                if search_str[-ix] == ord('.'):
                    rw_idx -= ix

                    break

#        print(op, match_str[:length], search_str[:length])
        # at start - ignore rewrite for now since it only modifies the end
        if (op == ord('>')):
            if (match_str[:length] == search_str[:length]): return '>', match_str[:length]

        # at end [] - tot
        elif (op == ord('<')):
            if (search_str[:rw_idx][-length:] == match_str[:length]): return '<', match_str[:length]

        # in middle - [i1:i2]
        elif (op == ord(':')):
            if (search_str[:rw_idx][i1:i2] == match_str[:length]): return ':', match_str[:length]

        # full domain membership
        elif (op == ord('?')):
            if (match_str[:length] in search_str[:rw_idx]): return '?', match_str[:length]

        # partial membership, beginning
        elif (op == ord(']')):
            if (match_str[:length] in search_str[:rw_idx][:i1]): return ']', match_str[:length]

        # partial membership, end
        elif (op == ord('[')):
            if (match_str[:length] in search_str[:rw_idx][i1:]): return '[', match_str[:length]

        offset += (length + 5)

# ============================
# Python Extension Types
# ============================
# designed to be used with pure python (no C/Cython compatibility)
# ----------------------------
# IPC (POSIX) - MessageQueue
# ----------------------------
# DEF MQ_PERMISSIONS   = 0o600
# DEF MQ_MESSAGE_SIZE  = 2048
# DEF MQ_MESSAGE_LIMIT = 10  # number of total messages sitting in queue

# cdef class MessageQueue:
#
#     cdef:
#         bint      ro
#         mqd_t     id
#         int       keylen
#         char      key[32]
#
#
#     def __dealloc__(self):
#         if (not self.ro):
#             mq_unlink(self.key)
#
#         mq_close(self.id)
#
#     def connect(self, unicode pkey):
#
#         self.keylen = len(pkey)
#         bpkey = pkey.encode('utf-8')
#
#         cdef:
#             char*   key = bpkey
#
#         strncpy(self.key, key, self.keylen)
#
#         self.id = mq_open(self.key, O_RDONLY, 0, NULL)
#         if (<int> self.id == -1):
#             perror("connect error")
#             return ERR
#
#         self.ro = False
#
#         return OK
#
#     def create_queue(self, unicode pkey):
#
#         self.keylen = len(pkey)
#         bpkey = pkey.encode('utf-8')
#
#         cdef:
#             char*   key = bpkey
#             mq_attr attr
#
#         strncpy(self.key, key, self.keylen)
#
#         attr.mq_maxmsg  = MQ_MESSAGE_LIMIT
#         attr.mq_msgsize = MQ_MESSAGE_SIZE
#
#         self.id = mq_open(self.key, O_WRONLY | O_CREAT, MQ_PERMISSIONS, &attr)
#         if (<int> self.id == -1):
#             perror("create_error")
#             return ERR
#
#         self.ro = False
#
#         return OK
#
#     def send_msg(self, const uint8_t[:] data, unsigned int prio):
#         cdef:
#             int         ret
#
#         ret = mq_send(self.id, <const char*>&data[0], data.shape[0], prio)
#         if (ret == -1):
#             perror("send error")
#             return ERR
#
#         return ret
#
#     def recv_msg(self, unsigned int prio):
#         cdef:
#             int         ret
#             char        data[MQ_MESSAGE_SIZE]
#
#         ret = mq_receive(self.id, data, MQ_MESSAGE_SIZE, &prio)
#         if (ret == -1):
#             perror("receive error")
#             return ERR
#
#         return data[:ret]
