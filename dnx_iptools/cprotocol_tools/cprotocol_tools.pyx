#!/usr/bin/env Cython

from libc.errno cimport *
from libc.stdlib cimport strtol
from libc.stdio cimport snprintf, perror, printf
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint_fast16_t
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

cpdef unicode hextoip(unicode hex_ip):

    bhex = hex_ip.encode('utf-8')

    cdef:
        char* chex = bhex

        uint32_t ip = <uint32_t>strtol(chex, NULL, 16)

    return itoip(ntohl(ip))


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

cdef int cmp(uint8_t *search_str, uint8_t *match_str, uint32_t mlen, uint32_t offset) nogil:
    cdef:
        int     i, midx = mlen - 1

    # OVERFLOW in search string - fast exit path
    # if (offset < 0): return -1
    # first char - no match
    if (match_str[0] != search_str[offset]): return -1
    # last char - no match
    if (match_str[midx] != search_str[offset + midx]): return -1

    for i in range(midx):

        if (match_str[i] != search_str[i + offset]):
            return 0

    return 1

cdef int find(uint8_t *search_str, uint8_t *match_str, uint32_t mlen, uint32_t bounds) nogil:

    cdef:
        uint32_t    i, ix = 0
        uint32_t    midx = mlen - 1

        uint32_t    left  = bounds >> 16
        uint32_t    right = bounds & UINT16_MAX
        uint32_t    slen  = right - left

    # match str is bigger than search string - fast exit path
    if (mlen > slen): return 0

    for i in range(slen):
        # first char - no match
        if (match_str[0] != search_str[left + i]): continue
        # OVERFLOW in search string - fast exit path
        if (i + midx >= slen): return 0
        # last char - no match
        if (match_str[midx] != search_str[left + i + midx]): continue

        for ix in range(1, midx):

            if (match_str[midx - ix] != search_str[(i + midx) - ix]):
                break

        if (ix == midx - 1):
            return 1

    return 0

cdef inline int tld_idx(uint8_t *search_str, int slen):
    cdef int ix

    for ix in range(1, slen):

        if search_str[-ix] == ord('.'): return ix

    return 0

# dont need category, proxy will know which one based on filter container passed in
def check_filters(uint8_t[:] cat_filter, uint32_t sig_ct, const uint8_t[:] domain):
    # domain rewrites / special options
    # no TLD   ->  "@" (decrements right bound by length of ".tld"
    # int scan ->  "i" (sum of chars / number of chars = avg ord value | set threshold in n2??)

    # START    ->  ">"
    # END      ->  "<"
    # IN       ->  "?"
    # IN START ->  "]" (:n1 slice)
    # IN END   ->  "[" (n1: slice)
    cdef:
        uint8_t        *search_str = <uint8_t*> &domain[0]
        uint32_t        slen = domain.shape[0]

        uint8_t        *match_str
        operators      *ops
        uint32_t        i, ix, mlen

        uint32_t        rw_idx = 0
        uint32_t        offset = 0

    for i in range(sig_ct):

        mlen = cat_filter[offset]
        match_str = <uint8_t*> &cat_filter[offset + 1]

        ops = <operators*> &cat_filter[offset + mlen + 1]
        # ==========================
        # REWRITE / SPECIAL OPTIONS
        # ==========================
        # remove TLD
        if (ops.rw == ord('@')):
            rw_idx = tld_idx(search_str, slen)

        elif (ops.rw == ord('i')):
            pass

        # ==========================
        # SEARCH TYPE OPERATORS
        # ==========================
        # rw_idx is used to additionally adjust the index bounds. for example, to skip the TLD in the search
        # startswith
        if (ops.op == ord('>')):
            if cmp(search_str, match_str, mlen, 0): return ord('>')

        # endswith
        elif (ops.op == ord('<')):
            # OVERFLOW in search string - fast exit path
            if ((mlen + rw_idx) > slen): return 0

            if cmp(search_str, match_str, mlen, slen - (mlen + rw_idx)): return ord('<')

        # general membership - find fn will handle its own overflow checks since they won't produce negatives
        elif (ops.op == ord('?')):
            if find(search_str, match_str, mlen, slen - rw_idx): return ord('?')

        elif (ops.op == ord(']')):
            if find(search_str, match_str, mlen, ops.n1): return ord(']')

        elif (ops.op == ord('[')):
            if find(search_str, match_str, mlen, (ops.n1 << 16 | slen - rw_idx)): return ord('[')

        offset += (mlen + 5)

    return 0


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
