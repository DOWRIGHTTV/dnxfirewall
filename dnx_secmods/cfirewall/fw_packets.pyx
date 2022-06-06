#!/usr/bin/env Cython

from dnx_secmods.cfirewall.fw_main.fw_main cimport *

# calculates and returns calculated standard tcp/ip checksum
cdef u_int16_t checksum(void *pkt_data, size_t dlen) nogil:

    cdef:
        size_t i
        u_int32_t csum = 0

    # subtract 1 from dlen to account for 0 index
    for i in range(0, dlen-1, 2):
        csum += <u_int16_t*>pkt_data[i]

    # odd bytes needs last one added separately
    if (dlen & 1):
        csum += <u_int8_t*>pkt_data[dlen-1]

    # fold 32-bit sum to 16 bits (x2) then bitwise NOT for inverse
    csum = (csum >> 16) + (csum & 65535)
    csum += csum >> 16

    return htons(<u_int16_t>~csum)

cdef inline void reject_packet() nogil:
    pass
