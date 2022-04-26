#!/usr/bin/env Cython

from libc.stdint cimport uint16_t, uint32_t

cdef extern from "netinet/in.h":
    uint32_t ntohl (uint32_t __netlong) nogil
    uint16_t ntohs (uint16_t __netshort) nogil
    uint32_t htonl (uint32_t __hostlong) nogil
    uint16_t htons (uint16_t __hostshort) nogil

cdef extern from '<arpa/inet.h>':
    ctypedef unsigned long in_addr_t

    struct in_addr:
        pass

    in_addr_t inet_addr(char *cp)

cdef inline void nullset(void *data, size_t dlen) nogil
