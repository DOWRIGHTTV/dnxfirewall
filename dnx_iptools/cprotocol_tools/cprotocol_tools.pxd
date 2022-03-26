#!/usr/bin/env Cython

from libc.stdint import uint32_t

cdef extern from "netinet/in.h":
    uint32_t ntohl (uint32_t __netlong) nogil
    uint32_t htonl (uint32_t __hostlong) nogil

cdef extern from '<arpa/inet.h>':
    ctypedef unsigned long in_addr_t

    struct in_addr:
        pass

    in_addr_t inet_addr(char *cp)
