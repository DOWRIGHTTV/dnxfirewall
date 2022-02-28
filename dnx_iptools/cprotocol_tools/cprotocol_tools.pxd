#!/usr/bin/env Cython

cdef extern from "sys/types.h":
    ctypedef unsigned char      u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int       u_int32_t

cdef extern from "netinet/in.h":
    u_int32_t ntohl (u_int32_t __netlong) nogil
    u_int32_t htonl (u_int32_t __hostlong) nogil

cdef extern from '<arpa/inet.h>':
    ctypedef unsigned long in_addr_t

    struct in_addr:
        pass

    in_addr_t inet_addr(char *cp)
