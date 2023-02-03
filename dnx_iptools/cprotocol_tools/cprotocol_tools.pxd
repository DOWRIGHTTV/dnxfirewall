#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t

cdef extern from "netinet/in.h":
    uint32_t ntohl (uint32_t __netlong) nogil
    uint16_t ntohs (uint16_t __netshort) nogil
    uint32_t htonl (uint32_t __hostlong) nogil
    uint16_t htons (uint16_t __hostshort) nogil

cdef extern from '<fcntl.h>':
    enum:
        O_CREAT
        O_EXCL

        O_RDONLY
        O_WRONLY
        O_RDWR

cdef extern from '<arpa/inet.h>':
    ctypedef unsigned long in_addr_t

    struct in_addr:
        pass

    in_addr_t inet_addr(char *cp)

cdef struct operators:
    uint8_t    rw
    uint8_t    op
    uint8_t    n1
    uint8_t    n2

# ctypedef int mode_t
#
# cdef extern from '<mqueue.h>':
#     ctypedef void* mqd_t
#
#     struct mq_attr:
#         long int mq_flags
#         long int mq_maxmsg
#         long int mq_msgsize
#         long int mq_curmsgs
#
#     mqd_t   mq_open(const char *name, int oflag, mode_t mode, mq_attr *attr)
#     int     mq_close(mqd_t mqdes)
#     int     mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio)
#     ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio)
#     int     mq_unlink(const char *name)
