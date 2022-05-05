#!/usr/bin/env Cython

from cpython cimport array
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdint cimport uint_fast8_t, uint_fast16_t, uint_fast32_t, int_fast8_t, int_fast16_t, int_fast32_t
from libc.stdio cimport FILE

from posix.types cimport pid_t

# LIBMNL && LIBNETFILTER_QUEUE SOURCE FILES
# https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2
# https://netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2

# DNXFIREWALL TYPEDEFS
ctypedef array.array    PyArray
ctypedef uint_fast8_t   uintf8_t
ctypedef uint_fast16_t  uintf16_t
ctypedef uint_fast32_t  uintf32_t

# NOTE: might not need anymore... confirm
cdef extern from "<stdbool.h>":
    pass
    # ctypedef int bool
    # ctypedef int true
    # ctypedef int false

cdef extern from "<time.h>" nogil:
    ctypedef long   time_t

    time_t      time(time_t*)
    struct timeval:
        time_t  tv_sec
        time_t  tv_usec

cdef extern from "<sys/socket.h>":
    ctypedef unsigned int   socklen_t

    ssize_t     recv(int __fd, void *__buf, size_t __n, int __flags) nogil

    enum: AF_INET

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_mutex_t:
        pass

    int pthread_mutex_lock(pthread_mutex_t*)
    int pthread_mutex_unlock(pthread_mutex_t*)

# cdef extern from "libnfnetlink/libnfnetlink.h" nogil:
#     struct nfnl_handle:
#         pass
#
#     unsigned int nfnl_rcvbufsiz(nfnl_handle *h, unsigned int size)
