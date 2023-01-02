#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t

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

cdef extern from '<sys/ipc.h>':
    enum:
        IPC_CREAT   # Create entry if key does not exist.
        IPC_EXCL    # Fail if key exists.
        IPC_NOWAIT  # Error if request must wait.

        IPC_PRIVATE # Private key.

        IPC_RMID    # Remove identifier.
        IPC_SET     # Set options.
        IPC_STAT    # Get options.

    ctypedef short int key_t

    key_t  ftok(const char*, int)

cdef extern from '<sys/msg.h>':
    int       msgctl(int a, int b, void* c)
    int       msgget(key_t a, int b)
    ssize_t   msgrcv(int a, void* b, size_t c, long int d, int e)
    int       msgsnd(int a, const void* b, size_t c, int d)
