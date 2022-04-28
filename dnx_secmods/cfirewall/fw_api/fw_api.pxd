#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint32_t

cdef extern from "time.h":
    ctypedef    long time_t

cdef extern from "pwd.h":
    passwd     *getpwnam(const char* name)

    ctypedef uint32_t    uid_t
    ctypedef uint32_t    gid_t

    struct passwd:
        uid_t   pw_uid
        gid_t   pw_gid

cdef extern from "<sys/uio.h>":
   struct iovec:
       void    *iov_base
       size_t   iov_len

cdef extern from "<sys/socket.h>":
    ctypedef uint32_t    socklen_t
    ctypedef uint32_t    sa_family_t

    struct sockaddr:
        sa_family_t   sa_family       # address family
        char         *sa_data         # socket address (variable-length data)

    struct msghdr:
        void        *msg_name        # optional address
        socklen_t    msg_namelen     # size of address
        iovec       *msg_iov         # scatter/gather array
        int          msg_iovlen      # members in msg_iov
        void        *msg_control     # ancillary data, see below
        socklen_t    msg_controllen  # ancillary data buffer len
        int          msg_flags       # flags on received message

    struct cmsghdr:
        socklen_t    cmsg_len        # data byte count, including the cmsghdr
        int          cmsg_level      # originating protocol
        int          cmsg_type       # protocol-specific type

    struct ucred:
        uint32_t     pid
        uint32_t     uid
        uint32_t     gid

    int      socket(int domain, int type, int protocol) nogil
    int      setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) nogil
    int      bind(int socket, const sockaddr *address, socklen_t address_len) nogil
    ssize_t  recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    ssize_t  recvmsg(int socket, msghdr *message, int flags) nogil
    ssize_t  send(int socket, const void *message, size_t length, int flags) nogil
    ssize_t  sendmsg(int socket, const msghdr *message, int flags) nogil

    cmsghdr *CMSG_FIRSTHDR(msghdr *mhdr) nogil
    cmsghdr *CMSG_NXTHDR(msghdr *mhdr, cmsghdr *cmsg) nogil
    uint8_t *CMSG_DATA(cmsghdr *cmsg) nogil

    enum: AF_UNIX
    enum: SOCK_DGRAM

    enum: SOL_SOCKET
    enum: SO_PASSCRED
    enum: SCM_CREDENTIALS

cdef extern from "<sys/un.h>":
    struct sockaddr_un:
        sa_family_t   sun_family  # Address family
        char         *sun_path    # Socket pathname

# ========
# EXPORTS
# ========
cdef struct fwattacker:
    uint32_t    host
    time_t      expire

cdef struct dnxfwmsg:
    uint8_t     control
    uint8_t     id
    uint8_t     len
    uint8_t    *data[128]

cdef void process_api(int fd)
cdef int api_open(char* sock_path)
cdef size_t api_recv(int fd, dnxfwmsg *dfm) # process_api wraps this and is recommended to use