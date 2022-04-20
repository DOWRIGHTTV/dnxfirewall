#!/usr/bin/env Cython

# CONTROL
# =========
# 1. INFORM
# 2. SET
# 3. UNSET

# ID
# =========
# 1. RULE_UPDATE
# 2. ATTACKER

from libc.stdlib cimport calloc
from libc.stdio cimport printf, close
from libc.string cimport memcpy, memset

from libc.stdint cimport uint8_t, uint32_t

# ======================
# SOCKET AUTHENTICATION
# ======================
DEF AUTH_UNAME = 'dnx'

cdef passwd user = getpwnam(<char*>AUTH_UNAME)

UID = user.pw_uid
GID = user.pw_gid
# ======================

DEF OK  = 0
DEF ERR = -1

DEF Py_OK  = 0
DEF Py_ERR = 1

DEF FW_MSG_MAX_SIZE = 132

cdef struct fwattacker:
    uint32_t    host
    time_t      expire

cdef struct dnxfwmsg:
    uint8_t     control
    uint8_t     id
    uint8_t     len
    uint8_t    *data[128]


cdef void process_api(int fd):

    cdef:
        size_t    dlen
        dnxfwmsg  dmsg

    dlen = api_recv(fd, &dnxfwmsg)
    if (dlen == ERR):
        # dis real bad, but shouldnt happen now because the thread would crash first
        return

    # handle_packet
    # handle_routine > // make routine file and move ips block list set there.

cdef int api_open(char* sock_path):

    cdef:
        int     sd, ret

        int     opt_val = 1
        sockaddr_un *addr = calloc(1, sizeof(sockaddr_un))

    addr.sun_family = AF_UNIX
    addr.sun_path   = sock_path

    sd = socket(AF_UNIX, SOCK_DGRAM, 0)
    if (sd == ERR):
        return ERR

    setsockopt(sd, SOL_SOCKET, SO_PASSCRED, <void*>&opt_val, sizeof(opt_val))

    ret = bind(sd, &addr, sizeof(sockaddr_un))
    if (ret == ERR):
        close(sd)

        return ERR

    return sd

cdef size_t api_recv(int fd, dnxfwmsg *dfm):

    cdef:
        msghdr      msg
        cmsghdr    *cmsg
        ucred       auth

        ssize_t     dlen

    # -------------
    # RECEIVE LOOP
    # -------------
    # loop will return to caller on successfully authenticated and parsed message.
    # ERR is returned if the loop breaks without returning (currently not possible)
    while True:
        dlen = recvmsg(fd, &msg, 0)

        if (dlen >= FW_MSG_MAX_SIZE):
            continue

        cmsg = CMSG_FIRSTHDR(&msg)
        if (cmsg == NULL):
            continue

        # TODO: see if dnx auth header will always be first. if not adjust accordingly.
        if (cmsg.cmsg_type != SCM_CREDENTIALS):
            printf(<char*>'CONTINUE - not scm_creds')
            continue

        memcpy(&auth, CMSG_DATA(cmsg), sizeof(ucred))

        # ---------------------
        # AUTHORIZATION CHECK
        # ---------------------
        # if the sender is not authorized the creds struct will get wiped and the loop will continue back to recv.
        if (auth.uid != UID):
            memset(&ucred, 0, sizeof(ucred))

            continue

        # ----------------------
        # DEFINE CALLERS STRUCT
        # ----------------------
        dfm.control = msg.msg_iov.iov_base[0]
        dfm.id      = msg.msg_iov.iov_base[1]
        dfm.data    = &msg.msg_iov.iov_base[2]

        return msg.msg_iov.iov_len - 2

        # shouldnt need additional headers as long as CREDS are in first header.
        # while True:
        #     cmsg = CMSG_NXTHDR(&msgh, cmsg)
        #     if (cmsg == NULL):
        #         continue

    return ERR