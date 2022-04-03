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
from libc.stdio cimport close
from libc.string cimport memcpy, memset

from libc.stdint cimport uint8_t, uint32_t

# ======================
# SOCKET AUTHENTICATION
# ======================
from os import environ
HOME_DIR = environ['HOME_DIR']

DEF AUTH_UNAME = 'dnx'
DEF API_PATH_DEFAULT = f'{HOME_DIR}/cfirewall/fw_api.sock'

cdef passwd user = getpwnam(<char*>AUTH_UNAME)

UID = user.pw_uid
GID = user.pw_gid
# ======================

DEF OK  = 0
DEF ERR = -1

DEF Py_OK  = 0
DEF Py_ERR = 1

cdef struct fwattacker:
    uint32_t    host
    time_t      expire

cdef struct dnxfwmsg:
    uint8_t     control
    uint8_t     id
    uint8_t    *data[128]

# int len;
# struct ucred ucred;
# len = sizeof(struct ucred);

# if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {

cdef int api_open():

    cdef:
        int     sd, ret

        sockaddr_un *addr = calloc(1, sizeof(sockaddr_un))

    addr.sun_family = AF_UNIX
    addr.sun_path   = API_PATH_DEFAULT

    sd = socket(AF_UNIX, SOCK_DGRAM, 0)
    if (sd == -1):
        return ERR

    setsockopt(sd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval))

    ret = bind(sd, &addr, sizeof(sockaddr_un))
    if (ret == -1):
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
    # loop will break on successfully authenticated and parse message.
    # break or return are both possible loop exits.
    while True:
        dlen = recvmsg(fd, &msg, 0)

        cmsg = CMSG_FIRSTHDR(&msg)
        if (cmsg == NULL):
            continue

        # TODO: see if dnx auth header will always be first. if not adjust accordingly.
        if (cmsg.cmsg_type != SCM_CREDENTIALS):
            continue

        memcpy(&auth, CMSG_DATA(cmsg), sizeof(ucred))

        # --------------------
        # AUTHORIZATION CHECK
        # --------------------
        # if sender is not authorized, the creds struct will get wiped and the loop will continue back to recv.
        if (auth.uid != UID):
            memset(&ucred, 0, sizeof(ucred))

            continue

        # ---------------------
        # DEFINE CALLER STRUCT
        # ---------------------
        dfm.control = msg.msg_iov.iov_base[0]
        dfm.id      = msg.msg_iov.iov_base[1]
        dfm.data    = &msg.msg_iov.iov_base[2]

        return msg.msg_iov.iov_len - 2

        # shouldnt need additional headers as long as CREDS are in first header.
        # while True:
        #     cmsg = CMSG_NXTHDR(&msgh, cmsg)
        #     if (cmsg == NULL):
        #         continue
