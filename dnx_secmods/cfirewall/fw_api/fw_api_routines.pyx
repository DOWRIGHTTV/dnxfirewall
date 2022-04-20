#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t

from fw_main.fw_main cimport ATTACKER_BLOCKLIST

cdef int remove_attacker(uint32_t host_ip):

    cdef:
        size_t    i, idx
        uint32_t  blocked_ip

    pthread_mutex_lock(&FWblocklistlock)

    for idx in range(FW_MAX_ATTACKERS):

        blocked_ip = ATTACKER_BLOCKLIST[idx]

        # reached end without host_ip match
        if (blocked_ip == END_OF_ARRAY):
            return Py_ERR

        # host_ip match, current idx will carry over to shift
        elif (blocked_ip == host_ip):
            break

    for i in range(idx, FW_MAX_ATTACKERS):

        if (ATTACKER_BLOCKLIST[i] == END_OF_ARRAY):
            break

        ATTACKER_BLOCKLIST[i] = ATTACKER_BLOCKLIST[i + 1]

    pthread_mutex_unlock(&FWblocklistlock)

    return Py_OK