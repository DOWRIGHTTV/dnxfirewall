#!/usr/bin/env Cython

from libc.stdio cimport printf, snprintf


cpdef long ipaddress(int ipa):
    '''clamps integer to unsigned 32 bits and returns -1 on overflow.
    '''
    # -1 is safe in python, but will never fall within a valid ip range, so win-win
    if (ipa < 0 or ipa > 4294967295):
        return -1

    return ipa

cpdef long iptoi(str ipa):

    cdef in_addr_t ip_int = inet_addr(<bytes>ipa)

    return ip_int

cpdef str itoip(long ip):

    cdef:
        u_int8_t octets[4]
        char ip_addr[18]

    octets[0] = ip >> 24 & 255
    octets[1] = ip >> 16 & 255
    octets[2] = ip >> 8 & 255
    octets[3] = ip & 255

    snprintf(ip_addr, sizeof(ip_addr), '%d.%d.%d.%d', octets[0], octets[1], octets[2], octets[3])

    return ip_addr.decode('utf-8')
