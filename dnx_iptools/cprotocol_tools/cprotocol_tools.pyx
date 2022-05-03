from libc.stdio cimport snprintf
from libc.stdint cimport uint8_t, uint32_t, uint_fast16_t

DEF UINT8_MAX  = 255
DEF UINT16_MAX = 65535

# TODO: make a biptoi for bytestring to integer conversion

# ==============
# PYTHON ONLY
# ==============
def default_route():
    with open('/proc/net/route', 'r') as f:
        f = f.readlines()[1:]
        for line in f:
            l = line.split()
            if int(l[1], 16) or int(l[7], 16):
                continue

            return int(l[2], 16)

        return 0

# ==============
# PYTHON/CYTHON
# ==============
cpdef uint32_t btoia(const uint8_t[:] cb):

    cdef:
        uint32_t i
        uint32_t num = 0

    for i in range(cb.shape[0]):
        num += cb[i]

    return num

cpdef uint32_t iptoi(unicode ipa):

    bipa = ipa.encode('utf-8')

    cdef:
        char* cipa = bipa

        in_addr_t ip_int = inet_addr(cipa)

    return htonl(ip_int)

cpdef unicode itoip(uint32_t ip):

    cdef:
        uint8_t octets[4]
        char ip_addr[18]

    octets[0] = <uint8_t>(ip >> 24) & 255
    octets[1] = <uint8_t>(ip >> 16) & 255
    octets[2] = <uint8_t>(ip >> 8) & 255
    octets[3] = <uint8_t>ip & 255

    snprintf(ip_addr, sizeof(ip_addr), '%d.%d.%d.%d', octets[0], octets[1], octets[2], octets[3])

    return ip_addr.decode('utf-8')

cpdef bytes calc_checksum(const uint8_t[:] data):

    cdef:
        # 16 bit integer is ip packet max
        uint_fast16_t   i
        uint8_t         ubytes[2]

        uint32_t        csum = 0
        uint_fast16_t   dlen = data.shape[0]

    for i in range(0, dlen, 2):
        csum += (data[i] << 8 | data[i + 1])

    # adding trailing byte for odd byte strings
    if (dlen & 1):
        csum += <uint8_t>data[dlen]

    csum = (csum >> 16) + (csum & UINT16_MAX)
    csum = ~(csum + (csum >> 16)) & UINT16_MAX

    # couldn't this be ubytes = <uint16_t>csum
    ubytes[0] = <uint8_t>(csum >> 8)
    ubytes[1] = csum & UINT8_MAX

    return ubytes
