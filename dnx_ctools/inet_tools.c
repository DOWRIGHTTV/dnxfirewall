#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "include/inet_tools.h"

//reference data - csum->b'x81\x02' | 33026
// b'E\x00\x00(\xd9\x04@\x00@\x06\x83\x08\x97e\x00\x00\xc0\xa8\x05\xb3\x01\xbb\x9fv\x0fvl\xfa\x03e\x86\xcbP\x10\x05\xc0#\x7f\x00\x00'
// '0x45 0x0 0x0 0x28 0xd9 0x4 0x40 0x0 0x40 0x6 0x83 0x8 0x97 0x65 0x0 0x0 0xc0 0xa8 0x5 0xb3'

uint16_t
calc_checksum (const uint8_t *data, uint16_t dlen)
{
    uint32_t    csum = 0;

    for (uint16_t i = 0; i < dlen; i+=2) {
        csum += (data[i] << 8 | data[i+1]);
    }

    // handle odd byte out if needed
    if (dlen & 1) {
        csum += (data[dlen] << 8);
    }

    while (csum >> 16) {
        csum = (csum >> 16) + (csum & UINT16_MAX);
    }
    csum ^= UINT16_MAX;

    return htons(csum);
}

void
itoip(uint32_t ip_int, char* ip_addr)
{
    uint8_t octets[4];

    ip_int = ntohl(ip_int);

    octets[0] = (ip_int >> 24) & 255;
    octets[1] = (ip_int >> 16) & 255;
    octets[2] = (ip_int >> 8) & 255;
    octets[3] = ip_int & 255;

    snprintf(ip_addr, 18, "%u.%u.%u.%u", octets[0], octets[1], octets[2], octets[3]);
}

uint32_t
intf_masquerade (uint32_t idx)
{
    struct  ifaddrs *ifap, *ifa;
    struct  sockaddr_in *sa;
    char    ifname[IF_NAMESIZE+1];

    // need the name to compare with when iterating over interfaces
    if_indextoname(idx, ifname);

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

        if (strcmp(ifname, ifa->ifa_name) != 0) { continue; }
        if (!ifa->ifa_addr) { continue; }
        if (ifa->ifa_addr->sa_family != AF_INET) { continue; }

        sa = (struct sockaddr_in*) ifa->ifa_addr;

        freeifaddrs(ifap);
        return sa->sin_addr.s_addr;
    }
    freeifaddrs(ifap);

    return 0;
}
// for now in case i need to tshoot
#ifndef CFIREWALL_H
int main ()
{
    return 0;
}
#endif
