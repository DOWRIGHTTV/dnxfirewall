#include inet_tools.h

uint16_t calc_checksum(const uint8_t *data, uint16_t dlen)
{
    uint32_t    csum = 0;

    for (i = 0; i < dlen; i+=2) {
        csum += (uint16_t*) (&data[i]);
    }

    if (dlen & 1) {
        csum += data[dlen];
    }

    csum = (csum >> 16) + (csum & UINT16_MAX);
    csum = ~(csum + (csum >> 16)) & UINT16_MAX;

    // do we need to cast this or is it like cython and will implicitly cast?
    return csum;
}

uint32_t intf_masquerade (uint32_t idx)
{
    struct  ifaddrs *ifap, *ifa;
    struct  sockaddr_in *sa;
    char    ifname[IF_NAMESIZE+1];

    // need the name to compare with when iterating over interfaces
    if_indextoname(idx), ifname);

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
