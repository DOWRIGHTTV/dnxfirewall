#ifndef INET_TOOLS_H
#define INET_TOOLS_H

#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>


#define UINT16_MAX 65535

typedef uint_fast8_t    uint8f_t;
typedef uint_fast16_t   uint16f_t;
typedef uint_fast32_t   uint32f_t;

uint16_t calc_checksum(const uint8_t *data, uint16_t dlen)
unsigned int intf_masquerade (unsigned int idx)

#endif