#ifndef INET_TOOLS_H
#define INET_TOOLS_H

#include <stdint.h>


typedef uint_fast8_t    uintf8_t;
typedef uint_fast16_t   uintf16_t;
typedef uint_fast32_t   uintf32_t;

uint16_t calc_checksum(const uint8_t *data, uint16_t dlen);
void itoip(uint32_t ip_int, char* ip_addr);
unsigned int intf_masquerade(unsigned int idx);

#endif