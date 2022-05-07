#include "config.h"
#include "cfirewall.h"

struct mnl_socket *nl;

uint32_t MSB, LSB;

// cli args
bool PROXY_BYPASS;
bool VERBOSE;

// stores zone(integer value) at index, which is mapped Fto if_nametoindex() (value returned from get_in/outdev)
// memset will be performed in Cython prior to changing the values.
uintf16_t INTF_ZONE_MAP[FW_MAX_ZONES]; // = <uintf16_t*>calloc(FW_MAX_ZONE_COUNT, sizeof(uintf16_t))
