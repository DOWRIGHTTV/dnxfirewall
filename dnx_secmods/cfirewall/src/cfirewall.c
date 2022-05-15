#include "config.h"
#include "cfirewall.h"

uint32_t MSB, LSB;

// cli args
bool PROXY_BYPASS;
bool VERBOSE;
bool VERBOSE2;

bool FW_V;
bool NAT_V;

struct mnl_socket *wtf_nl;
struct mnl_socket *nl[2];

// stores zone(integer value) at index, which is mapped to if_nametoindex() (value returned from get_in/outdev)
// memset will be performed in Cython prior to changing the values.
uintf16_t INTF_ZONE_MAP[FW_MAX_ZONES]; // = <uintf16_t*>calloc(FW_MAX_ZONE_COUNT, sizeof(uintf16_t))
