#include "config.h"
#include "cfirewall.h"

FILENUM(1);

// geolocation vars
uint32_t MSB, LSB;
int HTR_IDX;

// cli args
bool VERBOSE;
bool VERBOSE2;

bool FW_V;
bool NAT_V;

struct mnl_socket *nl[2];

// stores zone(integer value) at index, which is mapped to if_nametoindex() (value returned from get_in/outdev)
// memset will be performed in Cython prior to changing the values.
ZoneMap INTF_ZONE_MAP[FW_MAX_ZONES]; // = <uintf16_t*>calloc(FW_MAX_ZONE_COUNT, sizeof(uintf16_t))

// the packet id tracks revolving 1-255, which will be used tracked with connmark through nat process
//uint8_t dnx_pkt_id = 0;
//struct dnx_pktb dnx_pkt_tracker[UINT8_MAX];


void dnxFailed(int level, char* expr, int file, int lineno)
{
    if (level >= 1) {
        fprintf(stderr, "Assertion failure. expr->%s, file->%d, line->%d\n", expr, file, lineno);
        fflush(stderr); // shouldn't this be line buffered?
    }

    if (level >= 2) {
        abort();
    }
}
