#include <stdint.h>


void nullset(void **data, uint_fast16_t dlen)
{
    uint_fast16_t   i;

    for (i = 0; i < dlen; i++) {
        data[i] = NULL;
    }
}