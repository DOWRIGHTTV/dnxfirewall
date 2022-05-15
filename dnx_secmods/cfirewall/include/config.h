#ifndef COMMON_H_
#define COMMON_H_

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "netinet/in.h"
#include "pthread.h"

// function return values
#define OK   0
#define ERR -1
#define Py_OK  0
#define Py_ERR 1

// cli args
extern bool PROXY_BYPASS;
extern bool VERBOSE;
extern bool VERBOSE2;

extern bool FW_V;
extern bool NAT_V;

typedef uint_fast8_t    uintf8_t;
typedef uint_fast16_t   uintf16_t;
typedef uint_fast32_t   uintf32_t;

typedef int_fast8_t    intf8_t;
typedef int_fast16_t   intf16_t;
typedef int_fast32_t   intf32_t;

#endif
