#ifndef COMMON_H_
#define COMMON_H_

// needed for ucred struct
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <sys/un.h> // sockaddr_un
#include <sys/uio.h>
#include <pwd.h>

#include "netinet/in.h"
#include "pthread.h"

// function return values
#define OK   0
#define ERR -1
#define Py_OK  0
#define Py_ERR 1

// bitwise helpers
#define TWO_BITS       2
#define FOUR_BITS      4
#define ONE_BYTE       8
#define TWELVE_BITS   12
#define TWO_BYTES     16
#define THREE_BYTES   24

#define TWO_BIT_MASK   3
#define FOUR_BIT_MASK 15

typedef uint_fast8_t    uintf8_t;
typedef uint_fast16_t   uintf16_t;
typedef uint_fast32_t   uintf32_t;

typedef int_fast8_t    intf8_t;
typedef int_fast16_t   intf16_t;
typedef int_fast32_t   intf32_t;

#endif
