#ifndef DEBUG_H
#define DEBUG_H

#define DEVELOPMENT 0

// trailing underscore to reduce chance of conflicting name defined elsewhere.
#define dprint(on, fmt, ...) do { if (DEVELOPMENT && on) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

#endif