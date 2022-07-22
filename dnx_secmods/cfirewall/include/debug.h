#ifndef DEBUG_H
#define DEBUG_H

#define DEVELOPMENT 1

// trailing underscore to reduce chance of conflicting name defined elsewhere.
#define debug_(...) do { if (DEVELOPMENT) debug__(__VA_ARGS__); } while (0)

extern void debug__(int on, char* fmt, ...);

void
debug__(int on, char* fmt, ...)
{
    va_list     args;

    if (on) {
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

#endif