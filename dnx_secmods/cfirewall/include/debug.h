#ifndef DEBUG_H
#define DEBUG_H

//LABEL: DEVELOPMENT_ONLY_CODE
#define DEVELOPMENT 1

#define dprint(on, fmt, ...) do { if (DEVELOPMENT && on) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

/* ====================================
   DNXFIREWALL ASSERT IMPLEMENTATION
==================================== */
#define FILENUM(num) enum { F_NUM=num }; void _registerf##num(void) {}

// level 1 assert (always on for dev branch).
#if DEVELOPMENT
#define assert_a(expr) ((expr) || dnxFailed(1, expr, F_NUM, __LINE__))
#else
#define assert_a(ignore) ((void)0)
#endif

// level 2 assert (off by default, need to recompile with DDEBUG defined).
#ifdef DDEBUG
#define assert_d(expr) ((expr) || dnxFailed(2, expr, F_NUM, __LINE__))
#else
#define assert_d(ignore) ((void)0)
#endif

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
#endif
