#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>

static int check_failures;
static int check_total;

#define CHECK(cond, name)                                                     \
    do {                                                                      \
        check_total++;                                                        \
        if (cond) {                                                           \
            printf("PASS  %s\n", name);                                       \
        } else {                                                              \
            printf("FAIL  %s  (%s:%d)\n", name, __FILE__, __LINE__);          \
            check_failures++;                                                 \
        }                                                                     \
    } while (0)

static int check_done(const char *suite)
{
    printf("%s: %d/%d passed\n", suite, check_total - check_failures,
           check_total);
    return check_failures != 0;
}

#endif
