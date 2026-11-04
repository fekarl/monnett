#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "errors.h"

static const char *const error_names[] = {
    [ERR_OK] = "ok",
    [ERR_ARGS] = "arguments",
    [ERR_CONFIG] = "config",
    [ERR_CONFIG_PERMS] = "config permissions",
    [ERR_OPEN] = "open",
    [ERR_FILTER] = "filter",
    [ERR_LINKTYPE] = "link type",
    [ERR_NOMEM] = "out of memory",
    [ERR_SCHED_PERM] = "SCHED_DEADLINE not permitted",
    [ERR_SCHED_BUSY] = "SCHED_DEADLINE busy",
    [ERR_CAPS] = "capabilities",
    [ERR_THREAD] = "thread",
    [ERR_CAPTURE] = "capture",
};

#define N_ERROR_NAMES (sizeof error_names / sizeof error_names[0])

#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

enum error_code error_fail(struct error_info *e, enum error_code code,
                           const char *what, const char *why) {
    int saved_errno = errno;

    e->code = code;
    e->sys_errno = saved_errno;

    if (what && why)
        snprintf(e->msg, sizeof e->msg, "%s: %s", what, why);
    else if (what)
        snprintf(e->msg, sizeof e->msg, "%s", what);
    else
        e->msg[0] = '\0';

    errno = saved_errno;
    return code;
}

const char *error_str(enum error_code code) {
    if ((unsigned)code >= N_ERROR_NAMES || error_names[code] == NULL)
        return "unknown error";
    return error_names[code];
}

void error_print(const struct error_info *e) {
    int color = isatty(STDERR_FILENO);
    const char *on = color ? COLOR_RED : "";
    const char *off = color ? COLOR_RESET : "";

    if (e->msg[0] != '\0')
        fprintf(stderr, "%smonnett: %s: %s%s\n", on, error_str(e->code), e->msg,
                off);
    else
        fprintf(stderr, "%smonnett: %s%s\n", on, error_str(e->code), off);
}
