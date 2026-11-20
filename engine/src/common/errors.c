#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "errors.h"

static const char *const error_names[] = {
    [ERR_OK]           = "ok",
    [ERR_ARGS]         = "arguments",
    [ERR_CONFIG]       = "config",
    [ERR_CONFIG_PERMS] = "config permissions",
    [ERR_OPEN]         = "open",
    [ERR_FILTER]       = "filter",
    [ERR_LINKTYPE]     = "link type",
    [ERR_NOMEM]        = "out of memory",
    [ERR_SCHED_PERM]   = "SCHED_DEADLINE not permitted",
    [ERR_SCHED_BUSY]   = "SCHED_DEADLINE busy",
    [ERR_CAPS]         = "capabilities",
    [ERR_THREAD]       = "thread",
    [ERR_CAPTURE]      = "capture",
};

#define N_ERROR_NAMES (sizeof error_names / sizeof error_names[0])

#define COLOR_RED   "\033[1;31m"
#define COLOR_RESET "\033[0m"

error_code_mt error_fail(error_info_mt *einf, error_code_mt code,
                         const char *what, const char *why)
{
    int saved_errno = errno;

    einf->code = code;
    einf->sys_errno = saved_errno;

    if (what && why)
        snprintf(einf->msg, sizeof einf->msg, "%s: %s", what, why);
    else if (what)
        snprintf(einf->msg, sizeof einf->msg, "%s", what);
    else
        einf->msg[0] = '\0';

    errno = saved_errno;
    return code;
}

const char *error_str(error_code_mt code)
{
    if ((unsigned)code >= N_ERROR_NAMES || error_names[code] == NULL)
        return "unknown error";
    return error_names[code];
}

void error_print(const error_info_mt *einf)
{
    int color = isatty(STDERR_FILENO);
    const char *on  = color ? COLOR_RED : "";
    const char *off = color ? COLOR_RESET : "";

    if (einf->msg[0] != '\0')
        fprintf(stderr, "%smonnett: %s: %s%s\n", on, error_str(einf->code),
                einf->msg, off);
    else
        fprintf(stderr, "%smonnett: %s%s\n", on, error_str(einf->code), off);
}
