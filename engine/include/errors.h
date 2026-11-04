#ifndef ERRORS_H
#define ERRORS_H

enum error_code {
    ERR_OK = 0,
    ERR_ARGS = 1,
    ERR_CONFIG = 2,
    ERR_CONFIG_PERMS = 3,
    ERR_OPEN = 4,
    ERR_FILTER = 5,
    ERR_LINKTYPE = 6,
    ERR_NOMEM = 7,
    ERR_SCHED_PERM = 8,
    ERR_SCHED_BUSY = 9,
    ERR_CAPS = 10,
    ERR_THREAD = 11,
    ERR_CAPTURE = 12,
};

#define ERR_MSG_MAX 256

struct error_info {
    enum error_code code;
    int sys_errno;
    char msg[ERR_MSG_MAX];
};

enum error_code error_fail(struct error_info *e, enum error_code code,
                           const char *what, const char *why);

const char *error_str(enum error_code code);

void error_print(const struct error_info *e);

#endif
