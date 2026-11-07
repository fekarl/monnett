#ifndef ERRORS_H
#define ERRORS_H

typedef enum error_code {
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
} error_code_mt;

#define ERR_MSG_MAX 256

typedef struct error_info {
    error_code_mt code;
    int sys_errno;
    char msg[ERR_MSG_MAX];
} error_info_mt;

error_code_mt error_fail(error_info_mt *e, error_code_mt code, const char *what,
                         const char *why);

const char *error_str(error_code_mt code);

void error_print(const error_info_mt *e);

#endif
