#include <errno.h>
#include <string.h>

#include "check.h"
#include "errors.h"

int main(void)
{
    error_info_mt einf;

    memset(&einf, 0, sizeof einf);
    errno = ENODEV;
    error_code_mt r = error_fail(&einf, ERR_OPEN, "enp0s9", "No such device");
    CHECK(r == ERR_OPEN, "error_fail returns the code");
    CHECK(einf.code == ERR_OPEN, "code is stored");
    CHECK(einf.sys_errno == ENODEV, "errno is stored");
    CHECK(errno == ENODEV, "errno is not changed by error_fail");
    CHECK(strcmp(einf.msg, "enp0s9: No such device") == 0, "message is what: why");

    error_fail(&einf, ERR_CONFIG, "only what", NULL);
    CHECK(strcmp(einf.msg, "only what") == 0, "why == NULL");

    error_fail(&einf, ERR_FILTER, NULL, NULL);
    CHECK(einf.msg[0] == '\0', "what == NULL and why == NULL");

    char big[400];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    error_fail(&einf, ERR_CONFIG, big, "y");
    CHECK(strlen(einf.msg) == ERR_MSG_MAX - 1, "long message is cut to 255");

    CHECK(strcmp(error_str(ERR_OK), "ok") == 0, "error_str(ERR_OK)");
    CHECK(strcmp(error_str(ERR_FILTER), "filter") == 0, "error_str(ERR_FILTER)");
    CHECK(strcmp(error_str(ERR_CAPTURE), "capture") == 0,
          "error_str(ERR_CAPTURE)");
    CHECK(strcmp(error_str((error_code_mt)99), "unknown error") == 0,
          "error_str(99)");
    CHECK(strcmp(error_str((error_code_mt)-1), "unknown error") == 0,
          "error_str(-1)");

    CHECK(ERR_OK == 0 && ERR_ARGS == 1 && ERR_CONFIG == 2 &&
              ERR_CONFIG_PERMS == 3 && ERR_OPEN == 4 && ERR_FILTER == 5 &&
              ERR_LINKTYPE == 6 && ERR_NOMEM == 7 && ERR_SCHED_PERM == 8 &&
              ERR_SCHED_BUSY == 9 && ERR_CAPS == 10 && ERR_THREAD == 11 &&
              ERR_CAPTURE == 12,
          "exit code values are fixed");

    return check_done("test_errors");
}
