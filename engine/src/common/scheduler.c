#include <errno.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "errors.h"
#include "scheduler.h"

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

#define DEADLINE_TRIES    3
#define DEADLINE_RETRY_MS 10

typedef struct deadline_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
} deadline_attr_mt;

static void deadline_after(struct timespec *ts, int ms)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

static void sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (long)(ms % 1000) * 1000000L };

    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

void scheduler_startup_init(scheduler_startup_mt *startup, int nthreads)
{
    pthread_condattr_t attr;

    memset(startup, 0, sizeof *startup);
    startup->expected = nthreads;

    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_mutex_init(&startup->lock, NULL);
    pthread_cond_init(&startup->cond, &attr);
    pthread_condattr_destroy(&attr);
}

void scheduler_startup_destroy(scheduler_startup_mt *startup)
{
    pthread_cond_destroy(&startup->cond);
    pthread_mutex_destroy(&startup->lock);
}

error_code_mt scheduler_set_deadline(uint64_t runtime_ns, uint64_t deadline_ns,
                                     uint64_t period_ns, error_info_mt *einf)
{
    deadline_attr_mt attr;

    memset(&attr, 0, sizeof attr);
    attr.size = sizeof attr;
    attr.sched_policy = SCHED_DEADLINE;
    attr.sched_runtime = runtime_ns;
    attr.sched_deadline = deadline_ns;
    attr.sched_period = period_ns;

    for (int i = 0; i < DEADLINE_TRIES; i++) {
        if (syscall(SYS_sched_setattr, 0, &attr, 0) == 0)
            return ERR_OK;
        if (errno != EBUSY)
            return error_fail(einf, ERR_SCHED_PERM, "sched_setattr",
                              strerror(errno));
        sleep_ms(DEADLINE_RETRY_MS);
    }
    return error_fail(einf, ERR_SCHED_BUSY, "sched_setattr",
                      "not enough CPU bandwidth (EBUSY after 3 tries)");
}

error_code_mt scheduler_drop_caps(error_info_mt *einf)
{
    cap_t caps = cap_init();

    if (caps == NULL)
        return error_fail(einf, ERR_CAPS, "cap_init", strerror(errno));
    if (cap_set_proc(caps) != 0) {
        int err = errno;
        cap_free(caps);
        errno = err;
        return error_fail(einf, ERR_CAPS, "cap_set_proc", strerror(err));
    }
    cap_free(caps);
    return ERR_OK;
}

void scheduler_report(scheduler_startup_mt *startup, const error_info_mt *einf)
{
    pthread_mutex_lock(&startup->lock);
    if (einf != NULL && einf->code != ERR_OK) {
        if (!startup->failed) {
            startup->failed = 1;
            startup->first_einf = *einf;
        }
    } else {
        startup->ready++;
    }
    pthread_cond_broadcast(&startup->cond);
    pthread_mutex_unlock(&startup->lock);
}

error_code_mt scheduler_wait_all(scheduler_startup_mt *startup, int timeout_ms,
                                 error_info_mt *einf)
{
    struct timespec until;
    int timed_out = 0;

    deadline_after(&until, timeout_ms);

    pthread_mutex_lock(&startup->lock);
    while (!startup->failed && startup->ready < startup->expected && !timed_out)
        if (pthread_cond_timedwait(&startup->cond, &startup->lock, &until) ==
            ETIMEDOUT)
            timed_out = 1;

    error_code_mt rc = ERR_OK;
    if (startup->failed) {
        *einf = startup->first_einf;
        rc = einf->code;
    } else if (startup->ready < startup->expected) {
        rc = error_fail(einf, ERR_THREAD, "startup",
                        "threads did not report in time");
    }
    pthread_mutex_unlock(&startup->lock);
    return rc;
}
