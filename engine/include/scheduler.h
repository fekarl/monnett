#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "errors.h"
#include <pthread.h>
#include <stdint.h>

typedef struct scheduler_startup {
    pthread_mutex_t m;
    pthread_cond_t cv;
    int expected;
    int ready;
    int failed;
    error_info_mt first_err;
} scheduler_startup_mt;

void scheduler_startup_init(scheduler_startup_mt *s, int nthreads);
void scheduler_startup_destroy(scheduler_startup_mt *s);

error_code_mt scheduler_set_deadline(uint64_t runtime_ns, uint64_t deadline_ns,
                                     uint64_t period_ns, error_info_mt *e);

error_code_mt scheduler_drop_caps(error_info_mt *e);

void scheduler_report(scheduler_startup_mt *s, const error_info_mt *e);

error_code_mt scheduler_wait_all(scheduler_startup_mt *s, int timeout_ms,
                                 error_info_mt *e);

#endif
