#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "errors.h"
#include <pthread.h>
#include <stdint.h>

typedef struct scheduler_startup {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int expected;
    int ready;
    int failed;
    error_info_mt first_einf;
} scheduler_startup_mt;

void scheduler_startup_init(scheduler_startup_mt *startup, int nthreads);
void scheduler_startup_destroy(scheduler_startup_mt *startup);

error_code_mt scheduler_set_deadline(uint64_t runtime_ns, uint64_t deadline_ns,
                                     uint64_t period_ns, error_info_mt *einf);

error_code_mt scheduler_drop_caps(error_info_mt *einf);

void scheduler_report(scheduler_startup_mt *startup, const error_info_mt *einf);

error_code_mt scheduler_wait_all(scheduler_startup_mt *startup, int timeout_ms,
                                 error_info_mt *einf);

#endif
