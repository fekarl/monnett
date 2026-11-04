#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "errors.h"
#include <pthread.h>
#include <stdint.h>

struct scheduler_startup {
    pthread_mutex_t m;
    pthread_cond_t cv;
    int expected;
    int ready;
    int failed;
    struct error_info first_err;
};

void scheduler_startup_init(struct scheduler_startup *s, int nthreads);
void scheduler_startup_destroy(struct scheduler_startup *s);

enum error_code scheduler_set_deadline(uint64_t runtime_ns,
                                       uint64_t deadline_ns, uint64_t period_ns,
                                       struct error_info *e);

enum error_code scheduler_drop_caps(struct error_info *e);

void scheduler_report(struct scheduler_startup *s, const struct error_info *e);

enum error_code scheduler_wait_all(struct scheduler_startup *s, int timeout_ms,
                                   struct error_info *e);

#endif
