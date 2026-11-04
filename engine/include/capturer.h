#ifndef CAPTURER_H
#define CAPTURER_H

#include "config.h"
#include "errors.h"
#include "pktring.h"
#include "scheduler.h"
#include <pcap/pcap.h>
#include <stdatomic.h>
#include <stdint.h>

struct cap_counters {
    _Atomic uint64_t captured;
    _Atomic uint64_t bytes;
    _Atomic uint64_t engine_drop;
    _Atomic uint64_t truncated;
    _Atomic uint64_t k_recv;
    _Atomic uint64_t k_drop;
    _Atomic uint64_t k_ifdrop;
};

struct capture {
    pcap_t *p;
    int is_file;
    int linktype;
    atomic_int running;
    atomic_int done;
    struct pcap_stat last;
    struct cap_counters cnt;
    char err[PCAP_ERRBUF_SIZE];
};

struct cap_stats {
    uint64_t captured, bytes, engine_drop, truncated, k_recv, k_drop, k_ifdrop;
};

enum error_code cap_open(struct capture *c, const struct engine_config *cfg,
                         struct error_info *e);
const char *cap_error(const struct capture *c);

int cap_next(struct capture *c, struct pkt_slot *out);
void cap_poll_kernel_stats(struct capture *c);
void cap_snapshot(struct capture *c, struct cap_stats *s);
void cap_stop(struct capture *c);
void cap_close(struct capture *c);

struct capture_thread_args {
    struct capture *cap;
    struct pkt_pool *pool;
    struct scheduler_startup *startup;
    uint64_t runtime_ns, deadline_ns, period_ns;
    struct error_info err;
};

void *capture_thread(void *arg);

#endif
