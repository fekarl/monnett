#ifndef CAPTURER_H
#define CAPTURER_H

#include <pcap/pcap.h>
#include <stdatomic.h>
#include <stdint.h>
#include "config.h"
#include "errors.h"
#include "pktring.h"
#include "scheduler.h"

typedef struct cap_counters {
    _Atomic uint64_t captured;
    _Atomic uint64_t bytes;
    _Atomic uint64_t engine_drop;
    _Atomic uint64_t truncated;
    _Atomic uint64_t k_recv;
    _Atomic uint64_t k_drop;
    _Atomic uint64_t k_ifdrop;
} cap_counters_mt;

typedef struct capture {
    pcap_t     *pcap;
    int         is_file;
    int         linktype;
    int         ts_nano;
    atomic_int  running;
    atomic_int  done;
    struct pcap_stat last_kstats;
    cap_counters_mt counters;
    char        errbuf[PCAP_ERRBUF_SIZE];
} capture_mt;

typedef struct cap_stats {
    uint64_t captured, bytes, engine_drop, truncated, k_recv, k_drop, k_ifdrop;
} cap_stats_mt;

error_code_mt cap_open(capture_mt *cap, const engine_config_mt *cfg,
                       error_info_mt *einf);
const char *cap_error(const capture_mt *cap);

int  cap_next(capture_mt *cap, pkt_slot_mt *slot);
void cap_poll_kernel_stats(capture_mt *cap);
void cap_snapshot(capture_mt *cap, cap_stats_mt *s);
void cap_stop(capture_mt *cap);
void cap_close(capture_mt *cap);

typedef struct capture_thread_args {
    capture_mt           *cap;
    pkt_pool_mt          *pool;
    scheduler_startup_mt *startup;
    uint64_t runtime_ns, deadline_ns, period_ns;
    error_info_mt         einf;
} capture_thread_args_mt;

void *capture_thread(void *arg);

#endif
