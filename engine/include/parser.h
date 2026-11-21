#ifndef PARSER_H
#define PARSER_H

#include <stdatomic.h>
#include <stdint.h>
#include "errors.h"
#include "pktring.h"
#include "proto.h"
#include "scheduler.h"

#define LINK_EN10MB 1
#define LINK_SLL2   276

typedef struct prs_counters {
    _Atomic uint64_t parsed;
    _Atomic uint64_t malformed;
    _Atomic uint64_t app_bad;
    _Atomic uint64_t other;
    _Atomic uint64_t frag;
    _Atomic uint64_t events;
    _Atomic uint64_t per_proto[PROTO_COUNT];
} prs_counters_mt;

typedef struct prs_stats {
    uint64_t parsed, malformed, app_bad, other, frag, events;
    uint64_t per_proto[PROTO_COUNT];
} prs_stats_mt;

typedef struct parser {
    int          linktype;
    int          dump;
    pkt_info_mt  info;
    event_mt     ev;
    atomic_int   done;
    prs_counters_mt counters;
} parser_mt;

typedef struct parser_thread_args {
    parser_mt            *prs;
    pkt_pool_mt          *pool;
    pkt_ring_mt          *ready;
    scheduler_startup_mt *startup;
    uint64_t runtime_ns, deadline_ns, period_ns;
    uint32_t batch;
    error_info_mt         einf;
} parser_thread_args_mt;

void parser_init(parser_mt *prs, int linktype, int dump);
parse_rc_mt parse_packet(parser_mt *prs, const pkt_slot_mt *slot);
void parser_account(parser_mt *prs, parse_rc_mt rc);
void parser_snapshot(parser_mt *prs, prs_stats_mt *s);
void *parser_thread(void *arg);

#endif
