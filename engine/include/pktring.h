#ifndef PKTRING_H
#define PKTRING_H

#include "errors.h"
#include <pthread.h>
#include <stdint.h>

#define SLOT_DATA 2048
#define POOL_WAIT_MS 100

typedef struct pkt_slot {
    uint64_t ts_ns;
    uint32_t caplen;
    uint32_t wirelen;
    uint64_t seq;
    uint8_t data[SLOT_DATA];
} pkt_slot_mt;

typedef struct pkt_ring {
    pkt_slot_mt **buf;
    uint32_t cap, head, tail, count;
    int closed;
    pthread_mutex_t m;
    pthread_cond_t not_empty, not_full;
} pkt_ring_mt;

typedef struct pkt_pool {
    pkt_slot_mt *slots;
    uint32_t nslots;
    pkt_ring_mt free;
} pkt_pool_mt;

error_code_mt pool_init(pkt_pool_mt *p, uint32_t nslots, error_info_mt *e);
pkt_slot_mt *pool_get(pkt_pool_mt *p, int wait);
void pool_put(pkt_pool_mt *p, pkt_slot_mt *s);
void pool_destroy(pkt_pool_mt *p);

#endif
