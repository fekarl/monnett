#ifndef PKTRING_H
#define PKTRING_H

#include <pthread.h>
#include <stdint.h>
#include "errors.h"

#define SLOT_DATA    2048
#define POOL_WAIT_MS 100

typedef struct pkt_slot {
    uint64_t ts_ns;
    uint32_t caplen;
    uint32_t wirelen;
    uint64_t seq;
    uint8_t  data[SLOT_DATA];
} pkt_slot_mt;

typedef struct pkt_ring {
    pkt_slot_mt **items;
    uint32_t capacity, head, tail, count;
    int closed;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty, not_full;
} pkt_ring_mt;

typedef struct pkt_pool {
    pkt_slot_mt *slots;
    uint32_t nslots;
    pkt_ring_mt free;
} pkt_pool_mt;

int  ring_init(pkt_ring_mt *r, uint32_t capacity);
void ring_destroy(pkt_ring_mt *r);
int  ring_push(pkt_ring_mt *r, pkt_slot_mt *s);
pkt_slot_mt *ring_pop(pkt_ring_mt *r, int timeout_ms);
void ring_close(pkt_ring_mt *r);
int  ring_is_done(pkt_ring_mt *r);

error_code_mt pool_init(pkt_pool_mt *pool, uint32_t nslots,
                        error_info_mt *einf);
pkt_slot_mt *pool_get(pkt_pool_mt *pool, int wait);
void pool_put(pkt_pool_mt *pool, pkt_slot_mt *slot);
void pool_destroy(pkt_pool_mt *pool);

#endif
