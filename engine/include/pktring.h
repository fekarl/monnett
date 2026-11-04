#ifndef PKTRING_H
#define PKTRING_H

#include "errors.h"
#include <pthread.h>
#include <stdint.h>

#define SLOT_DATA 2048

struct pkt_slot {
    uint64_t ts_ns;
    uint32_t caplen;
    uint32_t wirelen;
    uint64_t seq;
    uint8_t data[SLOT_DATA];
};

struct pkt_ring {
    struct pkt_slot **buf;
    uint32_t cap, head, tail, count;
    int closed;
    pthread_mutex_t m;
    pthread_cond_t not_empty, not_full;
};

struct pkt_pool {
    struct pkt_slot *slots;
    uint32_t nslots;
    struct pkt_ring free;
};

enum error_code pool_init(struct pkt_pool *p, uint32_t nslots,
                          struct error_info *e);
struct pkt_slot *pool_get(struct pkt_pool *p, int wait);
void pool_put(struct pkt_pool *p, struct pkt_slot *s);
void pool_destroy(struct pkt_pool *p);

#endif
