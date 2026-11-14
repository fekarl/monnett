#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "errors.h"
#include "pktring.h"

static int ring_init(pkt_ring_mt *r, uint32_t capacity)
{
    pthread_condattr_t attr;

    memset(r, 0, sizeof *r);
    r->items = calloc(capacity, sizeof *r->items);
    if (r->items == NULL)
        return ENOMEM;
    r->capacity = capacity;

    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_mutex_init(&r->lock, NULL);
    pthread_cond_init(&r->not_empty, &attr);
    pthread_cond_init(&r->not_full, &attr);
    pthread_condattr_destroy(&attr);
    return 0;
}

static void ring_destroy(pkt_ring_mt *r)
{
    pthread_cond_destroy(&r->not_full);
    pthread_cond_destroy(&r->not_empty);
    pthread_mutex_destroy(&r->lock);
    free(r->items);
    r->items = NULL;
}

static int ring_push(pkt_ring_mt *r, pkt_slot_mt *s)
{
    int rc = -1;

    pthread_mutex_lock(&r->lock);
    if (r->count < r->capacity) {
        r->items[r->tail] = s;
        r->tail = (r->tail + 1) % r->capacity;
        r->count++;
        pthread_cond_signal(&r->not_empty);
        rc = 0;
    }
    pthread_mutex_unlock(&r->lock);
    return rc;
}

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

static pkt_slot_mt *ring_pop(pkt_ring_mt *r, int timeout_ms)
{
    pkt_slot_mt *s = NULL;
    struct timespec until;

    if (timeout_ms > 0)
        deadline_after(&until, timeout_ms);

    pthread_mutex_lock(&r->lock);
    while (r->count == 0 && timeout_ms > 0)
        if (pthread_cond_timedwait(&r->not_empty, &r->lock, &until) ==
            ETIMEDOUT)
            break;
    if (r->count > 0) {
        s = r->items[r->head];
        r->head = (r->head + 1) % r->capacity;
        r->count--;
        pthread_cond_signal(&r->not_full);
    }
    pthread_mutex_unlock(&r->lock);
    return s;
}

error_code_mt pool_init(pkt_pool_mt *pool, uint32_t nslots,
                        error_info_mt *einf)
{
    memset(pool, 0, sizeof *pool);
    if (nslots == 0)
        return error_fail(einf, ERR_NOMEM, "pool_init", "zero slots");

    pool->slots = calloc(nslots, sizeof *pool->slots);
    if (pool->slots == NULL)
        return error_fail(einf, ERR_NOMEM, "pool_init", strerror(errno));
    memset(pool->slots, 0, (size_t)nslots * sizeof *pool->slots);
    pool->nslots = nslots;

    int rc = ring_init(&pool->free, nslots);
    if (rc != 0) {
        free(pool->slots);
        pool->slots = NULL;
        return error_fail(einf, ERR_NOMEM, "pool_init", strerror(rc));
    }

    for (uint32_t i = 0; i < nslots; i++)
        ring_push(&pool->free, &pool->slots[i]);
    return ERR_OK;
}

pkt_slot_mt *pool_get(pkt_pool_mt *pool, int wait)
{
    return ring_pop(&pool->free, wait ? POOL_WAIT_MS : 0);
}

void pool_put(pkt_pool_mt *pool, pkt_slot_mt *slot)
{
    if (slot == NULL)
        return;
    ring_push(&pool->free, slot);
}

void pool_destroy(pkt_pool_mt *pool)
{
    if (pool->slots == NULL)
        return;
    ring_destroy(&pool->free);
    free(pool->slots);
    pool->slots = NULL;
    pool->nslots = 0;
}
