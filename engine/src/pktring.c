#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "errors.h"
#include "pktring.h"

static int ring_init(struct pkt_ring *r, uint32_t cap) {
    pthread_condattr_t attr;

    memset(r, 0, sizeof *r);
    r->buf = calloc(cap, sizeof *r->buf);
    if (r->buf == NULL)
        return ENOMEM;
    r->cap = cap;

    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_mutex_init(&r->m, NULL);
    pthread_cond_init(&r->not_empty, &attr);
    pthread_cond_init(&r->not_full, &attr);
    pthread_condattr_destroy(&attr);
    return 0;
}

static void ring_destroy(struct pkt_ring *r) {
    pthread_cond_destroy(&r->not_full);
    pthread_cond_destroy(&r->not_empty);
    pthread_mutex_destroy(&r->m);
    free(r->buf);
    r->buf = NULL;
}

static int ring_push(struct pkt_ring *r, struct pkt_slot *s) {
    int rc = -1;

    pthread_mutex_lock(&r->m);
    if (r->count < r->cap) {
        r->buf[r->tail] = s;
        r->tail = (r->tail + 1) % r->cap;
        r->count++;
        pthread_cond_signal(&r->not_empty);
        rc = 0;
    }
    pthread_mutex_unlock(&r->m);
    return rc;
}

static void deadline_after(struct timespec *ts, int ms) {
    clock_gettime(CLOCK_MONOTONIC, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

static struct pkt_slot *ring_pop(struct pkt_ring *r, int timeout_ms) {
    struct pkt_slot *s = NULL;
    struct timespec until;

    if (timeout_ms > 0)
        deadline_after(&until, timeout_ms);

    pthread_mutex_lock(&r->m);
    while (r->count == 0 && timeout_ms > 0)
        if (pthread_cond_timedwait(&r->not_empty, &r->m, &until) == ETIMEDOUT)
            break;
    if (r->count > 0) {
        s = r->buf[r->head];
        r->head = (r->head + 1) % r->cap;
        r->count--;
        pthread_cond_signal(&r->not_full);
    }
    pthread_mutex_unlock(&r->m);
    return s;
}

enum error_code pool_init(struct pkt_pool *p, uint32_t nslots,
                          struct error_info *e) {
    memset(p, 0, sizeof *p);
    if (nslots == 0)
        return error_fail(e, ERR_NOMEM, "pool_init", "zero slots");

    p->slots = calloc(nslots, sizeof *p->slots);
    if (p->slots == NULL)
        return error_fail(e, ERR_NOMEM, "pool_init", strerror(errno));
    memset(p->slots, 0, (size_t)nslots * sizeof *p->slots);
    p->nslots = nslots;

    int rc = ring_init(&p->free, nslots);
    if (rc != 0) {
        free(p->slots);
        p->slots = NULL;
        return error_fail(e, ERR_NOMEM, "pool_init", strerror(rc));
    }

    for (uint32_t i = 0; i < nslots; i++)
        ring_push(&p->free, &p->slots[i]);
    return ERR_OK;
}

struct pkt_slot *pool_get(struct pkt_pool *p, int wait) {
    return ring_pop(&p->free, wait ? POOL_WAIT_MS : 0);
}

void pool_put(struct pkt_pool *p, struct pkt_slot *s) {
    if (s == NULL)
        return;
    ring_push(&p->free, s);
}

void pool_destroy(struct pkt_pool *p) {
    if (p->slots == NULL)
        return;
    ring_destroy(&p->free);
    free(p->slots);
    p->slots = NULL;
    p->nslots = 0;
}
