#include <pthread.h>
#include <string.h>
#include <time.h>

#include "check.h"
#include "errors.h"
#include "pktring.h"

#define NSLOTS  1024
#define THREADS 4
#define ROUNDS  20000
#define BATCH   64

static pkt_pool_mt pool;

static long elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) * 1000 + (b->tv_nsec - a->tv_nsec) / 1000000;
}

static void *worker(void *arg)
{
    pkt_slot_mt *held[BATCH];

    (void)arg;
    for (int r = 0; r < ROUNDS; r++) {
        int n = 0;
        while (n < BATCH) {
            pkt_slot_mt *s = pool_get(&pool, 1);
            if (s != NULL) {
                s->seq = (uint64_t)r;
                held[n++] = s;
            }
        }
        for (int i = 0; i < n; i++)
            pool_put(&pool, held[i]);
    }
    return NULL;
}

int main(void)
{
    error_info_mt einf;
    pkt_slot_mt *all[NSLOTS];
    struct timespec a, b;

    memset(&einf, 0, sizeof einf);
    CHECK(pool_init(&pool, 0, &einf) == ERR_NOMEM, "zero slots rejected");

    CHECK(pool_init(&pool, NSLOTS, &einf) == ERR_OK, "pool_init");

    int ok = 1;
    for (int i = 0; i < NSLOTS; i++) {
        all[i] = pool_get(&pool, 0);
        if (all[i] == NULL)
            ok = 0;
    }
    CHECK(ok, "all slots can be taken");

    int distinct = 1;
    for (int i = 0; i < NSLOTS && distinct; i++)
        for (int j = i + 1; j < NSLOTS; j++)
            if (all[i] == all[j]) {
                distinct = 0;
                break;
            }
    CHECK(distinct, "every slot is different");

    int inside = 1;
    for (int i = 0; i < NSLOTS; i++)
        if (all[i] < pool.slots || all[i] >= pool.slots + NSLOTS)
            inside = 0;
    CHECK(inside, "every slot is inside the pool array");

    CHECK(pool_get(&pool, 0) == NULL, "empty pool, no wait: NULL at once");

    clock_gettime(CLOCK_MONOTONIC, &a);
    pkt_slot_mt *x = pool_get(&pool, 1);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = elapsed_ms(&a, &b);
    CHECK(x == NULL && ms >= POOL_WAIT_MS - 5 && ms < POOL_WAIT_MS + 100,
          "empty pool, wait: NULL after about 100 ms");

    memset(all[0]->data, 0xab, SLOT_DATA);
    for (int i = 0; i < NSLOTS; i++)
        pool_put(&pool, all[i]);
    pool_put(&pool, NULL);

    pkt_slot_mt *first = pool_get(&pool, 0);
    CHECK(first == all[0], "FIFO: first returned is first given");
    pool_put(&pool, first);

    pthread_t t[THREADS];
    for (int i = 0; i < THREADS; i++)
        pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < THREADS; i++)
        pthread_join(t[i], NULL);

    int count = 0;
    while (pool_get(&pool, 0) != NULL)
        count++;
    CHECK(count == NSLOTS, "no slot lost after 4 threads x 1.28M get/put");

    pool_destroy(&pool);
    CHECK(pool.slots == NULL, "pool_destroy clears pointers");
    pool_destroy(&pool);
    CHECK(1, "second pool_destroy is harmless");

    return check_done("test_pktring");
}
