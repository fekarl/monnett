#include <stdio.h>
#include <string.h>
#include <time.h>

#include "capturer.h"
#include "errors.h"
#include "pktring.h"
#include "scheduler.h"

#define STATS_PERIOD_MS 1000

static error_code_mt open_fail(capture_mt *c, error_info_mt *e,
                               error_code_mt code, const char *what) {
    error_fail(e, code, what, c->err);
    if (c->p != NULL) {
        pcap_close(c->p);
        c->p = NULL;
    }
    return code;
}

static error_code_mt open_live(capture_mt *c, const engine_config_mt *cfg,
                               error_info_mt *e) {
    c->p = pcap_create(cfg->source, c->err);
    if (c->p == NULL)
        return open_fail(c, e, ERR_OPEN, cfg->source);

    pcap_set_snaplen(c->p, SLOT_DATA);
    pcap_set_promisc(c->p, cfg->promisc);
    pcap_set_timeout(c->p, cfg->timeout_ms);
    pcap_set_buffer_size(c->p, cfg->buffer_mb << 20);
    pcap_set_tstamp_precision(c->p, PCAP_TSTAMP_PRECISION_NANO);

    int rc = pcap_activate(c->p);
    if (rc < 0) {
        const char *why = pcap_geterr(c->p);
        snprintf(c->err, sizeof c->err, "%s",
                 why[0] != '\0' ? why : pcap_statustostr(rc));
        return open_fail(c, e, ERR_OPEN, cfg->source);
    }
    if (rc > 0)
        fprintf(stderr, "monnett: warning: %s: %s\n", cfg->source,
                pcap_statustostr(rc));
    if (strcmp(cfg->source, "any") == 0)
        pcap_set_datalink(c->p, DLT_LINUX_SLL2);
    return ERR_OK;
}

static error_code_mt open_file(capture_mt *c, const engine_config_mt *cfg,
                               error_info_mt *e) {
    c->p = pcap_open_offline_with_tstamp_precision(
        cfg->source, PCAP_TSTAMP_PRECISION_NANO, c->err);
    if (c->p == NULL)
        return open_fail(c, e, ERR_OPEN, cfg->source);
    return ERR_OK;
}

static error_code_mt check_linktype(capture_mt *c, error_info_mt *e) {
    c->linktype = pcap_datalink(c->p);
    if (c->linktype == DLT_EN10MB || c->linktype == DLT_LINUX_SLL2)
        return ERR_OK;

    const char *name = pcap_datalink_val_to_name(c->linktype);
    snprintf(c->err, sizeof c->err, "unsupported link type %d (%s)",
             c->linktype, name ? name : "unknown");
    return open_fail(c, e, ERR_LINKTYPE, "link type");
}

static error_code_mt set_filter(capture_mt *c, const char *expr,
                                error_info_mt *e) {
    struct bpf_program fp;

    if (pcap_compile(c->p, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        snprintf(c->err, sizeof c->err, "%s", pcap_geterr(c->p));
        return open_fail(c, e, ERR_FILTER, expr);
    }
    int rc = pcap_setfilter(c->p, &fp);
    pcap_freecode(&fp);
    if (rc < 0) {
        snprintf(c->err, sizeof c->err, "%s", pcap_geterr(c->p));
        return open_fail(c, e, ERR_FILTER, expr);
    }
    return ERR_OK;
}

error_code_mt cap_open(capture_mt *c, const engine_config_mt *cfg,
                       error_info_mt *e) {
    error_code_mt rc;

    memset(c, 0, sizeof *c);
    c->is_file = cfg->is_file;

    rc = c->is_file ? open_file(c, cfg, e) : open_live(c, cfg, e);
    if (rc != ERR_OK)
        return rc;
    rc = check_linktype(c, e);
    if (rc != ERR_OK)
        return rc;
    if (cfg->filter[0] != '\0') {
        rc = set_filter(c, cfg->filter, e);
        if (rc != ERR_OK)
            return rc;
    }

    c->ts_nano = pcap_get_tstamp_precision(c->p) == PCAP_TSTAMP_PRECISION_NANO;
    atomic_store(&c->running, 1);
    return ERR_OK;
}

const char *cap_error(const capture_mt *c) { return c->err; }

int cap_next(capture_mt *c, pkt_slot_mt *out) {
    struct pcap_pkthdr *h;
    const u_char *data;

    if (!atomic_load(&c->running))
        return -2;

    int rc = pcap_next_ex(c->p, &h, &data);
    if (rc == PCAP_ERROR) {
        snprintf(c->err, sizeof c->err, "%s", pcap_geterr(c->p));
        return -1;
    }
    if (rc != 1)
        return rc == 0 ? 0 : -2;

    uint64_t seq = atomic_fetch_add(&c->cnt.captured, 1);
    atomic_fetch_add(&c->cnt.bytes, h->len);
    if (h->caplen < h->len)
        atomic_fetch_add(&c->cnt.truncated, 1);

    if (out == NULL) {
        atomic_fetch_add(&c->cnt.engine_drop, 1);
        return 1;
    }

    uint32_t n = h->caplen < SLOT_DATA ? h->caplen : SLOT_DATA;
    uint64_t frac = (uint64_t)h->ts.tv_usec;

    memcpy(out->data, data, n);
    out->caplen = n;
    out->wirelen = h->len;
    out->ts_ns = (uint64_t)h->ts.tv_sec * 1000000000ull +
                 (c->ts_nano ? frac : frac * 1000ull);
    out->seq = seq;
    return 1;
}

void cap_poll_kernel_stats(capture_mt *c) {
    struct pcap_stat st;

    if (c->is_file || c->p == NULL || pcap_stats(c->p, &st) < 0)
        return;
    atomic_fetch_add(&c->cnt.k_recv, (uint32_t)(st.ps_recv - c->last.ps_recv));
    atomic_fetch_add(&c->cnt.k_drop, (uint32_t)(st.ps_drop - c->last.ps_drop));
    atomic_fetch_add(&c->cnt.k_ifdrop,
                     (uint32_t)(st.ps_ifdrop - c->last.ps_ifdrop));
    c->last = st;
}

void cap_snapshot(capture_mt *c, cap_stats_mt *s) {
    s->captured = atomic_load(&c->cnt.captured);
    s->bytes = atomic_load(&c->cnt.bytes);
    s->engine_drop = atomic_load(&c->cnt.engine_drop);
    s->truncated = atomic_load(&c->cnt.truncated);
    s->k_recv = atomic_load(&c->cnt.k_recv);
    s->k_drop = atomic_load(&c->cnt.k_drop);
    s->k_ifdrop = atomic_load(&c->cnt.k_ifdrop);
}

void cap_stop(capture_mt *c) {
    atomic_store(&c->running, 0);
    if (c->p != NULL)
        pcap_breakloop(c->p);
}

void cap_close(capture_mt *c) {
    if (c->p != NULL)
        pcap_close(c->p);
    c->p = NULL;
}

static uint64_t mono_ms(void) {
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void capture_loop(capture_thread_args_mt *a) {
    capture_mt *c = a->cap;
    uint64_t next_stats = mono_ms() + STATS_PERIOD_MS;

    while (atomic_load(&c->running)) {
        pkt_slot_mt *s = pool_get(a->pool, c->is_file);
        if (s == NULL && c->is_file)
            continue;

        int rc = cap_next(c, s);
        if (s != NULL)
            pool_put(a->pool, s);

        if (rc == -1) {
            error_fail(&a->err, ERR_CAPTURE, "pcap_next_ex", cap_error(c));
            break;
        }
        if (rc == -2)
            break;

        if (mono_ms() >= next_stats) {
            cap_poll_kernel_stats(c);
            next_stats = mono_ms() + STATS_PERIOD_MS;
        }
    }
}

void *capture_thread(void *arg) {
    capture_thread_args_mt *a = arg;
    capture_mt *c = a->cap;

    if (scheduler_set_deadline(a->runtime_ns, a->deadline_ns, a->period_ns,
                               &a->err) != ERR_OK ||
        scheduler_drop_caps(&a->err) != ERR_OK) {
        scheduler_report(a->startup, &a->err);
        atomic_store(&c->done, 1);
        return NULL;
    }
    scheduler_report(a->startup, NULL);

    capture_loop(a);

    cap_poll_kernel_stats(c);
    atomic_store(&c->done, 1);
    return NULL;
}
