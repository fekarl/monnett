#include <stdio.h>
#include <string.h>
#include <time.h>

#include "capturer.h"
#include "errors.h"
#include "pktring.h"
#include "scheduler.h"

#define STATS_PERIOD_MS 1000

static error_code_mt open_fail(capture_mt *cap, error_info_mt *einf,
                               error_code_mt code, const char *what)
{
    error_fail(einf, code, what, cap->errbuf);
    if (cap->pcap != NULL) {
        pcap_close(cap->pcap);
        cap->pcap = NULL;
    }
    return code;
}

static error_code_mt open_live(capture_mt *cap, const engine_config_mt *cfg,
                               error_info_mt *einf)
{
    cap->pcap = pcap_create(cfg->source, cap->errbuf);
    if (cap->pcap == NULL)
        return open_fail(cap, einf, ERR_OPEN, cfg->source);

    pcap_set_snaplen(cap->pcap, SLOT_DATA);
    pcap_set_promisc(cap->pcap, cfg->promisc);
    pcap_set_timeout(cap->pcap, cfg->timeout_ms);
    pcap_set_buffer_size(cap->pcap, cfg->buffer_mb << 20);
    pcap_set_tstamp_precision(cap->pcap, PCAP_TSTAMP_PRECISION_NANO);

    int rc = pcap_activate(cap->pcap);
    if (rc < 0) {
        const char *why = pcap_geterr(cap->pcap);
        snprintf(cap->errbuf, sizeof cap->errbuf, "%s",
                 why[0] != '\0' ? why : pcap_statustostr(rc));
        return open_fail(cap, einf, ERR_OPEN, cfg->source);
    }
    if (rc > 0)
        fprintf(stderr, "monnett: warning: %s: %s\n", cfg->source,
                pcap_statustostr(rc));

    if (strcmp(cfg->source, "any") == 0)
        pcap_set_datalink(cap->pcap, DLT_LINUX_SLL2);
    return ERR_OK;
}

static error_code_mt open_file(capture_mt *cap, const engine_config_mt *cfg,
                               error_info_mt *einf)
{
    cap->pcap = pcap_open_offline_with_tstamp_precision(
        cfg->source, PCAP_TSTAMP_PRECISION_NANO, cap->errbuf);
    if (cap->pcap == NULL)
        return open_fail(cap, einf, ERR_OPEN, cfg->source);
    return ERR_OK;
}

static error_code_mt check_linktype(capture_mt *cap, const char *source,
                                    error_info_mt *einf)
{
    cap->linktype = pcap_datalink(cap->pcap);
    if (cap->linktype == DLT_EN10MB || cap->linktype == DLT_LINUX_SLL2)
        return ERR_OK;

    const char *name = pcap_datalink_val_to_name(cap->linktype);
    snprintf(cap->errbuf, sizeof cap->errbuf, "unsupported link type %d (%s)",
             cap->linktype, name ? name : "unknown");
    return open_fail(cap, einf, ERR_LINKTYPE, source);
}

static error_code_mt set_filter(capture_mt *cap, const char *expr,
                                error_info_mt *einf)
{
    struct bpf_program fp;

    if (pcap_compile(cap->pcap, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        snprintf(cap->errbuf, sizeof cap->errbuf, "%s",
                 pcap_geterr(cap->pcap));
        return open_fail(cap, einf, ERR_FILTER, expr);
    }
    int rc = pcap_setfilter(cap->pcap, &fp);
    pcap_freecode(&fp);
    if (rc < 0) {
        snprintf(cap->errbuf, sizeof cap->errbuf, "%s",
                 pcap_geterr(cap->pcap));
        return open_fail(cap, einf, ERR_FILTER, expr);
    }
    return ERR_OK;
}

error_code_mt cap_open(capture_mt *cap, const engine_config_mt *cfg,
                       error_info_mt *einf)
{
    error_code_mt rc;

    memset(cap, 0, sizeof *cap);
    cap->is_file = cfg->is_file;

    rc = cap->is_file ? open_file(cap, cfg, einf) : open_live(cap, cfg, einf);
    if (rc != ERR_OK)
        return rc;
    rc = check_linktype(cap, cfg->source, einf);
    if (rc != ERR_OK)
        return rc;
    if (cfg->filter[0] != '\0') {
        rc = set_filter(cap, cfg->filter, einf);
        if (rc != ERR_OK)
            return rc;
    }

    cap->ts_nano =
        pcap_get_tstamp_precision(cap->pcap) == PCAP_TSTAMP_PRECISION_NANO;
    atomic_store(&cap->running, 1);
    return ERR_OK;
}

const char *cap_error(const capture_mt *cap)
{
    return cap->errbuf;
}

int cap_next(capture_mt *cap, pkt_slot_mt *slot)
{
    struct pcap_pkthdr *hdr;
    const u_char *pkt;

    if (!atomic_load(&cap->running))
        return -2;

    int rc = pcap_next_ex(cap->pcap, &hdr, &pkt);
    if (rc == PCAP_ERROR) {
        snprintf(cap->errbuf, sizeof cap->errbuf, "%s",
                 pcap_geterr(cap->pcap));
        return -1;
    }
    if (rc != 1)
        return rc == 0 ? 0 : -2;

    uint64_t seq = atomic_fetch_add(&cap->counters.captured, 1);
    atomic_fetch_add(&cap->counters.bytes, hdr->len);
    if (hdr->caplen < hdr->len)
        atomic_fetch_add(&cap->counters.truncated, 1);

    if (slot == NULL) {
        atomic_fetch_add(&cap->counters.engine_drop, 1);
        return 1;
    }

    uint32_t copy_len = hdr->caplen < SLOT_DATA ? hdr->caplen : SLOT_DATA;
    uint64_t frac = (uint64_t)hdr->ts.tv_usec;

    memcpy(slot->data, pkt, copy_len);
    slot->caplen = copy_len;
    slot->wirelen = hdr->len;
    slot->ts_ns = (uint64_t)hdr->ts.tv_sec * 1000000000ull +
                  (cap->ts_nano ? frac : frac * 1000ull);
    slot->seq = seq;
    return 1;
}

void cap_poll_kernel_stats(capture_mt *cap)
{
    struct pcap_stat st;

    if (cap->is_file || cap->pcap == NULL || pcap_stats(cap->pcap, &st) < 0)
        return;
    atomic_fetch_add(&cap->counters.k_recv,
                     (uint32_t)(st.ps_recv - cap->last_kstats.ps_recv));
    atomic_fetch_add(&cap->counters.k_drop,
                     (uint32_t)(st.ps_drop - cap->last_kstats.ps_drop));
    atomic_fetch_add(&cap->counters.k_ifdrop,
                     (uint32_t)(st.ps_ifdrop - cap->last_kstats.ps_ifdrop));
    cap->last_kstats = st;
}

void cap_snapshot(capture_mt *cap, cap_stats_mt *s)
{
    s->captured = atomic_load(&cap->counters.captured);
    s->bytes = atomic_load(&cap->counters.bytes);
    s->engine_drop = atomic_load(&cap->counters.engine_drop);
    s->truncated = atomic_load(&cap->counters.truncated);
    s->k_recv = atomic_load(&cap->counters.k_recv);
    s->k_drop = atomic_load(&cap->counters.k_drop);
    s->k_ifdrop = atomic_load(&cap->counters.k_ifdrop);
}

void cap_stop(capture_mt *cap)
{
    atomic_store(&cap->running, 0);
    if (cap->pcap != NULL)
        pcap_breakloop(cap->pcap);
}

void cap_close(capture_mt *cap)
{
    if (cap->pcap != NULL)
        pcap_close(cap->pcap);
    cap->pcap = NULL;
}

static uint64_t mono_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void capture_loop(capture_thread_args_mt *args)
{
    capture_mt *cap = args->cap;
    uint64_t next_stats = mono_ms() + STATS_PERIOD_MS;

    while (atomic_load(&cap->running)) {
        pkt_slot_mt *slot = pool_get(args->pool, cap->is_file);
        if (slot == NULL && cap->is_file)
            continue;

        int rc = cap_next(cap, slot);
        if (slot != NULL && (rc != 1 || ring_push(args->ready, slot) != 0))
            pool_put(args->pool, slot);

        if (rc == -1) {
            error_fail(&args->einf, ERR_CAPTURE, "pcap_next_ex",
                       cap_error(cap));
            break;
        }
        if (rc == -2)
            break;

        if (mono_ms() >= next_stats) {
            cap_poll_kernel_stats(cap);
            next_stats = mono_ms() + STATS_PERIOD_MS;
        }
    }
}

void *capture_thread(void *arg)
{
    capture_thread_args_mt *args = arg;
    capture_mt *cap = args->cap;

    if (scheduler_set_deadline(args->runtime_ns, args->deadline_ns,
                               args->period_ns, &args->einf) != ERR_OK ||
        scheduler_drop_caps(&args->einf) != ERR_OK) {
        scheduler_report(args->startup, &args->einf);
        ring_close(args->ready);
        atomic_store(&cap->done, 1);
        return NULL;
    }
    scheduler_report(args->startup, NULL);

    capture_loop(args);

    cap_poll_kernel_stats(cap);
    ring_close(args->ready);
    atomic_store(&cap->done, 1);
    return NULL;
}
