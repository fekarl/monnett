#include <sched.h>
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "parser.h"

static const char *const rc_names[] = {
    [PRS_OK] = "ok",
    [PRS_SHORT] = "short",
    [PRS_BAD] = "bad",
    [PRS_OTHER] = "other",
};

void parser_init(parser_mt *prs, int linktype, int dump) {
    memset(prs, 0, sizeof *prs);
    prs->linktype = linktype;
    prs->dump = dump;
}

static parse_rc_mt parse_l3(pkt_info_mt *info) {
    switch (info->ethertype) {
    case ETYPE_ARP:
    case ETYPE_IP4:
    case ETYPE_IP6:
        return PRS_OK;
    default:
        return PRS_OTHER;
    }
}

parse_rc_mt parse_packet(parser_mt *prs, const pkt_slot_mt *slot) {
    pkt_info_mt *info = &prs->info;
    parse_rc_mt rc;
    rd_mt rd;

    memset(info, 0, sizeof *info);
    prs->ev.type = EV_NONE;
    info->ts_ns = slot->ts_ns;
    info->seq = slot->seq;
    info->wirelen = slot->wirelen;
    info->caplen = slot->caplen;

    rd_init(&rd, slot->data, slot->caplen);
    rc = prs->linktype == LINK_SLL2 ? proto_sll2(&rd, info)
                                    : proto_eth(&rd, info);
    if (rc == PRS_OK)
        rc = parse_l3(info);

    if (rc == PRS_SHORT && slot->caplen < slot->wirelen)
        info->truncated = 1;
    return rc;
}

void parser_account(parser_mt *prs, parse_rc_mt rc) {
    prs_counters_mt *c = &prs->counters;

    atomic_fetch_add(&c->parsed, 1);
    if (rc == PRS_OTHER)
        atomic_fetch_add(&c->other, 1);
    else if ((rc == PRS_SHORT && !prs->info.truncated) || rc == PRS_BAD)
        atomic_fetch_add(&c->malformed, 1);
    if (prs->info.is_frag)
        atomic_fetch_add(&c->frag, 1);
    if (prs->ev.type != EV_NONE)
        atomic_fetch_add(&c->events, 1);
}

static void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void on_packet(parser_mt *prs, parse_rc_mt rc) {
    const pkt_info_mt *info = &prs->info;

    if (!prs->dump)
        return;
    printf("#%llu %llu.%09llu %u/%u ", (unsigned long long)info->seq,
           (unsigned long long)(info->ts_ns / 1000000000ull),
           (unsigned long long)(info->ts_ns % 1000000000ull),
           (unsigned)info->caplen, (unsigned)info->wirelen);
    print_mac(info->src_mac);
    printf(" > ");
    print_mac(info->dst_mac);
    if (info->layers & L_VLAN)
        printf(" vlan %u", (unsigned)info->vlan);
    printf(" type 0x%04x %s%s\n", (unsigned)info->ethertype, rc_names[rc],
           info->truncated ? " truncated" : "");
}

static void on_event(parser_mt *prs) {
    if (prs->dump)
        printf("  event %d\n", (int)prs->ev.type);
}

void parser_snapshot(parser_mt *prs, prs_stats_mt *s) {
    prs_counters_mt *c = &prs->counters;

    s->parsed = atomic_load(&c->parsed);
    s->malformed = atomic_load(&c->malformed);
    s->app_bad = atomic_load(&c->app_bad);
    s->other = atomic_load(&c->other);
    s->frag = atomic_load(&c->frag);
    s->events = atomic_load(&c->events);
    for (int i = 0; i < PROTO_COUNT; i++)
        s->per_proto[i] = atomic_load(&c->per_proto[i]);
}

static void parser_loop(parser_thread_args_mt *args) {
    parser_mt *prs = args->prs;

    for (;;) {
        for (uint32_t n = 0; n < args->batch; n++) {
            pkt_slot_mt *slot = ring_pop(args->ready, 0);
            if (slot == NULL)
                break;
            parse_rc_mt rc = parse_packet(prs, slot);
            parser_account(prs, rc);
            on_packet(prs, rc);
            if (prs->ev.type != EV_NONE)
                on_event(prs);
            pool_put(args->pool, slot);
        }
        if (ring_is_done(args->ready))
            break;
        sched_yield();
    }
}

void *parser_thread(void *arg) {
    parser_thread_args_mt *args = arg;

    if (scheduler_set_deadline(args->runtime_ns, args->deadline_ns,
                               args->period_ns, &args->einf) != ERR_OK ||
        scheduler_drop_caps(&args->einf) != ERR_OK) {
        scheduler_report(args->startup, &args->einf);
        atomic_store(&args->prs->done, 1);
        return NULL;
    }
    scheduler_report(args->startup, NULL);

    parser_loop(args);

    fflush(stdout);
    atomic_store(&args->prs->done, 1);
    return NULL;
}
