#include <arpa/inet.h>
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

static parse_rc_mt parse_l3(rd_mt *rd, pkt_info_mt *info, event_mt *ev) {
    switch (info->ethertype) {
    case ETYPE_ARP:
        return proto_arp(rd, info, ev);
    case ETYPE_IP4:
        return proto_ipv4(rd, info);
    case ETYPE_IP6:
        return proto_ipv6(rd, info);
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
        rc = parse_l3(&rd, info, &prs->ev);

    if (prs->ev.type != EV_NONE) {
        prs->ev.ts_ns = slot->ts_ns;
        prs->ev.seq = slot->seq;
    }

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
    if (prs->info.is_frag != FRAG_NONE)
        atomic_fetch_add(&c->frag, 1);
    if (prs->ev.type != EV_NONE)
        atomic_fetch_add(&c->events, 1);
    if (prs->info.layers & L_ARP)
        atomic_fetch_add(&c->per_proto[PROTO_ARP], 1);
    if (prs->info.layers & L_IP4)
        atomic_fetch_add(&c->per_proto[PROTO_IP4], 1);
    if (prs->info.layers & L_IP6)
        atomic_fetch_add(&c->per_proto[PROTO_IP6], 1);
}

static void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void print_ip4(const uint8_t *a) {
    printf("%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void print_ip6(const uint8_t *a) {
    char buf[INET6_ADDRSTRLEN];

    printf("%s", inet_ntop(AF_INET6, a, buf, sizeof buf) ? buf : "?");
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
    printf(" type 0x%04x", (unsigned)info->ethertype);
    if (info->layers & (L_IP4 | L_IP6)) {
        void (*print_ip)(const uint8_t *) =
            info->family == 6 ? print_ip6 : print_ip4;
        printf(" | ");
        print_ip(info->src_ip);
        printf(" > ");
        print_ip(info->dst_ip);
        printf(" proto %u ttl %u len %u", (unsigned)info->ip_proto,
               (unsigned)info->ttl, (unsigned)info->ip_len);
        if (info->is_frag != FRAG_NONE)
            printf(" frag %s", info->is_frag == FRAG_FIRST ? "first" : "later");
    }
    printf(" %s%s\n", rc_names[rc], info->truncated ? " truncated" : "");
}

static void dump_arp(const ev_arp_mt *a) {
    printf("  arp %s ", a->opcode == ARP_REQUEST ? "request" : "reply");
    print_ip4(a->sender_ip);
    printf(" ");
    print_mac(a->sender_mac);
    printf(" -> ");
    print_ip4(a->target_ip);
    printf(" ");
    print_mac(a->target_mac);
    printf("%s%s\n", a->gratuitous ? " gratuitous" : "",
           a->probe ? " probe" : "");
}

static void on_event(parser_mt *prs) {
    if (!prs->dump)
        return;
    switch (prs->ev.type) {
    case EV_ARP:
        dump_arp(&prs->ev.u.arp);
        break;
    default:
        printf("  event %d\n", (int)prs->ev.type);
        break;
    }
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
