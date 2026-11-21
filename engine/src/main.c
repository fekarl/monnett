#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "capturer.h"
#include "config.h"
#include "errors.h"
#include "parser.h"
#include "pktring.h"
#include "scheduler.h"

#define STARTUP_TIMEOUT_MS 2000
#define US_TO_NS(us) ((uint64_t)(us) * 1000u)

typedef struct engine {
    engine_config_mt cfg;
    capture_mt cap;
    pkt_pool_mt pool;
    pkt_ring_mt ready;
    parser_mt prs;
    scheduler_startup_mt startup;
    capture_thread_args_mt cap_args;
    parser_thread_args_mt prs_args;
    pthread_t cap_thread;
    pthread_t prs_thread;
    error_info_mt einf;
} engine_mt;

static void usage(FILE *f, const char *prog) {
    fprintf(f,
            "usage: %s [--config FILE] [-i SOURCE] [-f FILTER] [-d]\n"
            "  -c, --config FILE   settings file (default: %s)\n"
            "  -i, --source SRC    interface\n"
            "  -f, --filter EXPR   BPF filter\n"
            "  -d, --dump          one line per packet\n"
            "  -h, --help          please help me\n",
            prog, DEFAULT_CONFIG);
}

static const char *option_name(char **argv, int opt) {
    static char shortopt[3] = {'-', 0, 0};

    if (opt == 0 || strncmp(argv[optind - 1], "--", 2) == 0)
        return argv[optind - 1];
    shortopt[1] = (char)opt;
    return shortopt;
}

static error_code_mt parse_args(int argc, char **argv,
                                cli_opts_mt *opts, error_info_mt *einf) {
    static const struct option longopts[] = {
        {"config", required_argument, NULL, 'c'},
        {"source", required_argument, NULL, 'i'},
        {"filter", required_argument, NULL, 'f'},
        {"dump", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    memset(opts, 0, sizeof *opts);
    opterr = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, ":c:i:f:dh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            opts->config = optarg;
            break;
        case 'i':
            opts->source = optarg;
            break;
        case 'f':
            opts->filter = optarg;
            break;
        case 'd':
            opts->dump = 1;
            break;
        case 'h':
            opts->help = 1;
            break;
        case ':':
            return error_fail(einf, ERR_ARGS, option_name(argv, optopt),
                              "expected a value");
        default:
            return error_fail(einf, ERR_ARGS, option_name(argv, optopt),
                              "unknown option");
        }
    }
    if (optind < argc)
        return error_fail(einf, ERR_ARGS, argv[optind], "unexpected argument");
    return ERR_OK;
}

static void setup_signals(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, set, NULL);
}

static void print_stats(engine_mt *eng, const char *when) {
    cap_stats_mt s;
    prs_stats_mt p;
    cap_snapshot(&eng->cap, &s);
    parser_snapshot(&eng->prs, &p);
    printf("[%s] captured=%llu bytes=%llu engine_drop=%llu truncated=%llu "
           "k_recv=%llu k_drop=%llu k_ifdrop=%llu | parsed=%llu "
           "malformed=%llu app_bad=%llu other=%llu frag=%llu events=%llu\n",
           when, (unsigned long long)s.captured, (unsigned long long)s.bytes,
           (unsigned long long)s.engine_drop, (unsigned long long)s.truncated,
           (unsigned long long)s.k_recv, (unsigned long long)s.k_drop,
           (unsigned long long)s.k_ifdrop, (unsigned long long)p.parsed,
           (unsigned long long)p.malformed, (unsigned long long)p.app_bad,
           (unsigned long long)p.other, (unsigned long long)p.frag,
           (unsigned long long)p.events);
    fflush(stdout);
}

static int wait_for_stop(engine_mt *eng, const sigset_t *sigs) {
    const struct timespec one_second = {.tv_sec = 1, .tv_nsec = 0};

    for (;;) {
        int sig = sigtimedwait(sigs, NULL, &one_second);
        if (sig == SIGINT || sig == SIGTERM) {
            cap_stop(&eng->cap);
            return sig;
        }
        if (sig < 0 && errno == EINTR)
            continue;

        if (!eng->cfg.is_file)
            print_stats(eng, "1s");
        if (atomic_load(&eng->prs.done))
            return 0;
    }
}

static int exit_code(const engine_mt *eng) { return (int)eng->einf.code; }

static error_code_mt load_config(engine_mt *eng,
                                 const cli_opts_mt *opts) {
    const char *path = opts->config ? opts->config : DEFAULT_CONFIG;
    int required = (opts->config != NULL);

    config_defaults(&eng->cfg);
    if (config_check_perms(path, &eng->einf) != ERR_OK)
        return eng->einf.code;
    if (config_load(&eng->cfg, path, required, &eng->einf) != ERR_OK)
        return eng->einf.code;
    if (config_apply_args(&eng->cfg, opts, &eng->einf) != ERR_OK)
        return eng->einf.code;
    if (config_validate(&eng->cfg, &eng->einf) != ERR_OK)
        return eng->einf.code;
    config_print(&eng->cfg, eng->cfg.file_loaded ? path : NULL);
    return ERR_OK;
}

static int start_parser(engine_mt *eng) {
    eng->prs_args = (parser_thread_args_mt){
        .prs = &eng->prs,
        .pool = &eng->pool,
        .ready = &eng->ready,
        .startup = &eng->startup,
        .runtime_ns = US_TO_NS(eng->cfg.prs_runtime_us),
        .deadline_ns = US_TO_NS(eng->cfg.cap_period_us),
        .period_ns = US_TO_NS(eng->cfg.cap_period_us),
        .batch = eng->cfg.prs_batch,
    };

    int rc =
        pthread_create(&eng->prs_thread, NULL, parser_thread, &eng->prs_args);
    if (rc != 0) {
        errno = rc;
        error_fail(&eng->einf, ERR_THREAD, "parser thread", strerror(rc));
        return -1;
    }
    return 0;
}

static int start_capture(engine_mt *eng) {
    eng->cap_args = (capture_thread_args_mt){
        .cap = &eng->cap,
        .pool = &eng->pool,
        .ready = &eng->ready,
        .startup = &eng->startup,
        .runtime_ns = US_TO_NS(eng->cfg.cap_runtime_us),
        .deadline_ns = US_TO_NS(eng->cfg.cap_deadline_us),
        .period_ns = US_TO_NS(eng->cfg.cap_period_us),
    };

    int rc =
        pthread_create(&eng->cap_thread, NULL, capture_thread, &eng->cap_args);
    if (rc != 0) {
        errno = rc;
        error_fail(&eng->einf, ERR_THREAD, "capture thread", strerror(rc));
        return -1;
    }
    return 0;
}

static void keep_thread_error(engine_mt *eng, const error_info_mt *einf) {
    if (eng->einf.code == ERR_OK && einf->code != ERR_OK)
        eng->einf = *einf;
}

static void run_threads(engine_mt *eng, const sigset_t *sigs) {
    scheduler_startup_init(&eng->startup, 2);
    parser_init(&eng->prs, eng->cap.linktype, eng->cfg.dump);

    if (start_parser(eng) != 0) {
        scheduler_startup_destroy(&eng->startup);
        return;
    }
    if (start_capture(eng) != 0) {
        ring_close(&eng->ready);
        pthread_join(eng->prs_thread, NULL);
        scheduler_startup_destroy(&eng->startup);
        return;
    }

    if (scheduler_wait_all(&eng->startup, STARTUP_TIMEOUT_MS, &eng->einf) !=
        ERR_OK ||
        scheduler_drop_caps(&eng->einf) != ERR_OK) {
        cap_stop(&eng->cap);
    } else {
        int sig = wait_for_stop(eng, sigs);
        if (sig)
            fprintf(stderr, "monnett: %s, stopping\n",
                    sig == SIGINT ? "SIGINT" : "SIGTERM");
    }

    pthread_join(eng->cap_thread, NULL);
    pthread_join(eng->prs_thread, NULL);
    keep_thread_error(eng, &eng->cap_args.einf);
    keep_thread_error(eng, &eng->prs_args.einf);
    print_stats(eng, "end");
    scheduler_startup_destroy(&eng->startup);
}

static void run_engine(engine_mt *eng) {
    if (cap_open(&eng->cap, &eng->cfg, &eng->einf) != ERR_OK)
        return;

    if (pool_init(&eng->pool, eng->cfg.pool_slots, &eng->einf) == ERR_OK) {
        int rc = ring_init(&eng->ready, eng->cfg.pool_slots);
        if (rc != 0) {
            error_fail(&eng->einf, ERR_NOMEM, "ring_init", strerror(rc));
        } else {
            sigset_t sigs;
            setup_signals(&sigs);
            run_threads(eng, &sigs);
            ring_destroy(&eng->ready);
        }
        pool_destroy(&eng->pool);
    }

    cap_close(&eng->cap);
}

int main(int argc, char **argv) {
    engine_mt eng;
    cli_opts_mt opts;

    memset(&eng, 0, sizeof eng);

    if (parse_args(argc, argv, &opts, &eng.einf) != ERR_OK) {
        error_print(&eng.einf);
        return exit_code(&eng);
    }
    if (opts.help) {
        usage(stdout, argv[0]);
        return 0;
    }

    if (load_config(&eng, &opts) == ERR_OK)
        run_engine(&eng);

    if (eng.einf.code != ERR_OK)
        error_print(&eng.einf);
    return exit_code(&eng);
}
