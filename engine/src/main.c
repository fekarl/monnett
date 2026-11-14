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
#include "pktring.h"
#include "scheduler.h"

#define STARTUP_TIMEOUT_MS 2000
#define US_TO_NS(us) ((uint64_t)(us) * 1000u)

typedef struct engine {
    engine_config_mt cfg;
    capture_mt cap;
    pkt_pool_mt pool;
    scheduler_startup_mt startup;
    capture_thread_args_mt cap_args;
    pthread_t cap_thread;
    error_info_mt einf;
} engine_mt;

static void usage(FILE *f, const char *prog) {
    fprintf(f,
            "usage: %s [--config FILE] [-i SOURCE] [-f FILTER]\n"
            "  -c, --config FILE   settings file (default: %s)\n"
            "  -i, --source SRC    interface\n"
            "  -f, --filter EXPR   BPF filter\n"
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

static error_code_mt parse_args(int argc, char **argv, cli_opts_mt *opts,
                                error_info_mt *einf) {
    static const struct option longopts[] = {
        {"config", required_argument, NULL, 'c'},
        {"source", required_argument, NULL, 'i'},
        {"filter", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    memset(opts, 0, sizeof *opts);
    opterr = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, ":c:i:f:h", longopts, NULL)) != -1) {
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

static void print_stats(capture_mt *cap, const char *when) {
    cap_stats_mt s;
    cap_snapshot(cap, &s);
    printf("[%s] captured=%llu bytes=%llu engine_drop=%llu truncated=%llu "
           "k_recv=%llu k_drop=%llu k_ifdrop=%llu\n",
           when, (unsigned long long)s.captured, (unsigned long long)s.bytes,
           (unsigned long long)s.engine_drop, (unsigned long long)s.truncated,
           (unsigned long long)s.k_recv, (unsigned long long)s.k_drop,
           (unsigned long long)s.k_ifdrop);
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
            print_stats(&eng->cap, "1s");
        if (atomic_load(&eng->cap.done))
            return 0;
    }
}

static int exit_code(const engine_mt *eng) { return (int)eng->einf.code; }

static error_code_mt load_config(engine_mt *eng, const cli_opts_mt *opts) {
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

static void run_capture(engine_mt *eng, const sigset_t *sigs) {
    scheduler_startup_init(&eng->startup, 1);
    eng->cap_args = (capture_thread_args_mt){
        .cap = &eng->cap,
        .pool = &eng->pool,
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
    if (eng->einf.code == ERR_OK && eng->cap_args.einf.code != ERR_OK)
        eng->einf = eng->cap_args.einf;
    print_stats(&eng->cap, "end");
    scheduler_startup_destroy(&eng->startup);
}

static void run_engine(engine_mt *eng) {
    if (cap_open(&eng->cap, &eng->cfg, &eng->einf) != ERR_OK)
        return;

    if (pool_init(&eng->pool, eng->cfg.pool_slots, &eng->einf) == ERR_OK) {
        sigset_t sigs;
        setup_signals(&sigs);
        run_capture(eng, &sigs);
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