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

struct engine {
    struct engine_config cfg;
    struct capture cap;
    struct pkt_pool pool;
    struct scheduler_startup startup;
    struct capture_thread_args cargs;
    pthread_t tcap;
    struct error_info err;
};

static void usage(FILE *f, const char *prog) {
    fprintf(f,
            "usage: %s [--config FILE] [-i SOURCE] [-f FILTER]\n"
            "  -c, --config FILE   settings file (default: %s)\n"
            "  -i, --source SRC    interface (e.g. enp0s3) or .pcap file\n"
            "  -f, --filter EXPR   BPF filter, e.g. \"tcp or udp\"\n"
            "  -h, --help          this text\n",
            prog, DEFAULT_CONFIG);
}

static const char *option_name(char **argv, int opt) {
    static char shortopt[3] = {'-', 0, 0};

    if (opt == 0 || strncmp(argv[optind - 1], "--", 2) == 0)
        return argv[optind - 1];
    shortopt[1] = (char)opt;
    return shortopt;
}

static enum error_code parse_args(int argc, char **argv, struct cli_opts *opts,
                                  struct error_info *e) {
    static const struct option longopts[] = {
        {"config", required_argument, NULL, 'c'},
        {"source", required_argument, NULL, 'i'},
        {"filter", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    memset(opts, 0, sizeof *opts);
    opterr = 0;

    int ch;
    while ((ch = getopt_long(argc, argv, ":c:i:f:h", longopts, NULL)) != -1) {
        switch (ch) {
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
            return error_fail(e, ERR_ARGS, option_name(argv, optopt),
                              "expected a value");
        default:
            return error_fail(e, ERR_ARGS, option_name(argv, optopt),
                              "unknown option");
        }
    }
    if (optind < argc)
        return error_fail(e, ERR_ARGS, argv[optind], "unexpected argument");
    return ERR_OK;
}

static void setup_signals(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, set, NULL);
}

static void print_stats(struct capture *c, const char *when) {
    struct cap_stats s;
    cap_snapshot(c, &s);
    printf("[%s] captured=%llu bytes=%llu engine_drop=%llu truncated=%llu "
           "k_recv=%llu k_drop=%llu k_ifdrop=%llu\n",
           when, (unsigned long long)s.captured, (unsigned long long)s.bytes,
           (unsigned long long)s.engine_drop, (unsigned long long)s.truncated,
           (unsigned long long)s.k_recv, (unsigned long long)s.k_drop,
           (unsigned long long)s.k_ifdrop);
    fflush(stdout);
}

static int wait_for_stop(struct engine *eng, const sigset_t *set) {
    const struct timespec one_second = {.tv_sec = 1, .tv_nsec = 0};

    for (;;) {
        int sig = sigtimedwait(set, NULL, &one_second);
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

static int exit_code(const struct engine *eng) { return (int)eng->err.code; }

static enum error_code load_config(struct engine *eng,
                                   const struct cli_opts *opts) {
    const char *path = opts->config ? opts->config : DEFAULT_CONFIG;
    int required = (opts->config != NULL);

    config_defaults(&eng->cfg);
    if (config_check_perms(path, &eng->err) != ERR_OK)
        return eng->err.code;
    if (config_load(&eng->cfg, path, required, &eng->err) != ERR_OK)
        return eng->err.code;
    if (config_apply_args(&eng->cfg, opts, &eng->err) != ERR_OK)
        return eng->err.code;
    if (config_validate(&eng->cfg, &eng->err) != ERR_OK)
        return eng->err.code;
    config_print(&eng->cfg, eng->cfg.file_loaded ? path : NULL);
    return ERR_OK;
}

static void run_capture(struct engine *eng, const sigset_t *sigs) {
    scheduler_startup_init(&eng->startup, 1);
    eng->cargs = (struct capture_thread_args){
        .cap = &eng->cap,
        .pool = &eng->pool,
        .startup = &eng->startup,
        .runtime_ns = US_TO_NS(eng->cfg.cap_runtime_us),
        .deadline_ns = US_TO_NS(eng->cfg.cap_deadline_us),
        .period_ns = US_TO_NS(eng->cfg.cap_period_us),
    };

    int rc = pthread_create(&eng->tcap, NULL, capture_thread, &eng->cargs);
    if (rc != 0) {
        errno = rc;
        error_fail(&eng->err, ERR_THREAD, "capture thread", strerror(rc));
        scheduler_startup_destroy(&eng->startup);
        return;
    }

    if (scheduler_wait_all(&eng->startup, STARTUP_TIMEOUT_MS, &eng->err) !=
            ERR_OK ||
        scheduler_drop_caps(&eng->err) != ERR_OK) {
        cap_stop(&eng->cap);
    } else {
        int sig = wait_for_stop(eng, sigs);
        if (sig)
            fprintf(stderr, "monnett: %s, stopping\n",
                    sig == SIGINT ? "SIGINT" : "SIGTERM");
    }

    pthread_join(eng->tcap, NULL);
    if (eng->err.code == ERR_OK && eng->cargs.err.code != ERR_OK)
        eng->err = eng->cargs.err;
    print_stats(&eng->cap, "end");
    scheduler_startup_destroy(&eng->startup);
}

static void run_engine(struct engine *eng) {
    if (cap_open(&eng->cap, &eng->cfg, &eng->err) != ERR_OK)
        return;

    if (pool_init(&eng->pool, eng->cfg.pool_slots, &eng->err) == ERR_OK) {
        sigset_t sigs;
        setup_signals(&sigs);
        run_capture(eng, &sigs);
        pool_destroy(&eng->pool);
    }

    cap_close(&eng->cap);
}

int main(int argc, char **argv) {
    struct engine eng;
    struct cli_opts opts;

    memset(&eng, 0, sizeof eng);

    if (parse_args(argc, argv, &opts, &eng.err) != ERR_OK) {
        error_print(&eng.err);
        return exit_code(&eng);
    }
    if (opts.help) {
        usage(stdout, argv[0]);
        return 0;
    }

    if (load_config(&eng, &opts) == ERR_OK)
        run_engine(&eng);

    if (eng.err.code != ERR_OK)
        error_print(&eng.err);
    return exit_code(&eng);
}
