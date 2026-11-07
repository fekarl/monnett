#ifndef CONFIG_H
#define CONFIG_H

#include "errors.h"
#include <stdint.h>

#define DEFAULT_CONFIG "configs/default.toml"

#define CFG_SOURCE_MAX 256
#define CFG_FILTER_MAX 1024

#define DEF_SOURCE "enp0s3"
#define DEF_FILTER ""
#define DEF_PROMISC 1
#define DEF_TIMEOUT_MS 100
#define DEF_BUFFER_MB 64
#define DEF_POOL_SLOTS 8192

#define DEF_CAP_RUNTIME_US 200
#define DEF_CAP_DEADLINE_US 1000
#define DEF_CAP_PERIOD_US 1000

#define POOL_SLOTS_MIN 1024
#define POOL_SLOTS_MAX 65536
#define BUFFER_MB_MIN 1
#define BUFFER_MB_MAX 1024
#define TIMEOUT_MS_MIN 1
#define TIMEOUT_MS_MAX 1000
#define SCHED_US_MIN 10
#define SCHED_US_MAX 1000000

typedef struct cli_opts {
    const char *config;
    const char *source;
    const char *filter;
    int help;
} cli_opts_mt;

typedef struct engine_config {
    char source[CFG_SOURCE_MAX];
    char filter[CFG_FILTER_MAX];
    int is_file;
    int promisc;
    int timeout_ms;
    int buffer_mb;
    uint32_t pool_slots;
    uint64_t cap_runtime_us;
    uint64_t cap_deadline_us;
    uint64_t cap_period_us;
    int file_loaded;
} engine_config_mt;

void config_defaults(engine_config_mt *c);

error_code_mt config_check_perms(const char *path, error_info_mt *e);

error_code_mt config_load(engine_config_mt *c, const char *path, int required,
                          error_info_mt *e);

error_code_mt config_apply_args(engine_config_mt *c, const cli_opts_mt *opts,
                                error_info_mt *e);

error_code_mt config_validate(engine_config_mt *c, error_info_mt *e);

void config_print(const engine_config_mt *c, const char *path);

#endif
