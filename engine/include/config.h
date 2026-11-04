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

struct cli_opts {
    const char *config;
    const char *source;
    const char *filter;
    int help;
};

struct engine_config {
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
};

void config_defaults(struct engine_config *c);

enum error_code config_check_perms(const char *path, struct error_info *e);

enum error_code config_load(struct engine_config *c, const char *path,
                            int required, struct error_info *e);

void config_apply_args(struct engine_config *c, const struct cli_opts *o);

enum error_code config_validate(struct engine_config *c, struct error_info *e);

void config_print(const struct engine_config *c, const char *path);

#endif
