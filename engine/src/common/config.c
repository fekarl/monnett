#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "errors.h"

#define LINE_MAX_LEN 2048

typedef enum key_id {
    KEY_SOURCE,
    KEY_FILTER,
    KEY_PROMISC,
    KEY_TIMEOUT_MS,
    KEY_BUFFER_MB,
    KEY_POOL_SLOTS,
    KEY_CAP_RUNTIME_US,
    KEY_CAP_DEADLINE_US,
    KEY_CAP_PERIOD_US,
    KEY_PRS_RUNTIME_US,
    KEY_PRS_BATCH,
    KEY_COUNT
} key_id_mt;

static const char *const key_names[KEY_COUNT] = {
    [KEY_SOURCE]          = "source",
    [KEY_FILTER]          = "filter",
    [KEY_PROMISC]         = "promisc",
    [KEY_TIMEOUT_MS]      = "timeout_ms",
    [KEY_BUFFER_MB]       = "buffer_mb",
    [KEY_POOL_SLOTS]      = "pool_slots",
    [KEY_CAP_RUNTIME_US]  = "cap_runtime_us",
    [KEY_CAP_DEADLINE_US] = "cap_deadline_us",
    [KEY_CAP_PERIOD_US]   = "cap_period_us",
    [KEY_PRS_RUNTIME_US]  = "prs_runtime_us",
    [KEY_PRS_BATCH]       = "prs_batch",
};

typedef struct parser {
    const char *path;
    int line;
    int in_engine;
    int seen_engine;
    int seen[KEY_COUNT];
    error_info_mt *einf;
} parser_mt;

void config_defaults(engine_config_mt *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    snprintf(cfg->source, sizeof cfg->source, "%s", DEF_SOURCE);
    snprintf(cfg->filter, sizeof cfg->filter, "%s", DEF_FILTER);
    cfg->promisc = DEF_PROMISC;
    cfg->timeout_ms = DEF_TIMEOUT_MS;
    cfg->buffer_mb = DEF_BUFFER_MB;
    cfg->pool_slots = DEF_POOL_SLOTS;
    cfg->cap_runtime_us = DEF_CAP_RUNTIME_US;
    cfg->cap_deadline_us = DEF_CAP_DEADLINE_US;
    cfg->cap_period_us = DEF_CAP_PERIOD_US;
    cfg->prs_runtime_us = DEF_PRS_RUNTIME_US;
    cfg->prs_batch = DEF_PRS_BATCH;
}

error_code_mt config_check_perms(const char *path, error_info_mt *einf)
{
    struct stat finfo;

    if (stat(path, &finfo) != 0) {
        if (errno == ENOENT)
            return ERR_OK;
        return error_fail(einf, ERR_CONFIG, path, strerror(errno));
    }
    if (!S_ISREG(finfo.st_mode))
        return error_fail(einf, ERR_CONFIG, path, "not a regular file");
    if (finfo.st_uid != 0 && finfo.st_uid != getuid())
        return error_fail(einf, ERR_CONFIG_PERMS, path,
                          "must be owned by root or by you");
    if (finfo.st_mode & (S_IWGRP | S_IWOTH))
        return error_fail(einf, ERR_CONFIG_PERMS, path,
                          "writable by group or others (chmod go-w)");
    return ERR_OK;
}

static error_code_mt parse_fail(parser_mt *prs, const char *why)
{
    char where[CFG_SOURCE_MAX + 16];

    snprintf(where, sizeof where, "%s:%d", prs->path, prs->line);
    return error_fail(prs->einf, ERR_CONFIG, where, why);
}

static error_code_mt key_fail(parser_mt *prs, const char *why,
                              const char *key)
{
    char msg[128];

    snprintf(msg, sizeof msg, "%s '%s'", why, key);
    return parse_fail(prs, msg);
}

static char *skip_space(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

static int is_key_char(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
}

static int find_key(const char *name)
{
    for (int i = 0; i < KEY_COUNT; i++)
        if (strcmp(key_names[i], name) == 0)
            return i;
    return -1;
}

static error_code_mt read_string(parser_mt *prs, char **str, char *out,
                                 size_t size)
{
    char *r = *str + 1;
    size_t n = 0;

    while (*r != '"') {
        char ch = *r;

        if (ch == '\0')
            return parse_fail(prs, "unterminated string");
        if (ch == '\\') {
            r++;
            switch (*r) {
            case '"':  ch = '"';  break;
            case '\\': ch = '\\'; break;
            case 't':  ch = '\t'; break;
            case 'n':  ch = '\n'; break;
            default:
                return parse_fail(prs, "unknown escape in string");
            }
        }
        if (n + 1 >= size)
            return parse_fail(prs, "string too long");
        out[n++] = ch;
        r++;
    }
    out[n] = '\0';
    *str = r + 1;
    return ERR_OK;
}

static error_code_mt read_bare(parser_mt *prs, char **str, char *out,
                               size_t size)
{
    char *r = *str;
    size_t n = 0;

    while (*r != '\0' && *r != ' ' && *r != '\t' && *r != '#') {
        if (n + 1 >= size)
            return parse_fail(prs, "value too long");
        out[n++] = *r++;
    }
    if (n == 0)
        return parse_fail(prs, "missing value");
    out[n] = '\0';
    *str = r;
    return ERR_OK;
}

static int parse_uint(const char *text, unsigned long long max,
                      unsigned long long *out)
{
    char *end;

    if (text[0] < '0' || text[0] > '9')
        return -1;
    errno = 0;
    unsigned long long v = strtoull(text, &end, 10);
    if (errno != 0 || *end != '\0' || v > max)
        return -1;
    *out = v;
    return 0;
}

static error_code_mt set_value(parser_mt *prs, engine_config_mt *cfg,
                               int key, int quoted, const char *text)
{
    unsigned long long num = 0;
    const char *name = key_names[key];

    if (key == KEY_SOURCE || key == KEY_FILTER) {
        if (!quoted)
            return key_fail(prs, "expected a \"string\" for", name);
        char *dst = key == KEY_SOURCE ? cfg->source : cfg->filter;
        size_t size =
            key == KEY_SOURCE ? sizeof cfg->source : sizeof cfg->filter;

        if (strlen(text) >= size)
            return key_fail(prs, "value too long for", name);
        memcpy(dst, text, strlen(text) + 1);
        return ERR_OK;
    }

    if (quoted)
        return key_fail(prs, "expected a value without quotes for", name);

    if (key == KEY_PROMISC) {
        if (strcmp(text, "true") == 0)
            cfg->promisc = 1;
        else if (strcmp(text, "false") == 0)
            cfg->promisc = 0;
        else
            return key_fail(prs, "expected true or false for", name);
        return ERR_OK;
    }

    if (parse_uint(text, INT_MAX, &num) != 0)
        return key_fail(prs, "expected a whole number for", name);

    switch (key) {
    case KEY_TIMEOUT_MS:      cfg->timeout_ms = (int)num;         break;
    case KEY_BUFFER_MB:       cfg->buffer_mb = (int)num;          break;
    case KEY_POOL_SLOTS:      cfg->pool_slots = (uint32_t)num;    break;
    case KEY_CAP_RUNTIME_US:  cfg->cap_runtime_us = num;          break;
    case KEY_CAP_DEADLINE_US: cfg->cap_deadline_us = num;         break;
    case KEY_CAP_PERIOD_US:   cfg->cap_period_us = num;           break;
    case KEY_PRS_RUNTIME_US:  cfg->prs_runtime_us = num;          break;
    case KEY_PRS_BATCH:       cfg->prs_batch = (uint32_t)num;     break;
    default:                                                      break;
    }
    return ERR_OK;
}

static error_code_mt parse_section(parser_mt *prs, char *str)
{
    char *end = strchr(str, ']');

    if (end == NULL)
        return parse_fail(prs, "missing ']'");
    *end = '\0';

    char *rest = skip_space(end + 1);
    if (*rest != '\0' && *rest != '#')
        return parse_fail(prs, "text after ']'");

    char *name = skip_space(str + 1);
    char *tail = name + strlen(name);
    while (tail > name && (tail[-1] == ' ' || tail[-1] == '\t'))
        *--tail = '\0';

    prs->in_engine = (strcmp(name, "engine") == 0);
    if (prs->in_engine) {
        if (prs->seen_engine)
            return parse_fail(prs, "[engine] appears twice");
        prs->seen_engine = 1;
    }
    return ERR_OK;
}

static error_code_mt parse_key_value(parser_mt *prs,
                                     engine_config_mt *cfg, char *str)
{
    char name[64];
    char value[CFG_FILTER_MAX];
    size_t len = 0;
    int quoted;
    error_code_mt rc;

    while (is_key_char(*str)) {
        if (len + 1 >= sizeof name)
            return parse_fail(prs, "key too long");
        name[len++] = *str++;
    }
    name[len] = '\0';
    if (len == 0)
        return parse_fail(prs, "expected a key");

    str = skip_space(str);
    if (*str != '=')
        return key_fail(prs, "expected '=' after", name);
    str = skip_space(str + 1);

    quoted = (*str == '"');
    if (quoted)
        rc = read_string(prs, &str, value, sizeof value);
    else
        rc = read_bare(prs, &str, value, sizeof value);
    if (rc != ERR_OK)
        return rc;

    str = skip_space(str);
    if (*str != '\0' && *str != '#')
        return key_fail(prs, "unexpected text after the value of", name);

    int key = find_key(name);
    if (key < 0)
        return key_fail(prs, "unknown key", name);
    if (prs->seen[key])
        return key_fail(prs, "duplicate key", name);
    prs->seen[key] = 1;

    return set_value(prs, cfg, key, quoted, value);
}

static error_code_mt parse_line(parser_mt *prs, engine_config_mt *cfg,
                                char *line)
{
    char *str = skip_space(line);

    if (*str == '\0' || *str == '#')
        return ERR_OK;
    if (*str == '[')
        return parse_section(prs, str);
    if (!prs->in_engine)
        return ERR_OK;
    return parse_key_value(prs, cfg, str);
}

static void warn(const char *path, const char *why)
{
    fprintf(stderr, "monnett: warning: %s: %s\n", path, why);
}

error_code_mt config_load(engine_config_mt *cfg, const char *path,
                          int required, error_info_mt *einf)
{
    parser_mt prs = { .path = path, .einf = einf };
    char line[LINE_MAX_LEN];
    error_code_mt rc = ERR_OK;

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        if (errno == ENOENT && !required) {
            warn(path, "not found, using built-in defaults");
            return ERR_OK;
        }
        return error_fail(einf, ERR_CONFIG, path, strerror(errno));
    }

    while (rc == ERR_OK && fgets(line, sizeof line, file) != NULL) {
        size_t len = strlen(line);

        prs.line++;
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        else if (!feof(file))
            rc = parse_fail(&prs, "line too long");
        if (rc == ERR_OK && len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';
        if (rc == ERR_OK)
            rc = parse_line(&prs, cfg, line);
    }

    if (rc == ERR_OK && ferror(file))
        rc = error_fail(einf, ERR_CONFIG, path, "read error");
    fclose(file);

    if (rc != ERR_OK)
        return rc;
    if (!prs.seen_engine)
        warn(path, "no [engine] section, using built-in defaults");
    cfg->file_loaded = 1;
    return ERR_OK;
}

static error_code_mt copy_arg(char *dst, size_t size, const char *src,
                              const char *opt, error_info_mt *einf)
{
    if (strlen(src) >= size)
        return error_fail(einf, ERR_ARGS, opt, "value too long");
    memcpy(dst, src, strlen(src) + 1);
    return ERR_OK;
}

error_code_mt config_apply_args(engine_config_mt *cfg,
                                const cli_opts_mt *opts,
                                error_info_mt *einf)
{
    if (opts->source &&
        copy_arg(cfg->source, sizeof cfg->source, opts->source, "-i",
                 einf) != ERR_OK)
        return einf->code;
    if (opts->filter &&
        copy_arg(cfg->filter, sizeof cfg->filter, opts->filter, "-f",
                 einf) != ERR_OK)
        return einf->code;
    if (opts->dump)
        cfg->dump = 1;
    return ERR_OK;
}

static error_code_mt range_fail(error_info_mt *einf, const char *key,
                                unsigned long long min,
                                unsigned long long max)
{
    char why[96];

    snprintf(why, sizeof why, "must be between %llu and %llu", min, max);
    return error_fail(einf, ERR_CONFIG, key, why);
}

static int ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);

    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static int looks_like_file(const char *source)
{
    return strchr(source, '/') != NULL || ends_with(source, ".pcap") ||
           ends_with(source, ".pcapng");
}

error_code_mt config_validate(engine_config_mt *cfg, error_info_mt *einf)
{
    struct stat finfo;

    if (cfg->source[0] == '\0')
        return error_fail(einf, ERR_CONFIG, "source", "is empty");

    if (cfg->timeout_ms < TIMEOUT_MS_MIN || cfg->timeout_ms > TIMEOUT_MS_MAX)
        return range_fail(einf, "timeout_ms", TIMEOUT_MS_MIN, TIMEOUT_MS_MAX);
    if (cfg->buffer_mb < BUFFER_MB_MIN || cfg->buffer_mb > BUFFER_MB_MAX)
        return range_fail(einf, "buffer_mb", BUFFER_MB_MIN, BUFFER_MB_MAX);
    if (cfg->pool_slots < POOL_SLOTS_MIN || cfg->pool_slots > POOL_SLOTS_MAX)
        return range_fail(einf, "pool_slots", POOL_SLOTS_MIN, POOL_SLOTS_MAX);

    if (cfg->cap_runtime_us < SCHED_US_MIN ||
        cfg->cap_runtime_us > SCHED_US_MAX)
        return range_fail(einf, "cap_runtime_us", SCHED_US_MIN, SCHED_US_MAX);
    if (cfg->cap_deadline_us < SCHED_US_MIN ||
        cfg->cap_deadline_us > SCHED_US_MAX)
        return range_fail(einf, "cap_deadline_us", SCHED_US_MIN, SCHED_US_MAX);
    if (cfg->cap_period_us < SCHED_US_MIN || cfg->cap_period_us > SCHED_US_MAX)
        return range_fail(einf, "cap_period_us", SCHED_US_MIN, SCHED_US_MAX);
    if (cfg->cap_runtime_us > cfg->cap_deadline_us ||
        cfg->cap_deadline_us > cfg->cap_period_us)
        return error_fail(einf, ERR_CONFIG, "cap_*_us",
                          "need runtime <= deadline <= period");

    if (cfg->prs_runtime_us < SCHED_US_MIN ||
        cfg->prs_runtime_us > cfg->cap_period_us)
        return range_fail(einf, "prs_runtime_us", SCHED_US_MIN,
                          cfg->cap_period_us);
    if (cfg->prs_batch < 1 || cfg->prs_batch > cfg->pool_slots)
        return range_fail(einf, "prs_batch", 1, cfg->pool_slots);
    if (cfg->cap_runtime_us + cfg->prs_runtime_us > cfg->cap_period_us)
        return error_fail(einf, ERR_CONFIG, "prs_runtime_us",
                          "need cap_runtime_us + prs_runtime_us <= "
                          "cap_period_us");

    if (stat(cfg->source, &finfo) == 0) {
        if (!S_ISREG(finfo.st_mode))
            return error_fail(einf, ERR_CONFIG, cfg->source,
                              "not a regular file");
        cfg->is_file = 1;
    } else {
        if (looks_like_file(cfg->source))
            return error_fail(einf, ERR_CONFIG, cfg->source, strerror(errno));
        cfg->is_file = 0;
    }
    return ERR_OK;
}

void config_print(const engine_config_mt *cfg, const char *path)
{
    printf("config:   %s\n", path ? path : "(built-in defaults)");
    printf("source:   %s (%s)\n", cfg->source, cfg->is_file ? "file" : "live");
    printf("filter:   %s\n", cfg->filter[0] ? cfg->filter : "(none)");
    if (!cfg->is_file) {
        printf("promisc:  %s\n", cfg->promisc ? "on" : "off");
        printf("buffer:   %d MiB\n", cfg->buffer_mb);
        printf("timeout:  %d ms\n", cfg->timeout_ms);
    }
    printf("pool:     %u slots\n", (unsigned)cfg->pool_slots);
    printf("deadline: runtime %llu us, deadline %llu us, period %llu us\n",
           (unsigned long long)cfg->cap_runtime_us,
           (unsigned long long)cfg->cap_deadline_us,
           (unsigned long long)cfg->cap_period_us);
    printf("parser:   runtime %llu us, period %llu us, batch %u%s\n",
           (unsigned long long)cfg->prs_runtime_us,
           (unsigned long long)cfg->cap_period_us, (unsigned)cfg->prs_batch,
           cfg->dump ? ", dump" : "");
}
