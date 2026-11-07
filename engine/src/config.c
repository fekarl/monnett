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
    KEY_COUNT
} key_id_mt;

static const char *const key_names[KEY_COUNT] = {
    [KEY_SOURCE] = "source",
    [KEY_FILTER] = "filter",
    [KEY_PROMISC] = "promisc",
    [KEY_TIMEOUT_MS] = "timeout_ms",
    [KEY_BUFFER_MB] = "buffer_mb",
    [KEY_POOL_SLOTS] = "pool_slots",
    [KEY_CAP_RUNTIME_US] = "cap_runtime_us",
    [KEY_CAP_DEADLINE_US] = "cap_deadline_us",
    [KEY_CAP_PERIOD_US] = "cap_period_us",
};

typedef struct parser {
    const char *path;
    int line;
    int in_engine;
    int seen_engine;
    int seen[KEY_COUNT];
    error_info_mt *e;
} parser_mt;

void config_defaults(engine_config_mt *c) {
    memset(c, 0, sizeof *c);
    snprintf(c->source, sizeof c->source, "%s", DEF_SOURCE);
    snprintf(c->filter, sizeof c->filter, "%s", DEF_FILTER);
    c->promisc = DEF_PROMISC;
    c->timeout_ms = DEF_TIMEOUT_MS;
    c->buffer_mb = DEF_BUFFER_MB;
    c->pool_slots = DEF_POOL_SLOTS;
    c->cap_runtime_us = DEF_CAP_RUNTIME_US;
    c->cap_deadline_us = DEF_CAP_DEADLINE_US;
    c->cap_period_us = DEF_CAP_PERIOD_US;
}

error_code_mt config_check_perms(const char *path, error_info_mt *e) {
    struct stat sb;

    if (stat(path, &sb) != 0) {
        if (errno == ENOENT)
            return ERR_OK;
        return error_fail(e, ERR_CONFIG, path, strerror(errno));
    }
    if (!S_ISREG(sb.st_mode))
        return error_fail(e, ERR_CONFIG, path, "not a regular file");
    if (sb.st_uid != 0 && sb.st_uid != getuid())
        return error_fail(e, ERR_CONFIG_PERMS, path,
                          "must be owned by root or by you");
    if (sb.st_mode & (S_IWGRP | S_IWOTH))
        return error_fail(e, ERR_CONFIG_PERMS, path,
                          "writable by group or others (chmod go-w)");
    return ERR_OK;
}

static error_code_mt parse_fail(parser_mt *p, const char *why) {
    char where[CFG_SOURCE_MAX + 16];

    snprintf(where, sizeof where, "%s:%d", p->path, p->line);
    return error_fail(p->e, ERR_CONFIG, where, why);
}

static error_code_mt key_fail(parser_mt *p, const char *why, const char *key) {
    char msg[128];

    snprintf(msg, sizeof msg, "%s '%s'", why, key);
    return parse_fail(p, msg);
}

static char *skip_space(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

static int is_key_char(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
}

static int find_key(const char *name) {
    for (int i = 0; i < KEY_COUNT; i++)
        if (strcmp(key_names[i], name) == 0)
            return i;
    return -1;
}

static error_code_mt read_string(parser_mt *p, char **s, char *out,
                                 size_t size) {
    char *r = *s + 1;
    size_t n = 0;

    while (*r != '"') {
        char ch = *r;

        if (ch == '\0')
            return parse_fail(p, "unterminated string");
        if (ch == '\\') {
            r++;
            switch (*r) {
            case '"':
                ch = '"';
                break;
            case '\\':
                ch = '\\';
                break;
            case 't':
                ch = '\t';
                break;
            case 'n':
                ch = '\n';
                break;
            default:
                return parse_fail(p, "unknown escape in string");
            }
        }
        if (n + 1 >= size)
            return parse_fail(p, "string too long");
        out[n++] = ch;
        r++;
    }
    out[n] = '\0';
    *s = r + 1;
    return ERR_OK;
}

static error_code_mt read_bare(parser_mt *p, char **s, char *out, size_t size) {
    char *r = *s;
    size_t n = 0;

    while (*r != '\0' && *r != ' ' && *r != '\t' && *r != '#') {
        if (n + 1 >= size)
            return parse_fail(p, "value too long");
        out[n++] = *r++;
    }
    if (n == 0)
        return parse_fail(p, "missing value");
    out[n] = '\0';
    *s = r;
    return ERR_OK;
}

static int parse_uint(const char *text, unsigned long long max,
                      unsigned long long *out) {
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

static error_code_mt set_value(parser_mt *p, engine_config_mt *c, int key,
                               int quoted, const char *text) {
    unsigned long long v = 0;
    const char *name = key_names[key];

    if (key == KEY_SOURCE || key == KEY_FILTER) {
        if (!quoted)
            return key_fail(p, "expected a \"string\" for", name);
        char *dst = key == KEY_SOURCE ? c->source : c->filter;
        size_t size = key == KEY_SOURCE ? sizeof c->source : sizeof c->filter;

        if (strlen(text) >= size)
            return key_fail(p, "value too long for", name);
        memcpy(dst, text, strlen(text) + 1);
        return ERR_OK;
    }

    if (quoted)
        return key_fail(p, "expected a value without quotes for", name);

    if (key == KEY_PROMISC) {
        if (strcmp(text, "true") == 0)
            c->promisc = 1;
        else if (strcmp(text, "false") == 0)
            c->promisc = 0;
        else
            return key_fail(p, "expected true or false for", name);
        return ERR_OK;
    }

    if (parse_uint(text, INT_MAX, &v) != 0)
        return key_fail(p, "expected a whole number for", name);

    switch (key) {
    case KEY_TIMEOUT_MS:
        c->timeout_ms = (int)v;
        break;
    case KEY_BUFFER_MB:
        c->buffer_mb = (int)v;
        break;
    case KEY_POOL_SLOTS:
        c->pool_slots = (uint32_t)v;
        break;
    case KEY_CAP_RUNTIME_US:
        c->cap_runtime_us = v;
        break;
    case KEY_CAP_DEADLINE_US:
        c->cap_deadline_us = v;
        break;
    case KEY_CAP_PERIOD_US:
        c->cap_period_us = v;
        break;
    default:
        break;
    }
    return ERR_OK;
}

static error_code_mt parse_section(parser_mt *p, char *s) {
    char *end = strchr(s, ']');

    if (end == NULL)
        return parse_fail(p, "missing ']'");
    *end = '\0';

    char *rest = skip_space(end + 1);
    if (*rest != '\0' && *rest != '#')
        return parse_fail(p, "text after ']'");

    char *name = skip_space(s + 1);
    char *tail = name + strlen(name);
    while (tail > name && (tail[-1] == ' ' || tail[-1] == '\t'))
        *--tail = '\0';

    p->in_engine = (strcmp(name, "engine") == 0);
    if (p->in_engine) {
        if (p->seen_engine)
            return parse_fail(p, "[engine] appears twice");
        p->seen_engine = 1;
    }
    return ERR_OK;
}

static error_code_mt parse_key_value(parser_mt *p, engine_config_mt *c,
                                     char *s) {
    char name[64];
    char value[CFG_FILTER_MAX];
    size_t n = 0;
    int quoted;
    error_code_mt rc;

    while (is_key_char(*s)) {
        if (n + 1 >= sizeof name)
            return parse_fail(p, "key too long");
        name[n++] = *s++;
    }
    name[n] = '\0';
    if (n == 0)
        return parse_fail(p, "expected a key");

    s = skip_space(s);
    if (*s != '=')
        return key_fail(p, "expected '=' after", name);
    s = skip_space(s + 1);

    quoted = (*s == '"');
    if (quoted)
        rc = read_string(p, &s, value, sizeof value);
    else
        rc = read_bare(p, &s, value, sizeof value);
    if (rc != ERR_OK)
        return rc;

    s = skip_space(s);
    if (*s != '\0' && *s != '#')
        return key_fail(p, "unexpected text after the value of", name);

    int key = find_key(name);
    if (key < 0)
        return key_fail(p, "unknown key", name);
    if (p->seen[key])
        return key_fail(p, "duplicate key", name);
    p->seen[key] = 1;

    return set_value(p, c, key, quoted, value);
}

static error_code_mt parse_line(parser_mt *p, engine_config_mt *c, char *line) {
    char *s = skip_space(line);

    if (*s == '\0' || *s == '#')
        return ERR_OK;
    if (*s == '[')
        return parse_section(p, s);
    if (!p->in_engine)
        return ERR_OK;
    return parse_key_value(p, c, s);
}

static void warn(const char *path, const char *why) {
    fprintf(stderr, "monnett: warning: %s: %s\n", path, why);
}

error_code_mt config_load(engine_config_mt *c, const char *path, int required,
                          error_info_mt *e) {
    parser_mt p = {.path = path, .e = e};
    char line[LINE_MAX_LEN];
    error_code_mt rc = ERR_OK;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (errno == ENOENT && !required) {
            warn(path, "not found, using built-in defaults");
            return ERR_OK;
        }
        return error_fail(e, ERR_CONFIG, path, strerror(errno));
    }

    while (rc == ERR_OK && fgets(line, sizeof line, f) != NULL) {
        size_t len = strlen(line);

        p.line++;
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        else if (!feof(f))
            rc = parse_fail(&p, "line too long");
        if (rc == ERR_OK && len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';
        if (rc == ERR_OK)
            rc = parse_line(&p, c, line);
    }

    if (rc == ERR_OK && ferror(f))
        rc = error_fail(e, ERR_CONFIG, path, "read error");
    fclose(f);

    if (rc != ERR_OK)
        return rc;
    if (!p.seen_engine)
        warn(path, "no [engine] section, using built-in defaults");
    c->file_loaded = 1;
    return ERR_OK;
}

static error_code_mt copy_arg(char *dst, size_t size, const char *src,
                              const char *opt, error_info_mt *e) {
    if (strlen(src) >= size)
        return error_fail(e, ERR_ARGS, opt, "value too long");
    memcpy(dst, src, strlen(src) + 1);
    return ERR_OK;
}

error_code_mt config_apply_args(engine_config_mt *c, const cli_opts_mt *opts,
                                error_info_mt *e) {
    if (opts->source &&
        copy_arg(c->source, sizeof c->source, opts->source, "-i", e) != ERR_OK)
        return e->code;
    if (opts->filter &&
        copy_arg(c->filter, sizeof c->filter, opts->filter, "-f", e) != ERR_OK)
        return e->code;
    return ERR_OK;
}

static error_code_mt range_fail(error_info_mt *e, const char *key,
                                unsigned long long min,
                                unsigned long long max) {
    char why[96];

    snprintf(why, sizeof why, "must be between %llu and %llu", min, max);
    return error_fail(e, ERR_CONFIG, key, why);
}

static int ends_with(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);

    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static int looks_like_file(const char *source) {
    return strchr(source, '/') != NULL || ends_with(source, ".pcap") ||
           ends_with(source, ".pcapng");
}

error_code_mt config_validate(engine_config_mt *c, error_info_mt *e) {
    struct stat sb;

    if (c->source[0] == '\0')
        return error_fail(e, ERR_CONFIG, "source", "is empty");

    if (c->timeout_ms < TIMEOUT_MS_MIN || c->timeout_ms > TIMEOUT_MS_MAX)
        return range_fail(e, "timeout_ms", TIMEOUT_MS_MIN, TIMEOUT_MS_MAX);
    if (c->buffer_mb < BUFFER_MB_MIN || c->buffer_mb > BUFFER_MB_MAX)
        return range_fail(e, "buffer_mb", BUFFER_MB_MIN, BUFFER_MB_MAX);
    if (c->pool_slots < POOL_SLOTS_MIN || c->pool_slots > POOL_SLOTS_MAX)
        return range_fail(e, "pool_slots", POOL_SLOTS_MIN, POOL_SLOTS_MAX);

    if (c->cap_runtime_us < SCHED_US_MIN || c->cap_runtime_us > SCHED_US_MAX)
        return range_fail(e, "cap_runtime_us", SCHED_US_MIN, SCHED_US_MAX);
    if (c->cap_deadline_us < SCHED_US_MIN || c->cap_deadline_us > SCHED_US_MAX)
        return range_fail(e, "cap_deadline_us", SCHED_US_MIN, SCHED_US_MAX);
    if (c->cap_period_us < SCHED_US_MIN || c->cap_period_us > SCHED_US_MAX)
        return range_fail(e, "cap_period_us", SCHED_US_MIN, SCHED_US_MAX);
    if (c->cap_runtime_us > c->cap_deadline_us ||
        c->cap_deadline_us > c->cap_period_us)
        return error_fail(e, ERR_CONFIG, "cap_*_us",
                          "need runtime <= deadline <= period");

    if (stat(c->source, &sb) == 0) {
        if (!S_ISREG(sb.st_mode))
            return error_fail(e, ERR_CONFIG, c->source, "not a regular file");
        c->is_file = 1;
    } else {
        if (looks_like_file(c->source))
            return error_fail(e, ERR_CONFIG, c->source, strerror(errno));
        c->is_file = 0;
    }
    return ERR_OK;
}

void config_print(const engine_config_mt *c, const char *path) {
    printf("config:   %s\n", path ? path : "(built-in defaults)");
    printf("source:   %s (%s)\n", c->source, c->is_file ? "file" : "live");
    printf("filter:   %s\n", c->filter[0] ? c->filter : "(none)");
    if (!c->is_file) {
        printf("promisc:  %s\n", c->promisc ? "on" : "off");
        printf("buffer:   %d MiB\n", c->buffer_mb);
        printf("timeout:  %d ms\n", c->timeout_ms);
    }
    printf("pool:     %u slots\n", (unsigned)c->pool_slots);
    printf("deadline: runtime %llu us, deadline %llu us, period %llu us\n",
           (unsigned long long)c->cap_runtime_us,
           (unsigned long long)c->cap_deadline_us,
           (unsigned long long)c->cap_period_us);
}
