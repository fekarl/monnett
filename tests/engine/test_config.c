#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "config.h"
#include "errors.h"

static char dir[] = "/tmp/monnett-test-XXXXXX";
static char path[256];

static void write_file(const char *name, const char *text, mode_t mode)
{
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
}

static error_code_mt load(const char *text, engine_config_mt *cfg,
                          error_info_mt *einf)
{
    write_file("t.toml", text, 0644);
    config_defaults(cfg);
    memset(einf, 0, sizeof *einf);
    error_code_mt rc = config_check_perms(path, einf);
    if (rc == ERR_OK)
        rc = config_load(cfg, path, 1, einf);
    return rc;
}

static int load_fails(const char *text, const char *msg_part)
{
    engine_config_mt cfg;
    error_info_mt einf;

    return load(text, &cfg, &einf) == ERR_CONFIG && strstr(einf.msg, msg_part) != NULL;
}

static error_code_mt validate(const char *text)
{
    engine_config_mt cfg;
    error_info_mt einf;

    if (load(text, &cfg, &einf) != ERR_OK)
        return einf.code;
    return config_validate(&cfg, &einf);
}

int main(void)
{
    engine_config_mt cfg;
    error_info_mt einf;
    cli_opts_mt opts;

    if (mkdtemp(dir) == NULL)
        return 1;

    config_defaults(&cfg);
    CHECK(strcmp(cfg.source, DEF_SOURCE) == 0 && cfg.pool_slots == DEF_POOL_SLOTS &&
              cfg.promisc == DEF_PROMISC && cfg.buffer_mb == DEF_BUFFER_MB,
          "defaults");

    CHECK(load("[common]\nsocket = \"/run/x.sock\"\nlist = [1, 2]\n\n"
               "[engine]\nsource = \"eth1\"   # comment\n"
               "filter = \"tcp or \\\"x\\\"\"\npromisc = false\n"
               "pool_slots = 4096\ncap_runtime_us = 300\n\n"
               "[analyzer]\nwindow = 10\n",
               &cfg, &einf) == ERR_OK,
          "full file with other sections loads");
    CHECK(strcmp(cfg.source, "eth1") == 0, "source read");
    CHECK(strcmp(cfg.filter, "tcp or \"x\"") == 0, "filter with escapes read");
    CHECK(cfg.promisc == 0, "promisc false read");
    CHECK(cfg.pool_slots == 4096, "pool_slots read");
    CHECK(cfg.cap_runtime_us == 300, "cap_runtime_us read");
    CHECK(cfg.buffer_mb == DEF_BUFFER_MB, "missing key keeps default");
    CHECK(cfg.file_loaded == 1, "file_loaded set");

    CHECK(load("[engine]\r\nsource = \"eth2\"\r\n", &cfg, &einf) == ERR_OK &&
              strcmp(cfg.source, "eth2") == 0,
          "CRLF line endings");

    CHECK(load_fails("[engine]\nsorce = \"a\"\n", "t.toml:2: unknown key"),
          "unknown key with line number");
    CHECK(load_fails("[engine]\nsource = enp0s3\n", "expected a \"string\""),
          "string without quotes");
    CHECK(load_fails("[engine]\npromisc = yes\n", "true or false"),
          "bad boolean");
    CHECK(load_fails("[engine]\npool_slots = -5\n", "whole number"),
          "negative number");
    CHECK(load_fails("[engine]\npool_slots = 99999999999\n", "whole number"),
          "number too big");
    CHECK(load_fails("[engine]\npool_slots = 12abc\n", "whole number"),
          "number with letters");
    CHECK(load_fails("[engine]\npool_slots = \"4096\"\n", "without quotes"),
          "number in quotes");
    CHECK(load_fails("[engine]\nsource = \"a\n", "unterminated string"),
          "unterminated string");
    CHECK(load_fails("[engine]\nfilter = \"\\q\"\n", "unknown escape"),
          "unknown escape");
    CHECK(load_fails("[engine]\nsource \"a\"\n", "expected '='"),
          "missing =");
    CHECK(load_fails("[engine]\nsource = \"a\" b\n", "unexpected text"),
          "text after value");
    CHECK(load_fails("[engine]\nsource =\n", "missing value"),
          "missing value");
    CHECK(load_fails("[engine]\npool_slots = 4096\npool_slots = 8192\n",
                     "t.toml:3: duplicate key"),
          "duplicate key");
    CHECK(load_fails("[engine\n", "missing ']'"), "missing ]");
    CHECK(load_fails("[engine]\n[engine]\n", "appears twice"),
          "[engine] twice");

    char longline[3000];
    memset(longline, 'a', sizeof longline - 1);
    longline[sizeof longline - 1] = '\0';
    char text[3100];
    snprintf(text, sizeof text, "[engine]\nfilter = \"%s\"\n", longline);
    CHECK(load_fails(text, "line too long"), "line too long");

    char longsrc[400];
    memset(longsrc, 'b', 300);
    longsrc[300] = '\0';
    snprintf(text, sizeof text, "[engine]\nsource = \"%s\"\n", longsrc);
    CHECK(load_fails(text, "value too long"), "source too long");

    CHECK(load("[common]\nx = 1\n", &cfg, &einf) == ERR_OK &&
              strcmp(cfg.source, DEF_SOURCE) == 0,
          "no [engine] section keeps defaults");

    config_defaults(&cfg);
    snprintf(path, sizeof path, "%s/missing.toml", dir);
    CHECK(config_check_perms(path, &einf) == ERR_OK, "perms: missing file is ok");
    CHECK(config_load(&cfg, path, 0, &einf) == ERR_OK && cfg.file_loaded == 0,
          "missing optional file uses defaults");
    CHECK(config_load(&cfg, path, 1, &einf) == ERR_CONFIG,
          "missing required file is an error");

    write_file("open.toml", "[engine]\n", 0666);
    CHECK(config_check_perms(path, &einf) == ERR_CONFIG_PERMS,
          "perms: writable by others rejected");
    write_file("group.toml", "[engine]\n", 0664);
    CHECK(config_check_perms(path, &einf) == ERR_CONFIG_PERMS,
          "perms: writable by group rejected");
    write_file("ok.toml", "[engine]\n", 0644);
    CHECK(config_check_perms(path, &einf) == ERR_OK, "perms: 0644 accepted");
    CHECK(config_check_perms(dir, &einf) == ERR_CONFIG,
          "perms: directory rejected");

    CHECK(validate("[engine]\nsource = \"eth0\"\n") == ERR_OK, "valid config");
    CHECK(validate("[engine]\npool_slots = 1000\n") == ERR_CONFIG,
          "pool_slots below range");
    CHECK(validate("[engine]\npool_slots = 70000\n") == ERR_CONFIG,
          "pool_slots above range");
    CHECK(validate("[engine]\nbuffer_mb = 0\n") == ERR_CONFIG,
          "buffer_mb below range");
    CHECK(validate("[engine]\nbuffer_mb = 2048\n") == ERR_CONFIG,
          "buffer_mb above range");
    CHECK(validate("[engine]\ntimeout_ms = 0\n") == ERR_CONFIG,
          "timeout_ms below range");
    CHECK(validate("[engine]\ncap_runtime_us = 5\n") == ERR_CONFIG,
          "runtime below range");
    CHECK(validate("[engine]\ncap_runtime_us = 2000\n") == ERR_CONFIG,
          "runtime > deadline");
    CHECK(validate("[engine]\ncap_deadline_us = 5000\n") == ERR_CONFIG,
          "deadline > period");
    CHECK(validate("[engine]\nsource = \"\"\n") == ERR_CONFIG, "empty source");
    CHECK(validate("[engine]\nsource = \"gone.pcap\"\n") == ERR_CONFIG,
          "missing .pcap file");
    CHECK(validate("[engine]\nsource = \"a/b\"\n") == ERR_CONFIG,
          "missing path with /");

    config_defaults(&cfg);
    snprintf(cfg.source, sizeof cfg.source, "eth0.100");
    CHECK(config_validate(&cfg, &einf) == ERR_OK && cfg.is_file == 0,
          "VLAN interface name is live");

    write_file("x.pcap", "data", 0644);
    config_defaults(&cfg);
    snprintf(cfg.source, sizeof cfg.source, "%s", path);
    CHECK(config_validate(&cfg, &einf) == ERR_OK && cfg.is_file == 1,
          "existing file is file mode");

    config_defaults(&cfg);
    memset(&opts, 0, sizeof opts);
    opts.source = "eth9";
    opts.filter = "udp";
    CHECK(config_apply_args(&cfg, &opts, &einf) == ERR_OK &&
              strcmp(cfg.source, "eth9") == 0 && strcmp(cfg.filter, "udp") == 0,
          "command line overrides");
    opts.source = longsrc;
    CHECK(config_apply_args(&cfg, &opts, &einf) == ERR_ARGS, "-i too long rejected");

    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0)
        return 1;
    return check_done("test_config");
}
