/*
 * git-guard.so — LD preload library enforcing git operation restrictions.
 *
 * Loaded via /etc/ld.so.preload (read-only rootfs — cannot be bypassed).
 * Detects when the current process is the real git binary and enforces:
 *   - git push blocked unless ALLOW_GIT_PUSH=1
 *   - git remote add/set-url/rename blocked
 *   - git config with dangerous keys blocked
 *   - GIT_CONFIG_COUNT env vars forced (hooksPath, credential.helper)
 *
 * Root (UID 0) is exempt — the entrypoint is trusted init code.
 * Non-git processes return immediately (one readlink + strcmp).
 *
 * Build: gcc -shared -fPIC -O2 -o git-guard.so git-guard.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WRAPPED_GIT_PATH "/usr/libexec/wrapped-git"
#define MAX_CMDLINE 65536
#define MAX_ARGS 256

static void block(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    _exit(1);
}

static int is_blocked_config_key(const char *key) {
    static const char *exact[] = {
        "core.fsmonitor", "core.sshCommand", "core.pager",
        "core.editor", "core.hooksPath", "credential.helper", NULL
    };
    for (int i = 0; exact[i]; i++) {
        if (strcmp(key, exact[i]) == 0)
            return 1;
    }
    /* filter.* — any key starting with "filter." */
    if (strncmp(key, "filter.", 7) == 0)
        return 1;
    /* diff.<driver>.textconv */
    if (strncmp(key, "diff.", 5) == 0 && strlen(key) > 5) {
        const char *dot = strchr(key + 5, '.');
        if (dot && strcmp(dot, ".textconv") == 0)
            return 1;
    }
    return 0;
}

__attribute__((constructor))
static void git_guard_init(void) {
    /* Fast path: only act on the real git binary */
    char exe[1024];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) return;
    exe[len] = '\0';
    if (strcmp(exe, WRAPPED_GIT_PATH) != 0) return;

    /* Root is trusted (entrypoint init code) */
    if (getuid() == 0) return;

    /* Force security-critical git config via environment.
     * GIT_CONFIG_COUNT overrides local/global gitconfig, preventing
     * bypass via .git/config or GIT_CONFIG_GLOBAL. */
    setenv("GIT_CONFIG_COUNT", "2", 1);
    setenv("GIT_CONFIG_KEY_0", "core.hooksPath", 1);
    setenv("GIT_CONFIG_VALUE_0", "/dev/null", 1);
    setenv("GIT_CONFIG_KEY_1", "credential.helper", 1);
    setenv("GIT_CONFIG_VALUE_1",
           "cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock", 1);

    /* Parse /proc/self/cmdline for argv */
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    char cmdline[MAX_CMDLINE];
    ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    if (n <= 0) return;
    cmdline[n] = '\0';

    char *argv[MAX_ARGS];
    int argc = 0;
    char *p = cmdline;
    char *end = cmdline + n;
    while (p < end && argc < MAX_ARGS - 1) {
        argv[argc++] = p;
        p += strlen(p) + 1;
    }
    argv[argc] = NULL;
    if (argc < 2) return;

    /* Skip any global flags before the subcommand (e.g., git -C /dir push) */
    int sub_idx = 1;
    while (sub_idx < argc && argv[sub_idx][0] == '-') {
        /* Flags that take an argument: skip next token too */
        if (strcmp(argv[sub_idx], "-C") == 0 ||
            strcmp(argv[sub_idx], "-c") == 0 ||
            strcmp(argv[sub_idx], "--git-dir") == 0 ||
            strcmp(argv[sub_idx], "--work-tree") == 0) {
            sub_idx++;
        }
        sub_idx++;
    }
    if (sub_idx >= argc) return;
    const char *subcmd = argv[sub_idx];

    /* Block: git push (unless ALLOW_GIT_PUSH=1) */
    if (strcmp(subcmd, "push") == 0) {
        const char *allow = getenv("ALLOW_GIT_PUSH");
        if (!allow || strcmp(allow, "1") != 0)
            block("git push is disabled in the sandbox "
                  "(use --allow-git-push to enable)");
    }

    /* Block: git remote add|set-url|rename */
    if (strcmp(subcmd, "remote") == 0 && sub_idx + 1 < argc) {
        const char *action = argv[sub_idx + 1];
        if (strcmp(action, "add") == 0 ||
            strcmp(action, "set-url") == 0 ||
            strcmp(action, "rename") == 0)
            block("git remote modification is disabled in the sandbox");
    }

    /* Block: git config <dangerous-key> */
    if (strcmp(subcmd, "config") == 0) {
        for (int i = sub_idx + 1; i < argc; i++) {
            if (argv[i][0] == '-') continue;  /* skip flags */
            if (is_blocked_config_key(argv[i]))
                block("this git config key is blocked in the sandbox");
            break;  /* first non-flag arg is the key */
        }
    }
}
