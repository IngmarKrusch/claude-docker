/*
 * git-guard.so — LD preload library enforcing git operation restrictions.
 *
 * Loaded via /etc/ld.so.preload (read-only rootfs — cannot be bypassed).
 * Detects when the current process is the real git binary and enforces:
 *   - git push blocked unless /run/sandbox-flags/allow-git-push exists
 *   - git remote add/set-url/rename blocked
 *   - git config with dangerous keys blocked
 *   - git submodule add blocked
 *   - GIT_CONFIG_COUNT env vars forced (hooksPath, credential.helper,
 *     core.fsmonitor, core.sshCommand)
 *
 * Credential extraction: git credential fill is blocked (R11-02 hardening),
 * but the token remains accessible via direct socket connect to the credential
 * cache daemon (same-UID limitation). Mitigation: use fine-grained PATs with
 * minimal scope.
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
#include <strings.h>
#include <unistd.h>

#define WRAPPED_GIT_PATH "/usr/libexec/wrapped-git"
#define MAX_CMDLINE 65536
#define MAX_ARGS 256

static void block(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    _exit(1);
}

static int is_blocked_config_key(const char *key) {
    /* Git config keys are case-insensitive for section and key name parts.
     * Use strcasecmp/strncasecmp throughout for case-insensitive matching. */
    static const char *exact[] = {
        "core.fsmonitor", "core.sshCommand", "core.pager",
        "core.editor", "core.hooksPath", "credential.helper",
        "include.path", "core.gitProxy", "core.askPass", NULL
    };
    for (int i = 0; exact[i]; i++) {
        if (strcasecmp(key, exact[i]) == 0)
            return 1;
    }
    /* H3 Round 10 fix: Block entire config sections that enable code execution */
    /* url.* — URL rewriting can redirect to attacker servers */
    if (strncasecmp(key, "url.", 4) == 0)
        return 1;
    /* http.* — proxy settings, SSL verification bypass */
    if (strncasecmp(key, "http.", 5) == 0)
        return 1;
    /* remote.* — remote URL manipulation */
    if (strncasecmp(key, "remote.", 7) == 0)
        return 1;
    /* credential.* — catch all forms (credential.helper, credential.<url>.helper, etc.) */
    if (strncasecmp(key, "credential.", 11) == 0)
        return 1;
    /* filter.* — any key starting with "filter." */
    if (strncasecmp(key, "filter.", 7) == 0)
        return 1;
    /* alias.* — any key starting with "alias." */
    if (strncasecmp(key, "alias.", 6) == 0)
        return 1;
    /* includeIf.*.path — starts with "includeIf." and ends with ".path" */
    if (strncasecmp(key, "includeIf.", 10) == 0) {
        size_t klen = strlen(key);
        if (klen > 15 && strcasecmp(key + klen - 5, ".path") == 0)
            return 1;
    }
    /* diff.<driver>.textconv and diff.<driver>.command (H3 fix) */
    if (strncasecmp(key, "diff.", 5) == 0 && strlen(key) > 5) {
        const char *dot = strchr(key + 5, '.');
        if (dot && (strcasecmp(dot, ".textconv") == 0 ||
                    strcasecmp(dot, ".command") == 0))
            return 1;
    }
    /* merge.<driver>.driver (H3 fix) */
    if (strncasecmp(key, "merge.", 6) == 0 && strlen(key) > 6) {
        const char *dot = strchr(key + 6, '.');
        if (dot && strcasecmp(dot, ".driver") == 0)
            return 1;
    }
    return 0;
}

/* Check if a -c or --config-env argument contains a blocked config key.
 * Format: key=value (for -c) or key=envvar (for --config-env).
 * Extracts the key (everything before the first '=') and checks it. */
static int check_config_arg(const char *arg) {
    char key_buf[256];
    const char *eq = strchr(arg, '=');
    size_t key_len = eq ? (size_t)(eq - arg) : strlen(arg);
    if (key_len == 0 || key_len >= sizeof(key_buf)) return 0;
    memcpy(key_buf, arg, key_len);
    key_buf[key_len] = '\0';
    return is_blocked_config_key(key_buf);
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

    /* H4 Round 10 fix: Clear dangerous git environment variables that can override
     * our forced config or execute code. Must be done BEFORE setting GIT_CONFIG_COUNT
     * so we don't accidentally unset our own forced values. */
    unsetenv("GIT_EXTERNAL_DIFF");
    unsetenv("GIT_SSH");
    unsetenv("GIT_SSH_COMMAND");
    unsetenv("GIT_ASKPASS");
    unsetenv("GIT_EDITOR");
    unsetenv("GIT_EXEC_PATH");
    unsetenv("GIT_TEMPLATE_DIR");
    unsetenv("GIT_CONFIG_SYSTEM");
    unsetenv("GIT_PROXY_COMMAND");

    /* Force security-critical git config via environment.
     * GIT_CONFIG_COUNT overrides local/global gitconfig, preventing
     * bypass via .git/config or GIT_CONFIG_GLOBAL. */
    setenv("GIT_CONFIG_COUNT", "4", 1);
    setenv("GIT_CONFIG_KEY_0", "core.hooksPath", 1);
    setenv("GIT_CONFIG_VALUE_0", "/dev/null", 1);
    setenv("GIT_CONFIG_KEY_1", "credential.helper", 1);
    setenv("GIT_CONFIG_VALUE_1",
           "cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock", 1);
    setenv("GIT_CONFIG_KEY_2", "core.fsmonitor", 1);
    setenv("GIT_CONFIG_VALUE_2", "false", 1);
    setenv("GIT_CONFIG_KEY_3", "core.sshCommand", 1);
    setenv("GIT_CONFIG_VALUE_3", "/bin/false", 1);

    /* Parse /proc/self/cmdline for argv */
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    char cmdline[MAX_CMDLINE];
    ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    if (n <= 0) return;
    cmdline[n] = '\0';

    /* Reject if cmdline was truncated — blocked keys past the boundary
     * would be silently missed. */
    if (n >= (ssize_t)(sizeof(cmdline) - 1))
        block("command line too long for sandbox validation");

    char *argv[MAX_ARGS];
    int argc = 0;
    char *p = cmdline;
    char *end = cmdline + n;
    while (p < end && argc < MAX_ARGS - 1) {
        argv[argc++] = p;
        p += strlen(p) + 1;
    }
    argv[argc] = NULL;
    /* L10 Round 10 fix: Block if args were truncated — attacker could push
     * blocked keys past the parsing boundary */
    if (p < end)
        block("too many arguments for sandbox validation");
    if (argc < 2) return;

    /* Skip global flags before the subcommand, inspecting -c and --config-env
     * for blocked config keys (C1 fix: -c has highest config precedence and
     * overrides GIT_CONFIG_COUNT environment variables). */
    int sub_idx = 1;
    while (sub_idx < argc && argv[sub_idx][0] == '-') {
        if (strcmp(argv[sub_idx], "-c") == 0) {
            /* -c key=value: inspect for blocked keys */
            if (sub_idx + 1 < argc && check_config_arg(argv[sub_idx + 1]))
                block("git -c with blocked config key is disabled "
                      "in the sandbox");
            sub_idx++; /* skip value */
        } else if (strncmp(argv[sub_idx], "-c", 2) == 0 && argv[sub_idx][2] != '\0') {
            /* C1 Round 10 fix: -ckey=value (concatenated form, no space) */
            if (check_config_arg(argv[sub_idx] + 2))
                block("git -c with blocked config key is disabled "
                      "in the sandbox");
        } else if (strcmp(argv[sub_idx], "--config-env") == 0) {
            /* --config-env key=envvar: inspect for blocked keys */
            if (sub_idx + 1 < argc && check_config_arg(argv[sub_idx + 1]))
                block("git --config-env with blocked config key is disabled "
                      "in the sandbox");
            sub_idx++; /* skip value */
        } else if (strncmp(argv[sub_idx], "--config-env=", 13) == 0) {
            /* --config-env=key=envvar: combined form */
            if (check_config_arg(argv[sub_idx] + 13))
                block("git --config-env with blocked config key is disabled "
                      "in the sandbox");
        } else if (strcmp(argv[sub_idx], "-C") == 0 ||
                   strcmp(argv[sub_idx], "--git-dir") == 0 ||
                   strcmp(argv[sub_idx], "--work-tree") == 0 ||
                   strcmp(argv[sub_idx], "--namespace") == 0 ||
                   strcmp(argv[sub_idx], "--super-prefix") == 0) {
            sub_idx++; /* skip argument (H4 fix) */
        }
        sub_idx++;
    }
    if (sub_idx >= argc) return;
    const char *subcmd = argv[sub_idx];

    /* Block: git push (unless flag file created by entrypoint as root) */
    if (strcmp(subcmd, "push") == 0) {
        if (access("/run/sandbox-flags/allow-git-push", F_OK) != 0)
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

    /* R12-M04 fix: Block git clone --config <blocked-key>=<value>
     * git clone accepts --config/-c to set config keys in the cloned repo,
     * bypassing the git-config subcommand parsing above. */
    if (strcmp(subcmd, "clone") == 0) {
        for (int j = sub_idx + 1; j < argc; j++) {
            if ((strcmp(argv[j], "--config") == 0 || strcmp(argv[j], "-c") == 0)
                && j + 1 < argc) {
                if (check_config_arg(argv[j + 1]))
                    block("git clone --config with blocked key is disabled in the sandbox");
                j++; /* skip value */
            } else if (strncmp(argv[j], "--config=", 9) == 0) {
                /* --config=key=value combined form */
                if (check_config_arg(argv[j] + 9))
                    block("git clone --config with blocked key is disabled in the sandbox");
            }
        }
    }

    /* Block: git submodule add */
    if (strcmp(subcmd, "submodule") == 0 && sub_idx + 1 < argc) {
        if (strcmp(argv[sub_idx + 1], "add") == 0)
            block("git submodule add is disabled in the sandbox");
    }

    /* Block: git credential fill (R11-02 hardening)
     * NOTE: This blocks the trivial extraction path only. The token remains
     * accessible via direct socket connect to /tmp/.git-credential-cache/sock
     * (same-UID limitation). Root-cause fix requires fine-grained PATs. */
    if (strcmp(subcmd, "credential") == 0 && sub_idx + 1 < argc) {
        const char *cred_action = argv[sub_idx + 1];
        if (strcmp(cred_action, "fill") == 0)
            block("git credential extraction is disabled in the sandbox");
    }

    /* Block: git config <dangerous-key> */
    if (strcmp(subcmd, "config") == 0) {
        for (int i = sub_idx + 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                /* H2 fix: recognize flags that take a value argument and skip
                 * their values, so the value isn't mistaken for the config key.
                 * C2 Round 10 fix: removed --fixed-value (it's a boolean flag,
                 * not a value-taking flag, so including it caused the actual
                 * config key to be skipped during parsing). */
                if (strcmp(argv[i], "--file") == 0 ||
                    strcmp(argv[i], "-f") == 0 ||
                    strcmp(argv[i], "--blob") == 0 ||
                    strcmp(argv[i], "--type") == 0 ||
                    strcmp(argv[i], "--default") == 0) {
                    i++; /* skip flag's value */
                }
                continue;
            }
            if (is_blocked_config_key(argv[i]))
                block("this git config key is blocked in the sandbox");
            break;  /* first non-flag arg is the key */
        }
    }
}
