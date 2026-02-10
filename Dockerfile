FROM debian:bookworm-slim

ARG USER_ID=501
ARG GROUP_ID=20

# System dependencies (firewall + dev tools)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gosu zsh fzf ripgrep jq aggregate ca-certificates rsync \
    iptables ipset dnsutils iproute2 libcap2-bin gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Create user matching host UID/GID
RUN (groupadd -g ${GROUP_ID} claude 2>/dev/null || true) \
    && useradd -m -l -u ${USER_ID} -g ${GROUP_ID} -s /bin/bash claude

# Node.js (needed by MCP servers that use npx)
# hadolint ignore=DL3008,DL4006
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

ARG CACHE_BUST

# Install Claude Code (native binary)
ENV DISABLE_AUTOUPDATER=1
# hadolint ignore=DL4006
RUN curl -fsSL https://claude.ai/install.sh | bash \
    && cp -L /root/.local/bin/claude /usr/local/bin/claude \
    && rm -rf /root/.local/share/claude /root/.local/bin/claude \
    && mkdir -p /home/claude/.local/bin \
    && ln -s /usr/local/bin/claude /home/claude/.local/bin/claude \
    && chown -R ${USER_ID}:${GROUP_ID} /home/claude/.local

# Strip setuid/setgid bits from all binaries (NoNewPrivs prevents exploitation,
# but removing them reduces attack surface further)
RUN find / -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null || true; \
    find / -perm -2000 -type f -exec chmod g-s {} + 2>/dev/null || true

# Compile drop-dumpable wrapper (sets PR_SET_DUMPABLE=0 before exec — defense in
# depth only; the primary protection is nodump.so via LD_PRELOAD, see below)
COPY drop-dumpable.c /tmp/drop-dumpable.c
RUN gcc -static -O2 -o /usr/local/bin/drop-dumpable /tmp/drop-dumpable.c \
    && rm /tmp/drop-dumpable.c \
    && chmod +x /usr/local/bin/drop-dumpable

# Compile nodump.so — LD_PRELOAD library that calls prctl(PR_SET_DUMPABLE, 0) in
# a constructor. Unlike drop-dumpable (which sets dumpable BEFORE exec and gets
# reset by the kernel's would_dump), this runs AFTER exec inside the new process,
# making /proc/<pid>/mem inaccessible to same-UID children.
COPY nodump.c /tmp/nodump.c
RUN mkdir -p /usr/local/lib \
    && gcc -shared -fPIC -O2 -o /usr/local/lib/nodump.so /tmp/nodump.c \
    && rm /tmp/nodump.c \
    && chmod 755 /usr/local/lib/nodump.so

# Compile git-guard.so — LD_PRELOAD library enforcing git operation restrictions.
# Loaded via /etc/ld.so.preload (read-only rootfs — cannot be removed at runtime).
# Detects when the current process is wrapped-git and enforces: push blocking,
# remote modification blocking, dangerous config key blocking, and forced
# GIT_CONFIG_COUNT overrides. Root (UID 0) is exempt for entrypoint init.
# This is the PRIMARY enforcement layer — the shell wrapper is belt-and-suspenders.
COPY git-guard.c /tmp/git-guard.c
RUN gcc -shared -fPIC -O2 -o /usr/local/lib/git-guard.so /tmp/git-guard.c \
    && rm /tmp/git-guard.c \
    && chmod 755 /usr/local/lib/git-guard.so

# Install both guard libraries via /etc/ld.so.preload (kernel-enforced, cannot be
# bypassed by LD_PRELOAD overrides or environment manipulation on read-only rootfs).
# This ensures git-guard.so and nodump.so load into EVERY dynamically-linked process.
RUN printf '/usr/local/lib/git-guard.so\n/usr/local/lib/nodump.so\n' > /etc/ld.so.preload

# Git wrapper: replace ALL git entry points so /usr/bin/git can't bypass the wrapper.
# Force hooksPath=/dev/null and credential.helper on every invocation.
# Real binary moved to /usr/libexec/wrapped-git (NOT git-* to avoid git's
# argv[0] subcommand detection treating the basename as a builtin command).
# Rootfs is read-only so wrapper can't be modified at runtime.
# hadolint ignore=SC1003,SC2016
RUN printf '#!/bin/sh\n\
# Block dangerous git operations\n\
case "$1" in\n\
  push)\n\
    if [ "${ALLOW_GIT_PUSH:-}" != "1" ]; then\n\
      echo "error: git push is disabled in the sandbox (use --allow-git-push to enable)" >&2\n\
      exit 1\n\
    fi\n\
    ;;\n\
  remote)\n\
    case "${2:-}" in\n\
      add|set-url|rename)\n\
        echo "error: git remote modification is disabled in the sandbox" >&2\n\
        exit 1\n\
        ;;\n\
    esac\n\
    ;;\n\
  config)\n\
    _skip=1\n\
    _key=""\n\
    for _a in "$@"; do\n\
      if [ "$_skip" = 1 ]; then _skip=0; continue; fi\n\
      case "$_a" in\n\
        -*) ;;\n\
        *) _key="$_a"; break ;;\n\
      esac\n\
    done\n\
    case "$_key" in\n\
      core.fsmonitor|core.sshCommand|core.pager|core.editor|core.hooksPath|\\\n\
      diff.*.textconv|filter.*|credential.helper)\n\
        echo "error: setting \047$_key\047 is blocked in the sandbox" >&2\n\
        exit 1\n\
        ;;\n\
    esac\n\
    ;;\n\
esac\n\
export GIT_CONFIG_COUNT=2\n\
export GIT_CONFIG_KEY_0=core.hooksPath\n\
export GIT_CONFIG_VALUE_0=/dev/null\n\
export GIT_CONFIG_KEY_1=credential.helper\n\
export GIT_CONFIG_VALUE_1="cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock"\n\
exec /usr/libexec/wrapped-git "$@"\n' > /usr/local/bin/git \
    && chmod +x /usr/local/bin/git \
    && mkdir -p /usr/libexec \
    && mv /usr/bin/git /usr/libexec/wrapped-git \
    && cp /usr/local/bin/git /usr/bin/git \
    && cp /usr/local/bin/git /usr/lib/git-core/git

# Make sensitive binaries non-readable by UID 501 (belt-and-suspenders with nodump.so).
# When exec'ing a non-readable binary, the kernel's would_dump() sets dumpable=0,
# preventing /proc/<pid>/mem access even without LD_PRELOAD.
# Note: claude is excluded — it's a Bun single-file executable that must read itself
# to extract embedded JavaScript. Primary /proc/mem protection is via nodump.so.
RUN chmod 711 /usr/libexec/wrapped-git

# Purge compiler toolchain — prevents attacker from compiling exploit code,
# LD_PRELOAD injection libraries, or other tools inside the sandbox.
# hadolint ignore=DL3059
RUN apt-get purge -y --auto-remove gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Remove namespace manipulation tools (blocked by zero capabilities, but
# removing them prevents exploitation if capabilities are ever restored)
RUN rm -f /usr/bin/nsenter /usr/bin/unshare /usr/sbin/chroot /usr/sbin/pivot_root

# Firewall scripts
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
COPY reload-firewall.sh /usr/local/bin/reload-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/reload-firewall.sh

# Entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /mnt/.claude-host && chmod 700 /mnt/.claude-host

RUN mkdir -p /workspace && chown ${USER_ID}:${GROUP_ID} /workspace
RUN mkdir -p /home/claude/.claude && chown ${USER_ID}:${GROUP_ID} /home/claude/.claude

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
