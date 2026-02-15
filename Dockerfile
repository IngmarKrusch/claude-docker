# Builder stage: compile C libraries without shipping gcc into the final image
FROM debian:bookworm-slim AS builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY container/nodump.c /tmp/nodump.c
COPY container/git-guard.c /tmp/git-guard.c
RUN mkdir -p /usr/local/lib \
    && gcc -shared -fPIC -O2 -o /usr/local/lib/nodump.so /tmp/nodump.c \
    && gcc -shared -fPIC -O2 -o /usr/local/lib/git-guard.so /tmp/git-guard.c \
    && chmod 755 /usr/local/lib/nodump.so /usr/local/lib/git-guard.so

# ─── Main image ───
FROM debian:bookworm-slim

ARG USER_ID=501
ARG GROUP_ID=20

# System dependencies (firewall + dev tools) — gcc/libc6-dev no longer needed
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gosu zsh fzf ripgrep jq aggregate ca-certificates rsync ncurses-term \
    iptables ipset dnsutils iproute2 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create user matching host UID/GID
RUN (groupadd -g ${GROUP_ID} claude 2>/dev/null || true) \
    && useradd -m -l -u ${USER_ID} -g ${GROUP_ID} -s /bin/bash claude

# Node.js (needed by MCP servers that use npx)
# R12-C01 fix: Download script first instead of pipe-to-bash to prevent
# truncation attacks. Checksum verification is impractical (script changes
# per version) — NodeSource APT GPG key provides integrity for the package itself.
# hadolint ignore=DL3008
RUN curl -fsSL -o /tmp/node-setup.sh https://deb.nodesource.com/setup_22.x \
    && bash /tmp/node-setup.sh \
    && rm -f /tmp/node-setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

ARG CACHE_BUST

# Install Claude Code (native binary)
# R12-C01 fix: Download script first instead of pipe-to-bash. Checksum for the
# install script changes per release; post-install binary integrity is verified
# by the installer itself (signed binary). CACHE_BUST triggers re-download when
# a new version is available.
ENV DISABLE_AUTOUPDATER=1
RUN curl -fsSL -o /tmp/claude-install.sh https://claude.ai/install.sh \
    && bash /tmp/claude-install.sh \
    && rm -f /tmp/claude-install.sh \
    && cp -L /root/.local/bin/claude /usr/local/bin/claude \
    && rm -rf /root/.local/share/claude /root/.local/bin/claude \
    && mkdir -p /home/claude/.local/bin \
    && ln -s /usr/local/bin/claude /home/claude/.local/bin/claude \
    && chown -R ${USER_ID}:${GROUP_ID} /home/claude/.local

# Strip setuid/setgid bits from all binaries (NoNewPrivs prevents exploitation,
# but removing them reduces attack surface further)
RUN find / -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null || true; \
    find / -perm -2000 -type f -exec chmod g-s {} + 2>/dev/null || true

# Copy pre-compiled guard libraries from builder stage (R12-L08/S1 fix:
# eliminates gcc from all final image layers)
COPY --from=builder /usr/local/lib/nodump.so /usr/local/lib/nodump.so
COPY --from=builder /usr/local/lib/git-guard.so /usr/local/lib/git-guard.so

# Install both guard libraries via /etc/ld.so.preload (kernel-enforced, cannot be
# bypassed by LD_PRELOAD overrides or environment manipulation on read-only rootfs).
# This ensures git-guard.so and nodump.so load into EVERY dynamically-linked process.
RUN printf '/usr/local/lib/git-guard.so\n/usr/local/lib/nodump.so\n' > /etc/ld.so.preload

# Git wrapper: forces GIT_CONFIG_COUNT on every git invocation (defense-in-depth).
# Primary enforcement is git-guard.so via /etc/ld.so.preload. The wrapper only
# provides env-var overrides for the narrow case of statically-linked callers.
# Real binary at /usr/libexec/wrapped-git. Rootfs is read-only.
COPY container/git-wrapper.sh /usr/local/bin/git
RUN chmod +x /usr/local/bin/git \
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

# Remove namespace manipulation tools (blocked by zero capabilities, but
# removing them prevents exploitation if capabilities are ever restored)
# hadolint ignore=DL3059
RUN rm -f /usr/bin/nsenter /usr/bin/unshare /usr/sbin/chroot /usr/sbin/pivot_root

# Firewall scripts
COPY container/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY container/reload-firewall.sh /usr/local/bin/reload-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/reload-firewall.sh

# Entrypoint
COPY container/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /mnt/.claude-host && chmod 700 /mnt/.claude-host

RUN mkdir -p /workspace && chown ${USER_ID}:${GROUP_ID} /workspace
RUN mkdir -p /home/claude/.claude && chown ${USER_ID}:${GROUP_ID} /home/claude/.claude

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
