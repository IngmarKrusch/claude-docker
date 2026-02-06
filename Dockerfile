FROM debian:bookworm-slim

ARG USER_ID=501
ARG GROUP_ID=20

# System dependencies (firewall + dev tools)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gosu zsh fzf ripgrep jq aggregate ca-certificates \
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

# Compile drop-dumpable wrapper (sets PR_SET_DUMPABLE=0 before exec)
COPY drop-dumpable.c /tmp/drop-dumpable.c
RUN gcc -static -O2 -o /usr/local/bin/drop-dumpable /tmp/drop-dumpable.c \
    && rm /tmp/drop-dumpable.c \
    && chmod +x /usr/local/bin/drop-dumpable

# Git wrapper: replace ALL git entry points so /usr/bin/git can't bypass the wrapper.
# Force hooksPath=/dev/null and credential.helper on every invocation.
# Real binary moved to /usr/libexec/git-core-wrapped. Rootfs is read-only so
# wrapper can't be modified at runtime.
RUN printf '#!/bin/sh\n\
export GIT_CONFIG_COUNT=2\n\
export GIT_CONFIG_KEY_0=core.hooksPath\n\
export GIT_CONFIG_VALUE_0=/dev/null\n\
export GIT_CONFIG_KEY_1=credential.helper\n\
export GIT_CONFIG_VALUE_1="cache --timeout=86400 --socket=/tmp/.git-credential-cache/sock"\n\
exec /usr/libexec/git-core-wrapped "$@"\n' > /usr/local/bin/git \
    && chmod +x /usr/local/bin/git \
    && mkdir -p /usr/libexec \
    && mv /usr/bin/git /usr/libexec/git-core-wrapped \
    && cp /usr/local/bin/git /usr/bin/git \
    && cp /usr/local/bin/git /usr/lib/git-core/git

# Firewall scripts
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
COPY reload-firewall.sh /usr/local/bin/reload-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/reload-firewall.sh

# Entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /workspace && chown ${USER_ID}:${GROUP_ID} /workspace
RUN mkdir -p /home/claude/.claude && chown ${USER_ID}:${GROUP_ID} /home/claude/.claude

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
