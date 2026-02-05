FROM debian:bookworm-slim

ARG USER_ID=501
ARG GROUP_ID=20

# System dependencies (firewall + dev tools)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gosu zsh fzf ripgrep jq aggregate ca-certificates \
    iptables ipset dnsutils iproute2 libcap2-bin \
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
