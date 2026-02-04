FROM debian:bookworm-slim

ARG USER_ID=501
ARG GROUP_ID=20

# System dependencies (firewall + dev tools)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gosu zsh fzf ripgrep jq aggregate ca-certificates \
    iptables ipset dnsutils iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create user matching host UID/GID
RUN (groupadd -g ${GROUP_ID} claude 2>/dev/null || true) \
    && useradd -m -l -u ${USER_ID} -g ${GROUP_ID} -s /bin/bash claude

# Install Claude Code (native binary, no Node.js needed)
ENV DISABLE_AUTOUPDATER=1
# hadolint ignore=DL4006
RUN curl -fsSL https://claude.ai/install.sh | bash \
    && cp -L /root/.local/bin/claude /usr/local/bin/claude \
    && rm -rf /root/.local/share/claude /root/.local/bin/claude \
    && mkdir -p /home/claude/.local/bin \
    && ln -s /usr/local/bin/claude /home/claude/.local/bin/claude \
    && chown -R ${USER_ID}:${GROUP_ID} /home/claude/.local

# Firewall script (from Anthropic's official devcontainer)
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh

# Entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /workspace && chown ${USER_ID}:${GROUP_ID} /workspace
RUN mkdir -p /home/claude/.claude && chown ${USER_ID}:${GROUP_ID} /home/claude/.claude

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
