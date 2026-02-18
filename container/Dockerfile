# clawworker — OpenClaw Container
# Runs inside a Cloudflare Container sandbox.
# The CF Worker proxies HTTP/WebSocket traffic to this container on port 18789.
#
# Build:
#   docker build -t clawworker-container ./container
#   docker build --build-arg OPENCLAW_VERSION=2026.2.15 -t clawworker-container ./container

FROM node:22-bookworm-slim

# ── System dependencies ──────────────────────────────────────────────────────
# curl:      downloading optional skill binaries / health checks
# git:       workspace git operations by agent
# ca-certs:  HTTPS trust anchors
# socat:     socket relay (used by some skills)
# procps:    ps / kill utilities for agent tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      git \
      socat \
      procps \
    && rm -rf /var/lib/apt/lists/*

# ── Install OpenClaw globally ─────────────────────────────────────────────────
# The npm package ships a complete pre-built distribution — no pnpm/source
# build needed. Pin a specific version for reproducibility via OPENCLAW_VERSION.
ARG OPENCLAW_VERSION=latest
RUN npm install -g openclaw@${OPENCLAW_VERSION} --prefer-online \
    && openclaw --version 2>/dev/null || true

# ── Workspace ─────────────────────────────────────────────────────────────────
# /root/clawd — agent workspace (memory files, skills, SOUL.md, etc.)
# In Cloudflare Containers, state is ephemeral unless backed by R2.
# The Worker handles R2 backup/restore on a 5-minute cron.
WORKDIR /root
RUN mkdir -p /root/clawd

# ── Startup scripts ───────────────────────────────────────────────────────────
COPY start-openclaw.sh /root/start-openclaw.sh
COPY config-template.js /root/config-template.js
RUN chmod +x /root/start-openclaw.sh

# ── Environment ───────────────────────────────────────────────────────────────
ENV HOME=/root \
    NODE_ENV=production \
    TERM=xterm-256color

# ── Port ─────────────────────────────────────────────────────────────────────
# OpenClaw gateway default port — must match Worker proxy target
EXPOSE 18789

# ── Entrypoint ────────────────────────────────────────────────────────────────
CMD ["/root/start-openclaw.sh"]
