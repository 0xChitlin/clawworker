# clawworker

**OpenClaw agent hosting on Cloudflare Containers.**

Run a full [OpenClaw](https://github.com/openclaw/openclaw) AI agent gateway inside a Cloudflare Container sandbox, with a CF Worker as the authenticated HTTP/WebSocket proxy. Workspace state is persisted to R2 every 5 minutes.

This project is a fork/adaptation of [moltworker](https://github.com/cloudflare/moltworker) (Cloudflare × Molt.id) — replacing the MoltBot agent with OpenClaw.

---

## Architecture

```
User (Browser / Telegram / Slack)
    │
    ▼
CF Worker  (src/index.ts — Hono app)
  ✓ Auth — Bearer token validation
  ✓ HTTP proxy — /api/* → container:18789
  ✓ WebSocket relay — /ws → container:18789
  ✓ R2 backup cron — every 5 minutes
    │
    │  sandbox.containerFetch() / WebSocket
    ▼
CF Container  (container/Dockerfile)
  • node:22-bookworm-slim
  • openclaw installed globally via npm
  • /root/clawd/ workspace
  • start-openclaw.sh entrypoint
  • openclaw gateway on port 18789
```

---

## Quick Start (Local Dev)

### Prerequisites

- [Node.js 22+](https://nodejs.org/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm install -g wrangler`)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (for container builds)
- A Cloudflare account with Workers + Containers beta access

### 1. Clone

```bash
git clone https://github.com/0xChitlin/clawworker
cd clawworker
npm install
```

### 2. Configure secrets

```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars — add your ANTHROPIC_API_KEY, GATEWAY_TOKEN, etc.
```

### 3. Create R2 bucket

```bash
wrangler r2 bucket create clawworker-backups
```

### 4. Run locally

```bash
npm run dev
# Starts wrangler dev — builds the container, starts the Worker
# Worker: http://localhost:8787
# Container gateway: accessible via Worker proxy
```

### 5. Test

```bash
# Health check (no auth required)
curl http://localhost:8787/health

# Chat with the agent (auth required)
curl -H "Authorization: Bearer your-secret-gateway-token" \
     http://localhost:8787/api/status
```

---

## Project Structure

```
clawworker/
├── README.md
├── wrangler.toml           CF Worker config — container + R2 bindings + cron
├── package.json
├── tsconfig.json
├── .dev.vars.example       → copy to .dev.vars and fill in secrets
├── src/
│   └── index.ts            CF Worker: auth, HTTP proxy, WebSocket relay, R2 cron
└── container/
    ├── Dockerfile          node:22-bookworm-slim + openclaw@latest
    ├── start-openclaw.sh   Container entrypoint: config → gateway start
    └── config-template.js  Generates openclaw.json from env vars at runtime
```

---

## Environment Variables

All variables are injected into the container by Cloudflare at startup.

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | ✅ | Anthropic API key for Claude models |
| `GATEWAY_TOKEN` | ✅ | Bearer token to authenticate Worker→container and external clients |
| `ADMIN_TOKEN` | ✅ | Token for `/admin` management endpoint |
| `AGENT_ID` | ✅ | Unique agent identifier (used for R2 backup path) |
| `AGENT_NAME` | — | Display name shown in chat interfaces |
| `MODEL` | — | LLM model (default: `anthropic/claude-sonnet-4-6`) |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token (from @BotFather) |
| `TELEGRAM_CHAT_ID` | — | Default Telegram chat to respond in |
| `OPENAI_API_KEY` | — | OpenAI API key (for GPT models) |
| `BRAVE_API_KEY` | — | Brave Search API key (for web search tool) |

Non-secret vars (`AGENT_ID`, `MODEL`) can go in `wrangler.toml [vars]`.  
Secrets must use `.dev.vars` locally or `wrangler secret put <KEY>` in production.

---

## Routes

| Route | Auth | Description |
|---|---|---|
| `GET /health` | None | Worker + container liveness status |
| `ALL /api/*` | GATEWAY_TOKEN | Proxy to openclaw gateway HTTP API |
| `GET /ws` | GATEWAY_TOKEN | WebSocket relay to openclaw gateway |
| `GET /admin` | ADMIN_TOKEN | Admin status panel |

---

## Deployment

### Push secrets to production

```bash
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put GATEWAY_TOKEN
wrangler secret put ADMIN_TOKEN
wrangler secret put TELEGRAM_BOT_TOKEN  # if using Telegram
```

### Deploy

```bash
npm run deploy
# Deploys the Worker + builds and uploads the container image to Cloudflare
```

Your agent will be live at `https://clawworker.<your-subdomain>.workers.dev`

### Per-agent deployment (multi-agent)

Override `AGENT_ID` per deployment for multiple isolated agents:

```bash
wrangler deploy --name clawworker-alice --var AGENT_ID:alice
wrangler deploy --name clawworker-bob --var AGENT_ID:bob
```

Each gets its own container instance and R2 backup path (`agents/{id}/workspace.tar.gz`).

---

## How This Differs from Running OpenClaw Locally

| | Local (`openclaw gateway`) | clawworker (Cloudflare) |
|---|---|---|
| Infrastructure | Your machine | Cloudflare edge |
| Availability | Up when laptop is on | 24/7 |
| State | Local filesystem | Cloudflare R2 (every 5 min) |
| Access | SSH tunnel or LAN | HTTPS anywhere |
| Auth | GATEWAY_TOKEN | GATEWAY_TOKEN + CF TLS |
| Scaling | 1 instance | Up to N containers |
| Cost | Electricity + API keys | CF containers billing + API keys |

The OpenClaw gateway itself is identical — same config format, same tool capabilities, same channels. Only the hosting layer changes.

---

## R2 Backup / Restore

The Worker runs a cron every 5 minutes that:
1. POSTs to `/api/backup/export` on the container
2. Streams the workspace tarball to R2 at `agents/{AGENT_ID}/workspace.tar.gz`

On container restart (Cloudflare may restart containers during deploys or on low traffic), the Worker detects the container is fresh and pushes the latest R2 backup back before routing real traffic.

> **Note:** The `/api/backup/export` and restore endpoints are implemented inside the openclaw gateway. If your version of openclaw doesn't support these endpoints yet, the backup cron will log a warning but won't break anything — the gateway still runs, just without R2 persistence.

---

## Phase 2: Provisioning API

Phase 2 will add a multi-agent provisioning layer so a single clawworker deployment can spin up named agent instances on demand:

```
POST /admin/agents          — create a new agent (allocate ID, set env vars, start container)
GET  /admin/agents          — list all agents
DELETE /admin/agents/:id    — terminate and archive agent
POST /admin/agents/:id/restore — restore from R2 backup
```

This becomes the backend for the **ClawWallet managed agent** offering — users buy an agent slot, the provisioning API spins up an isolated OpenClaw instance for them.

---

## Credits

- [moltworker](https://github.com/cloudflare/moltworker) — original Cloudflare Containers agent template (Cloudflare × Molt.id / kingbootoshi)
- [OpenClaw](https://openclaw.dev) — the AI agent gateway running inside the container
- [Cloudflare Containers](https://developers.cloudflare.com/containers/) — the serverless container runtime
