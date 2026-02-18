# clawworker

Cloudflare Worker that proxies HTTP + WebSocket to an OpenClaw agent.

Two modes:
- **GCP proxy** (free tier) — proxies to a GCP VM running OpenClaw. No paid CF features needed.
- **CF Containers** (paid, beta) — runs OpenClaw in a Cloudflare Container sandbox.

This repo ships in **GCP proxy mode** by default.

---

## Deploy (Free Tier — GCP Proxy)

### 1. Install Wrangler
```bash
npm install -g wrangler
wrangler login
```

### 2. Clone and install
```bash
git clone https://github.com/0xChitlin/clawworker
cd clawworker
npm install
```

### 3. Set secrets
```bash
wrangler secret put GATEWAY_TOKEN   # token clients use to auth
wrangler secret put ADMIN_TOKEN     # token for /admin route
```

### 4. Set GCP target in wrangler.toml
```toml
[vars]
GCP_HOST = "YOUR_GCP_VM_IP"
AGENT_PORT = "80"       # or the specific PM2 port for this agent
AGENT_ID = "agent-001"
```

### 5. Deploy
```bash
wrangler deploy
```

Your Worker is live at `clawworker.<your-subdomain>.workers.dev`.

---

## Routes

| Route | Auth | Description |
|---|---|---|
| `GET /health` | None | Liveness check + backend ping |
| `ALL /api/*` | Bearer token | Proxy to OpenClaw API |
| `GET /ws` | Bearer token or `?token=` | WebSocket relay |
| `GET /admin` | Admin token | Worker status |

---

## Local Dev

```bash
cp .dev.vars.example .dev.vars
# edit .dev.vars with your values
wrangler dev
```

---

## Upgrade to CF Containers (later)

When you want to move off GCP and run OpenClaw serverlessly on Cloudflare:
1. Upgrade Cloudflare account to Workers Paid ($5/mo)
2. Request Containers beta access
3. Swap `src/index.ts` back to the Container version (see git history)
4. Deploy with `wrangler deploy`

---

## Stack

- [Hono](https://hono.dev) — Worker framework
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) — CF deploy tool
- [OpenClaw](https://github.com/openclaw/openclaw) — Agent runtime
