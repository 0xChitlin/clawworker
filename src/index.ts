/**
 * clawworker — CF Worker
 *
 * Acts as an authenticated HTTP/WebSocket proxy between the internet and the
 * OpenClaw container. Key responsibilities:
 *
 *   1. Auth — validate Bearer token on protected routes
 *   2. Proxy — forward /api/* requests to the container on port 18789
 *   3. WebSocket — relay /ws upgrades to the container
 *   4. R2 backup — cron triggers workspace tar → R2 every 5 minutes
 *   5. Health — /health endpoint (no auth required)
 *
 * Cloudflare Containers (beta) docs:
 *   https://developers.cloudflare.com/containers/
 */

import { Hono } from 'hono'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Env {
  /** Cloudflare Container binding — the running OpenClaw sandbox */
  CONTAINER: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
  }
  /** R2 bucket for workspace backups */
  R2_BUCKET: R2Bucket
  /** Unique agent identifier (e.g. "agent-001") */
  AGENT_ID: string
  /** Bearer token required to access /api/* and /ws routes */
  GATEWAY_TOKEN: string
  /** Admin token for management operations */
  ADMIN_TOKEN: string
}

// Container port (must match EXPOSE in Dockerfile and start-openclaw.sh)
const CONTAINER_PORT = 18789

// ── App ───────────────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Env }>()

// ── Middleware: Auth ──────────────────────────────────────────────────────────

/**
 * Validates Bearer token on protected routes.
 * Returns 401 if missing or invalid.
 */
function authMiddleware(env: Env, req: Request): Response | null {
  const token = env.GATEWAY_TOKEN
  if (!token) return null // No token configured — allow all (dev mode)

  const authHeader = req.headers.get('Authorization') ?? ''
  const [scheme, provided] = authHeader.split(' ')
  if (scheme !== 'Bearer' || provided !== token) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized', hint: 'Provide Authorization: Bearer <GATEWAY_TOKEN>' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    )
  }
  return null
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * GET /health — quick liveness check (no auth required).
 * Returns agent metadata and container status.
 */
app.get('/health', async (c) => {
  let containerOk = false
  try {
    const resp = await c.env.CONTAINER.fetch(`http://localhost:${CONTAINER_PORT}/api/health`)
    containerOk = resp.status < 500
  } catch {
    containerOk = false
  }

  return c.json({
    status: 'ok',
    agentId: c.env.AGENT_ID,
    containerReachable: containerOk,
    ts: new Date().toISOString(),
  })
})

/**
 * ALL /api/* — authenticated proxy to the OpenClaw gateway HTTP API.
 *
 * The openclaw gateway exposes its own REST API on port 18789.
 * All paths under /api/ are forwarded verbatim.
 */
app.all('/api/*', async (c) => {
  const authErr = authMiddleware(c.env, c.req.raw)
  if (authErr) return authErr

  // Build the target URL — replace host:port with container's localhost
  const incomingUrl = new URL(c.req.url)
  const targetUrl = new URL(incomingUrl.pathname + incomingUrl.search, `http://localhost:${CONTAINER_PORT}`)

  try {
    const resp = await c.env.CONTAINER.fetch(targetUrl.toString(), {
      method: c.req.method,
      headers: c.req.raw.headers,
      body: c.req.raw.body,
    })

    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    })
  } catch (err) {
    console.error('[clawworker] Container fetch failed:', err)
    return c.json(
      { error: 'Container unavailable', detail: String(err), agentId: c.env.AGENT_ID },
      503
    )
  }
})

/**
 * GET /ws — WebSocket upgrade relay to the OpenClaw container.
 *
 * The openclaw gateway supports WebSocket connections for real-time
 * chat and event streaming. This route upgrades and relays the WS to the
 * container's gateway endpoint.
 *
 * Auth: GATEWAY_TOKEN required (passed as ?token= query param or
 * Authorization header — openclaw gateway handles token validation
 * inside the container too).
 */
app.get('/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade')
  if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
    return c.text('Expected WebSocket upgrade', 426)
  }

  // Auth check — token can come from query param for WS clients that can't set headers
  const queryToken = new URL(c.req.url).searchParams.get('token') ?? ''
  const authHeader = c.req.header('Authorization') ?? ''
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : queryToken

  const expectedToken = c.env.GATEWAY_TOKEN
  if (expectedToken && bearerToken !== expectedToken) {
    return c.text('Unauthorized', 401)
  }

  // Forward the WebSocket upgrade to the container
  try {
    const targetUrl = `ws://localhost:${CONTAINER_PORT}/ws`
    const wsReq = new Request(targetUrl, c.req.raw)
    return c.env.CONTAINER.fetch(wsReq)
  } catch (err) {
    console.error('[clawworker] WebSocket relay failed:', err)
    return c.text(`Container WebSocket unavailable: ${String(err)}`, 503)
  }
})

/**
 * GET /admin — Admin panel (protected by ADMIN_TOKEN).
 * Phase 1: basic status page.
 * Phase 2: provisioning API for multi-agent management.
 */
app.get('/admin', async (c) => {
  const adminToken = c.env.ADMIN_TOKEN
  if (adminToken) {
    const provided = (c.req.header('Authorization') ?? '').replace('Bearer ', '')
    if (provided !== adminToken) {
      return c.text('Forbidden', 403)
    }
  }

  return c.json({
    worker: 'clawworker',
    agentId: c.env.AGENT_ID,
    containerPort: CONTAINER_PORT,
    uptime: Date.now(),
    phase: 1,
  })
})

// ── Cron: R2 Backup ───────────────────────────────────────────────────────────

/**
 * Scheduled cron handler — runs every 5 minutes (configured in wrangler.toml).
 *
 * Strategy:
 *   1. Ask the container to tar its workspace (/root/clawd)
 *   2. Stream the response body into R2 as agent-{id}/workspace.tar.gz
 *   3. Log success/failure
 *
 * The restore flow (triggered by the Worker on first /api or /ws request after
 * a container restart) reverses this: download tar from R2, POST it to the
 * container's /restore endpoint.
 *
 * Note: Cloudflare Containers are ephemeral — the workspace is lost on restart
 * unless backed up. This cron is the persistence layer.
 */
async function handleBackupCron(env: Env): Promise<void> {
  const agentId = env.AGENT_ID || 'default'
  const r2Key = `agents/${agentId}/workspace.tar.gz`

  console.log(`[clawworker] Cron: backing up workspace for agent ${agentId}...`)

  try {
    // Ask the container to generate a tar of its workspace
    const resp = await env.CONTAINER.fetch(
      `http://localhost:${CONTAINER_PORT}/api/backup/export`,
      { method: 'POST', headers: { Authorization: `Bearer ${env.GATEWAY_TOKEN}` } }
    )

    if (!resp.ok) {
      console.warn(`[clawworker] Backup: container returned ${resp.status}`)
      return
    }

    // Store in R2
    await env.R2_BUCKET.put(r2Key, resp.body, {
      httpMetadata: { contentType: 'application/gzip' },
      customMetadata: { agentId, ts: new Date().toISOString() },
    })

    console.log(`[clawworker] Backup: saved ${r2Key}`)
  } catch (err) {
    console.error('[clawworker] Backup failed:', err)
  }
}

// ── Default export ────────────────────────────────────────────────────────────

export default {
  fetch: app.fetch,

  /**
   * Scheduled handler — wired to cron triggers in wrangler.toml.
   */
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(handleBackupCron(env))
  },
}
