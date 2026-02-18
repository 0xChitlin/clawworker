/**
 * clawworker — CF Worker (GCP proxy mode)
 *
 * Free-tier compatible. Proxies HTTP + WebSocket to a GCP VM running OpenClaw.
 * No Container binding, no R2 — just fetch() to the backend.
 *
 * Architecture:
 *   Internet → CF Worker (auth + routing) → GCP VM (nginx + PM2 agents)
 *
 * Env vars (set via wrangler secret put or wrangler.toml [vars]):
 *   GCP_HOST          — e.g. "35.188.22.105"
 *   AGENT_PORT        — e.g. "4001" (PM2 port for this agent on GCP)
 *   GATEWAY_TOKEN     — Bearer token clients must send
 *   ADMIN_TOKEN       — Bearer token for /admin routes
 *   AGENT_ID          — e.g. "agent-001"
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'

interface Env {
  GCP_HOST: string      // IP or hostname of GCP VM (no protocol, no trailing slash)
  AGENT_PORT: string    // Port the OpenClaw gateway is running on for this agent
  GATEWAY_TOKEN: string
  ADMIN_TOKEN: string
  AGENT_ID: string
}

const app = new Hono<{ Bindings: Env }>()

app.use('*', cors())

// ── Helpers ───────────────────────────────────────────────────────────────────

function getBackendBase(env: Env): string {
  const host = env.GCP_HOST || '35.188.22.105'
  const port = env.AGENT_PORT || '4001'
  return `http://${host}:${port}`
}

function checkAuth(env: Env, req: Request): Response | null {
  const token = env.GATEWAY_TOKEN
  if (!token) return null // dev mode — no auth configured
  const auth = req.headers.get('Authorization') ?? ''
  const [scheme, provided] = auth.split(' ')
  if (scheme !== 'Bearer' || provided !== token) {
    return Response.json(
      { error: 'Unauthorized', hint: 'Authorization: Bearer <GATEWAY_TOKEN>' },
      { status: 401 }
    )
  }
  return null
}

// ── Health (no auth) ──────────────────────────────────────────────────────────

app.get('/health', async (c) => {
  const base = getBackendBase(c.env)
  let backendOk = false
  let backendMs = 0
  try {
    const t0 = Date.now()
    const r = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(3000) })
    backendMs = Date.now() - t0
    backendOk = r.status < 500
  } catch { /* backend down */ }

  return c.json({
    status: 'ok',
    agentId: c.env.AGENT_ID || 'default',
    backend: backendOk ? 'reachable' : 'unreachable',
    backendMs,
    backendUrl: `${base}/api/health`,
    ts: new Date().toISOString(),
  })
})

// ── API proxy (authenticated) ─────────────────────────────────────────────────

app.all('/api/*', async (c) => {
  const err = checkAuth(c.env, c.req.raw)
  if (err) return err

  const base = getBackendBase(c.env)
  const inUrl = new URL(c.req.url)
  const target = `${base}${inUrl.pathname}${inUrl.search}`

  try {
    const resp = await fetch(target, {
      method: c.req.method,
      headers: c.req.raw.headers,
      body: c.req.raw.body,
      signal: AbortSignal.timeout(30000),
    })
    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    })
  } catch (err) {
    return c.json({ error: 'Backend unavailable', detail: String(err) }, 503)
  }
})

// ── WebSocket relay (authenticated) ──────────────────────────────────────────

app.get('/ws', async (c) => {
  const upgrade = c.req.header('Upgrade')
  if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
    return c.text('Expected WebSocket upgrade', 426)
  }

  // Auth: token from query param or header (WS clients can't always set headers)
  const queryToken = new URL(c.req.url).searchParams.get('token') ?? ''
  const headerToken = (c.req.header('Authorization') ?? '').replace('Bearer ', '')
  const token = headerToken || queryToken
  if (c.env.GATEWAY_TOKEN && token !== c.env.GATEWAY_TOKEN) {
    return c.text('Unauthorized', 401)
  }

  const base = getBackendBase(c.env).replace('http://', 'ws://')
  const { 0: client, 1: server } = new WebSocketPair()

  server.accept()

  // Connect to GCP backend WebSocket
  const backendWs = new WebSocket(`${base}/ws`)

  backendWs.addEventListener('message', (e) => server.send(e.data))
  backendWs.addEventListener('close', () => server.close())
  backendWs.addEventListener('error', () => server.close(1011, 'Backend error'))

  server.addEventListener('message', (e) => {
    if (backendWs.readyState === WebSocket.OPEN) backendWs.send(e.data)
  })
  server.addEventListener('close', () => backendWs.close())

  return new Response(null, { status: 101, webSocket: client })
})

// ── Admin ─────────────────────────────────────────────────────────────────────

app.get('/admin', async (c) => {
  const adminToken = c.env.ADMIN_TOKEN
  if (adminToken) {
    const provided = (c.req.header('Authorization') ?? '').replace('Bearer ', '')
    if (provided !== adminToken) return c.text('Forbidden', 403)
  }
  return c.json({
    worker: 'clawworker',
    mode: 'gcp-proxy',
    agentId: c.env.AGENT_ID,
    backend: getBackendBase(c.env),
  })
})

export default { fetch: app.fetch }
