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
import { keccak_256 } from '@noble/hashes/sha3.js'

interface Env {
  GCP_HOST: string      // IP or hostname of GCP VM (no protocol, no trailing slash)
  AGENT_PORT: string    // Port the OpenClaw gateway is running on for this agent
  GATEWAY_TOKEN: string
  ADMIN_TOKEN: string
  AGENT_ID: string
}

const app = new Hono<{ Bindings: Env }>()

app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}))

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

// ── SIWE Helpers ──────────────────────────────────────────────────────────────

/** base64url encode (no padding) */
function base64urlEncode(buf: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...buf))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/** base64url decode */
function base64urlDecode(str: string): Uint8Array {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, '=')
  const bin = atob(padded)
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)))
}

/** HMAC-SHA256 → returns raw bytes */
async function hmacSign(keyStr: string, data: string): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', keyMaterial, enc.encode(data))
  return new Uint8Array(sig)
}

/** HMAC-SHA256 → returns base64url string */
async function hmacSignB64(keyStr: string, data: string): Promise<string> {
  return base64urlEncode(await hmacSign(keyStr, data))
}

/** Verify HMAC-SHA256 */
async function hmacVerify(keyStr: string, data: string, expected: string): Promise<boolean> {
  const actual = await hmacSignB64(keyStr, data)
  // constant-time compare
  if (actual.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

/** Create HS256 JWT */
async function createJWT(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const enc = new TextEncoder()
  const headerB64 = base64urlEncode(enc.encode(JSON.stringify(header)))
  const payloadB64 = base64urlEncode(enc.encode(JSON.stringify(payload)))
  const sigInput = `${headerB64}.${payloadB64}`
  const sigBytes = await hmacSign(secret, sigInput)
  return `${sigInput}.${base64urlEncode(sigBytes)}`
}

/** Decode JWT payload without verifying (for expiry check on client) */
function decodeJWTPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    return JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])))
  } catch { return null }
}

/** hex string → Uint8Array */
function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  const result = new Uint8Array(h.length / 2)
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  }
  return result
}

/** Uint8Array → hex string (no 0x prefix) */
function bytesToHex(buf: Uint8Array): string {
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Pad uint256 to 32 bytes */
function abiEncodeUint256(n: bigint): string {
  return n.toString(16).padStart(64, '0')
}

/**
 * ABI-encode an isValidSignature(bytes32 hash, bytes sig) call.
 * Returns the full calldata hex (no 0x prefix).
 */
function encodeIsValidSignatureCall(hash: Uint8Array, sig: Uint8Array): string {
  const selector = '1626ba7e'
  // bytes32 hash: 32 bytes value
  const hashHex = bytesToHex(hash).padStart(64, '0')
  // offset to bytes data: starts at position 64 (2 * 32 bytes head)
  const offset = abiEncodeUint256(64n)
  // length of sig
  const sigLen = abiEncodeUint256(BigInt(sig.length))
  // sig data padded to 32 bytes
  const sigHex = bytesToHex(sig)
  const paddedSigHex = sigHex.padEnd(Math.ceil(sig.length / 32) * 64, '0')
  return selector + hashHex + offset + sigLen + paddedSigHex
}

/**
 * Compute keccak256 of a UTF-8 string (returns Uint8Array)
 */
function keccak256Str(msg: string): Uint8Array {
  return keccak_256(new TextEncoder().encode(msg))
}

/**
 * Compute Ethereum personal_sign hash:
 * keccak256("\x19Ethereum Signed Message:\n" + len + message)
 */
function ethereumHashMessage(message: string): Uint8Array {
  const msgBytes = new TextEncoder().encode(message)
  const prefix = `\x19Ethereum Signed Message:\n${msgBytes.length}`
  const prefixBytes = new TextEncoder().encode(prefix)
  const combined = new Uint8Array(prefixBytes.length + msgBytes.length)
  combined.set(prefixBytes)
  combined.set(msgBytes, prefixBytes.length)
  return keccak_256(combined)
}

/**
 * Call isValidSignature on the Abstract mainnet contract.
 * Returns true if the contract returns the ERC-1271 magic value.
 */
async function erc1271Verify(address: string, message: string, signature: string): Promise<boolean> {
  try {
    const hash = ethereumHashMessage(message)
    const sigBytes = hexToBytes(signature)
    const calldata = encodeIsValidSignatureCall(hash, sigBytes)

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_call',
      params: [{ to: address, data: '0x' + calldata }, 'latest'],
      id: 1,
    })

    const resp = await fetch('https://api.mainnet.abs.xyz', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: AbortSignal.timeout(10000),
    })

    if (!resp.ok) return false
    const json = await resp.json() as { result?: string; error?: unknown }
    if (!json.result) return false

    // Return value is ABI-encoded bytes4 in a 32-byte slot
    // Magic value: 0x1626ba7e -> as 32-byte ABI result: 1626ba7e000...000
    const result = json.result.toLowerCase().replace('0x', '')
    return result.startsWith('1626ba7e')
  } catch (e) {
    console.error('ERC-1271 verify failed:', e)
    return false
  }
}

/**
 * Parse key fields from a SIWE message string.
 * Format (EIP-4361):
 *   {domain} wants you to sign in with your Ethereum account:\n
 *   {address}\n
 *   \n
 *   {statement}\n    ← optional
 *   \n
 *   URI: {uri}\n
 *   Version: {version}\n
 *   Chain ID: {chainId}\n
 *   Nonce: {nonce}\n
 *   Issued At: {issuedAt}\n
 *   ...
 */
function parseSiweMessage(message: string): {
  domain: string
  address: string
  nonce: string
  chainId: number
  issuedAt: string
} | null {
  try {
    const lines = message.split('\n')
    // Line 0: "{domain} wants you to sign in..."
    const domainMatch = lines[0].match(/^(.+) wants you to sign in with your Ethereum account:$/)
    const domain = domainMatch ? domainMatch[1] : ''
    // Line 1: address
    const address = lines[1]?.trim() ?? ''
    // Find fields
    const getField = (key: string): string => {
      const line = lines.find(l => l.startsWith(key + ': '))
      return line ? line.slice(key.length + 2).trim() : ''
    }
    const nonce = getField('Nonce')
    const chainIdStr = getField('Chain ID')
    const issuedAt = getField('Issued At')
    const chainId = parseInt(chainIdStr, 10)
    if (!domain || !address || !nonce || !chainId || !issuedAt) return null
    return { domain, address, nonce, chainId, issuedAt }
  } catch { return null }
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

// ── SIWE: GET /auth/nonce ─────────────────────────────────────────────────────

app.get('/auth/nonce', async (c) => {
  const address = c.req.query('address')?.toLowerCase() ?? ''
  if (!address || !address.startsWith('0x')) {
    return c.json({ error: 'Missing or invalid address parameter' }, 400)
  }

  const secret = c.env.GATEWAY_TOKEN
  if (!secret) return c.json({ error: 'Auth not configured' }, 500)

  // Generate random nonce
  const randomBytes = new Uint8Array(16)
  crypto.getRandomValues(randomBytes)
  const nonce = base64urlEncode(randomBytes)

  const expiresAt = Math.floor(Date.now() / 1000) + 300 // 5 minutes

  // HMAC sign: nonce:address:expiresAt
  const hmacData = `${nonce}:${address}:${expiresAt}`
  const hmac = await hmacSignB64(secret, hmacData)
  // nonceToken = {nonce}.{expiresAt}.{hmac}  — 3-part stateless token
  const nonceToken = `${nonce}.${expiresAt}.${hmac}`

  return c.json({ nonceToken, nonce, expiresAt })
})

// ── SIWE: POST /auth/verify ───────────────────────────────────────────────────

app.post('/auth/verify', async (c) => {
  const secret = c.env.GATEWAY_TOKEN
  if (!secret) return c.json({ error: 'Auth not configured' }, 500)

  let body: { message?: string; signature?: string; address?: string; nonceToken?: string }
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  const { message, signature, address, nonceToken } = body
  if (!message || !signature || !address || !nonceToken) {
    return c.json({ error: 'Missing required fields: message, signature, address, nonceToken' }, 400)
  }

  // ── 1. Verify nonceToken ──────────────────────────────────────────────────
  // nonceToken format: {nonce}.{expiresAt}.{hmac}  (3-part, matching /auth/nonce output)

  const parts = nonceToken.split('.')
  if (parts.length < 3) {
    return c.json({ error: 'Invalid nonceToken: expected nonce.expiresAt.hmac format' }, 400)
  }
  const nonceVal = parts[0]
  const expiresAtStr = parts[1]
  const hmacVal = parts.slice(2).join('.')

  const expiresAt = parseInt(expiresAtStr, 10)
  if (isNaN(expiresAt)) return c.json({ error: 'Invalid nonceToken: bad expiresAt' }, 400)
  if (Math.floor(Date.now() / 1000) > expiresAt) {
    return c.json({ error: 'Nonce expired. Please request a new one.' }, 401)
  }

  const hmacData = `${nonceVal}:${address.toLowerCase()}:${expiresAt}`
  const validHmac = await hmacVerify(secret, hmacData, hmacVal)
  if (!validHmac) return c.json({ error: 'Invalid nonceToken signature' }, 401)

  // ── 2. Parse SIWE message ─────────────────────────────────────────────────

  const siwe = parseSiweMessage(message)
  if (!siwe) return c.json({ error: 'Failed to parse SIWE message' }, 400)

  // ── 3. Verify nonce matches ───────────────────────────────────────────────

  if (siwe.nonce !== nonceVal) {
    return c.json({ error: 'Nonce mismatch: message nonce does not match token' }, 401)
  }

  // ── 4. Verify address matches ─────────────────────────────────────────────

  if (siwe.address.toLowerCase() !== address.toLowerCase()) {
    return c.json({ error: 'Address mismatch' }, 401)
  }

  // ── 5. Verify chain ───────────────────────────────────────────────────────

  if (siwe.chainId !== 2741) {
    return c.json({ error: `Wrong chain. Expected 2741 (Abstract), got ${siwe.chainId}` }, 401)
  }

  // ── 6. Verify signature via ERC-1271 ─────────────────────────────────────

  const sigValid = await erc1271Verify(address, message, signature)
  if (!sigValid) {
    return c.json({ error: 'Signature verification failed (ERC-1271)' }, 401)
  }

  // ── 7. Issue JWT ──────────────────────────────────────────────────────────

  const now = Math.floor(Date.now() / 1000)
  const jwtPayload = {
    sub: address.toLowerCase(),
    iat: now,
    exp: now + 7 * 24 * 60 * 60, // 7 days
    chainId: 2741,
  }
  const token = await createJWT(jwtPayload, secret)

  return c.json({
    token,
    address: address.toLowerCase(),
    expiresAt: jwtPayload.exp,
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
