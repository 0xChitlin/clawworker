#!/bin/bash
# start-openclaw.sh — Container entrypoint for clawworker
# Generates openclaw config from env vars, then starts the gateway.
set -e

WORKSPACE="/root/clawd"
CONFIG_FILE="$WORKSPACE/openclaw.json"
LOCK_FILE="/tmp/openclaw.lock"
PORT=${OPENCLAW_GATEWAY_PORT:-18789}

echo "[clawworker] Starting OpenClaw container..."
echo "[clawworker] Port: $PORT | Agent: ${AGENT_ID:-default} | Model: ${MODEL:-anthropic/claude-sonnet-4-6}"

# ── Prevent duplicate starts ──────────────────────────────────────────────────
if [ -f "$LOCK_FILE" ]; then
  echo "[clawworker] Lock file found — already running. Exiting."
  exit 0
fi
touch "$LOCK_FILE"

# Ensure workspace exists
mkdir -p "$WORKSPACE"

# ── R2 restore (if available) ─────────────────────────────────────────────────
# On first boot or after a container restart, the Worker will push workspace
# files from R2 to the container via the /api/restore endpoint BEFORE the
# gateway is fully alive. The Worker triggers this on the first connection.
# Nothing to do here — we just start up and wait for the Worker to push.
if [ -n "$R2_BUCKET" ] && [ -n "$AGENT_ID" ]; then
  echo "[clawworker] R2 backup enabled for agent '$AGENT_ID' (restore handled by Worker on connect)"
fi

# ── Generate openclaw config ──────────────────────────────────────────────────
echo "[clawworker] Generating openclaw config from environment..."
node /root/config-template.js > "$CONFIG_FILE"
echo "[clawworker] Config written to $CONFIG_FILE"

if [ "${DEBUG_CONFIG:-0}" = "1" ]; then
  # Redact secrets before printing
  echo "[clawworker] Config (redacted):"
  cat "$CONFIG_FILE" | sed 's/"[A-Za-z]*[Kk]ey": "[^"]*"/"[REDACTED]"/g' \
                     | sed 's/"[Tt]oken": "[^"]*"/"[REDACTED]"/g'
fi

# ── Start OpenClaw gateway ────────────────────────────────────────────────────
echo "[clawworker] Starting openclaw gateway on port $PORT..."
cd "$WORKSPACE"
exec openclaw gateway \
  --port "$PORT" \
  --bind lan \
  --verbose \
  --allow-unconfigured \
  --config "$CONFIG_FILE"
