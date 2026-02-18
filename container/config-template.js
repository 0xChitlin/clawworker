#!/usr/bin/env node
/**
 * config-template.js — Generates openclaw.json from environment variables.
 *
 * Called at container startup by start-openclaw.sh.
 * Outputs JSON to stdout — redirected to /root/clawd/openclaw.json.
 *
 * All configuration is driven by env vars injected by Cloudflare Containers
 * (via wrangler.toml [vars] and .dev.vars secrets).
 */

const config = {
  // LLM model — override with MODEL env var
  model: process.env.MODEL || "anthropic/claude-sonnet-4-6",

  // Channels — populated below based on what env vars are present
  channels: [],

  // Workspace path inside the container
  workspace: "/root/clawd",
};

// ── Telegram channel ──────────────────────────────────────────────────────────
if (process.env.TELEGRAM_BOT_TOKEN) {
  const telegramChannel = {
    kind: "telegram",
    token: process.env.TELEGRAM_BOT_TOKEN,
  };
  if (process.env.TELEGRAM_CHAT_ID) {
    telegramChannel.defaultChatId = process.env.TELEGRAM_CHAT_ID;
  }
  config.channels.push(telegramChannel);
}

// ── LLM provider API keys ─────────────────────────────────────────────────────
if (process.env.ANTHROPIC_API_KEY) {
  config.anthropicApiKey = process.env.ANTHROPIC_API_KEY;
}
if (process.env.OPENAI_API_KEY) {
  config.openaiApiKey = process.env.OPENAI_API_KEY;
}
if (process.env.BRAVE_API_KEY) {
  config.braveApiKey = process.env.BRAVE_API_KEY;
}

// ── Gateway auth token ─────────────────────────────────────────────────────────
// Used to authenticate requests to the openclaw gateway HTTP API.
// The CF Worker passes GATEWAY_TOKEN as a Bearer header when proxying.
if (process.env.GATEWAY_TOKEN) {
  config.gatewayToken = process.env.GATEWAY_TOKEN;
}

// ── Agent identity ─────────────────────────────────────────────────────────────
if (process.env.AGENT_NAME) {
  config.agentName = process.env.AGENT_NAME;
}

// ── Optional: Brave Search ─────────────────────────────────────────────────────
// config.braveApiKey is already set above if BRAVE_API_KEY is present

// ── Emit JSON ─────────────────────────────────────────────────────────────────
process.stdout.write(JSON.stringify(config, null, 2) + "\n");
