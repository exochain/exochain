#!/bin/bash
# ── The Team Dashboard — Native Mode ──────────────────────────────
# Run the dashboard natively on the host so spawned `claude` CLI
# processes inherit macOS Keychain auth.
#
# Modes:
#   Native (recommended for terminal auto-spawn): ./start.sh
#   Docker  (for deployment/portability):         docker compose up -d
#
# Why native? Docker containers cannot access the macOS Keychain,
# so `claude -p` inside Docker fails with "Not logged in".
# Native mode uses the host's Claude CLI directly.
# ──────────────────────────────────────────────────────────────────

cd "$(dirname "$0")/app"

export DB_PATH="../the_team.db"
export INBOX_PATH="../Teams inbox:Result"
export OUTBOX_PATH="../Stew's inbox:Owner"
export PROJECT_ROOT="$(dirname "$0")"
export NODE_ENV=production
export PORT=3000

# Install deps if needed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

echo "Starting The Team dashboard on http://localhost:3000"
echo "Terminal auto-spawn: ENABLED (using host Claude CLI)"
node server.js
