#!/bin/bash
# ExoChain Demo — Local Development (no Docker)
# Requires: PostgreSQL running locally with database 'exochain'
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEMO_DIR"

: "${DATABASE_URL:?set DATABASE_URL to a PostgreSQL connection string before running demo/scripts/dev.sh}"
export DATABASE_URL

echo "═══════════════════════════════════════════════════════════"
echo "  ExoChain Demo — Starting Services"
echo "═══════════════════════════════════════════════════════════"

# Start services in background
PORT=3000 node services/gateway-api/src/index.js &
PORT=3001 node services/identity-service/src/index.js &
PORT=3002 node services/consent-service/src/index.js &
PORT=3003 node services/governance-engine/src/index.js &
PORT=3004 node services/decision-forge/src/index.js &
PORT=3006 node services/provenance-writer/src/index.js &
PORT=3007 node services/audit-api/src/index.js &

echo ""
echo "Services starting..."
echo "  gateway-api:       http://localhost:3000"
echo "  identity-service:  http://localhost:3001"
echo "  consent-service:   http://localhost:3002"
echo "  governance-engine: http://localhost:3003"
echo "  decision-forge:    http://localhost:3004"
echo "  provenance-writer: http://localhost:3006"
echo "  audit-api:         http://localhost:3007"
echo ""
echo "Press Ctrl+C to stop all services"

trap 'kill $(jobs -p) 2>/dev/null; exit 0' INT TERM
wait
