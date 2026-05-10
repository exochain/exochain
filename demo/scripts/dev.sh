#!/bin/bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# ExoChain Demo — Local Development (no Docker)
# Requires: PostgreSQL running locally with database 'exochain'
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEMO_DIR"

export DATABASE_URL="${DATABASE_URL:-postgres://exochain:exochain_dev@localhost:5432/exochain}"

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
