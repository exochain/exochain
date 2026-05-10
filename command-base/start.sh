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
