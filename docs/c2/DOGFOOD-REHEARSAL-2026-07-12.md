<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Mission C2 Dogfood Rehearsal — 2026-07-12

**Status:** Partial (machine rehearsal complete; human dual-gate on a live GAP item still required)  
**Operators:** Bob (`bob-stewart`), Max (`mstewartbz`)  
**Branch / PR:** `cursor/cloud-agent-1783858638696-q6upw` / #791

## Slice executed

1. Doctrine + nodes present under `docs/c2/` (dagdb-memory, proof-verification, platform-release included).
2. Machine AI-IRB rehearsal via `cargo test -p exochain-consensus --test presidential_c2_bridge --features providers`:
   - Strategic panel with xAI/OpenAI/Anthropic/Google seats
   - Devil’s advocate review present
   - Advisory receipts bound; dissent receipt required
   - AI-IRB approve alone **fails** two-person gate
   - Bob + Max verified human Approves **pass** two-person gate
3. CCIR noise check (paper): routine ExoForge heuristic panels and doc-only PRs classified **non-CCIR** (no push).

## Outcomes / CCIR calibration notes

| Signal | Push? | Notes |
|--------|-------|-------|
| Constitutional dual-gate incomplete | Yes (CCIR) | Keep |
| AI-IRB dissent present with empty evidence | No (fail closed off brief) | Keep |
| Routine task completion | No | Keep |
| Railway health fail after promote | Yes (CCIR) | Keep |

## Live item prepared for dual gate

Binding worksheet: [DOGFOOD-LIVE-ITEM-PUSH-ENABLEMENT.md](DOGFOOD-LIVE-ITEM-PUSH-ENABLEMENT.md)
(push-enablement ratification; AI-IRB seats + Bob/Max rows still blank).

## Secrets status (2026-07-14)

- **Railway:** `PRESIDENTIAL_SLACK_WEBHOOK_URL`, `PRESIDENTIAL_TWILIO_AUTH_TOKEN`, `PRESIDENTIAL_TWILIO_ACCOUNT_SID`, `PRESIDENTIAL_TWILIO_FROM`, `PRESIDENTIAL_TWILIO_TO` set (names only) on `commandbase-web` production and on `exochain-node` + `livesafe` for development/staging/production. `EXOCHAIN_API_BASE_URL` already present.
- **GitHub Actions:** still blocked for cloud agents (`HTTP 403`); repo admin must set the same `PRESIDENTIAL_*` names.

## Blockers to full dogfood close

- Human Bob+Max attestation on the live item above (not only the automated bridge fixture).
- GitHub Actions secrets still need admin `gh secret set` (see commands below / [SECRETS-ACTIVATION.md](SECRETS-ACTIVATION.md)).

## Push enablement decision

**Do not enable live Slack/SMS push yet.** Remain fail-closed until:

1. PR #791 merged to `main` ✅
2. Secrets configured — Railway ✅ / GitHub ⏳ admin
3. Bob+Max complete one live dual-gate ratify/veto on a real item and update this record to **Complete**

## Required secrets (names only — values must be set by operators)

Operator runbook: [SECRETS-ACTIVATION.md](SECRETS-ACTIVATION.md).

### GitHub Actions (`exochain/exochain`)

- `PRESIDENTIAL_SLACK_WEBHOOK_URL`
- `PRESIDENTIAL_TWILIO_AUTH_TOKEN` (and related Twilio SID/from/to as used by CommandBase)

### Railway (EXOCHAIN / CommandBase services)

- `EXOCHAIN_API_BASE_URL`
- `PRESIDENTIAL_SLACK_WEBHOOK_URL`
- `PRESIDENTIAL_TWILIO_AUTH_TOKEN` (+ Twilio companions)
- Optional: LLM provider keys only after live adapter activation (not required for dogfood close)

## Commands re-run

```bash
bash tools/test_mission_c2_graph.sh
cargo test -p exochain-consensus --test presidential_c2_bridge --features providers
cargo test -p exochain-decision-forum two_person
node --test command-base/app/lib/presidential-desk.test.js
```
