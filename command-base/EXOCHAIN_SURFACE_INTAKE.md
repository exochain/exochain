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

# CommandBase EXOCHAIN Adjacent Surface Intake

- Owner/accountable maintainer: EXOCHAIN operator / CommandBase maintainer.
- Deployment status: internal cockpit adapter.
- Constitutional trust claims: CommandBase may display EXOCHAIN-recorded HonorGood
  and mission-economics objects only when responses come from the configured
  EXOCHAIN API. CommandBase-local governance receipts, review-panel votes, and
  heuristic invariant checks are adjacent audit records and must not be described
  as EXOCHAIN constitutional-kernel enforcement.
- Core state access: read/write through `EXOCHAIN_API_BASE_URL` and optional
  bearer token only.
- Trust boundary: CommandBase never computes authoritative settlements, anchors,
  EXOCHAIN receipts, governance outcomes, consent decisions, authority chains, or
  legal effects. It forwards operator requests to EXOCHAIN and displays EXOCHAIN
  responses. CommandBase-local heuristic checks may write local audit-trail
  records, but they must not extend a trusted EXOCHAIN receipt hash chain.
- Test command: `node --test command-base/app/lib/auth.security.test.js
  command-base/app/auth-bootstrap.test.js command-base/app/services/governance.test.js`.
- Secrets inventory: `EXOCHAIN_API_BASE_URL`; optional `EXOCHAIN_API_TOKEN` and optional
  `EXOCHAIN_AUTH_SECRET` (required if WASM auth backend is unavailable); optional
  `COMMAND_BASE_AUTH_BOOTSTRAP_TOKEN` for non-loopback operator auth bootstrap. Tokens
  are not logged or returned by status routes.
- Rollback/disablement: unset `EXOCHAIN_API_BASE_URL` to force HonorGood cockpit
  actions to fail closed. Disable CommandBase governance automation routes if
  local audit records are mistaken for EXOCHAIN core receipts.
