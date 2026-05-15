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

# EXOCHAIN Demo Surface Intake

Owner and accountable maintainer: EXOCHAIN Foundation demo maintainers.

Deployment status: `prototype`.

Constitutional trust claims: The demo surface is not allowed to claim
constitutional enforcement. It may demonstrate data shapes, API ergonomics, and
local WASM helpers, but it is not the canonical EXOCHAIN trust fabric.

Core state access: The demo surface must not read or write production EXOCHAIN
core state, production signatures, production credentials, governance outcomes,
consent records, authority records, provenance records, or tenant data. Demo
services may use local prototype PostgreSQL state only through an explicit
runtime `DATABASE_URL`.

Trust boundary: `demo/` is adjacent surface code. Calls into
`@exochain/exochain-wasm` are local helper calls and do not create authority,
consent, provenance, or governance outcomes unless a separate verified core
runtime adapter adjudicates the action.

Surface-specific test command:

```bash
bash tools/test_demo_shared_secret_boundaries.sh
```

CI gate: `.github/workflows/ci.yml` Gate 9 (`Demo shared secret boundary`).

Secrets inventory and configuration source:

| Secret or config | Source | Rule |
| --- | --- | --- |
| `DATABASE_URL` | Runtime environment or local `.env` ignored by Git | Required for shared demo DB pool creation; no hardcoded fallback. |
| `GOVERNANCE_API_TOKEN` | Runtime environment for `demo/services/audit-api` | Missing token fails protected governance writes closed. |

Rollback or disablement path: unset `DATABASE_URL` or stop the demo compose
stack. Shared demo DB access fails closed when `DATABASE_URL` is missing or
blank, so disabling the surface does not require touching EXOCHAIN core runtime
state.
