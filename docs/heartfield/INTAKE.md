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

# HeartField.ai Adjacent Surface Intake

## Owner and accountable maintainer

Owner: EXOCHAIN Foundation.

Accountable maintainer: Bob Stewart until a formal maintainer delegation is
recorded through the normal governance process.

## Deployment status

Status: `prototype`.

This repository change scaffolds documentation only. No production application,
hosting target, database, secrets, background jobs, auth provider, or EXOCHAIN
runtime adapter is introduced here.

## Allowed EXOCHAIN constitutional trust claims

None until a tested runtime adapter exists.

HeartField.ai may describe Constitutional Computing, uplifting self-governance,
and EXOCHAIN-adjacent doctrine. It must not claim EXOCHAIN constitutional
enforcement, consent verification, authority adjudication, provenance issuance,
or governance finality until a tested core call path exists and this intake is
updated.

## Core state read/write access

No direct read or write access to EXOCHAIN core state.

This scaffold does not read or write signatures, credentials, governance
outcomes, consent records, provenance records, tenant data, DAG state, validator
state, or EXOCHAIN deployment configuration.

## Exact trust boundary

HeartField.ai is a public movement and education surface. EXOCHAIN core remains
the constitutional trust fabric. The boundary is crossed only by a future
runtime adapter that:

- calls owned EXOCHAIN core APIs;
- has tests proving fail-closed behavior on core rejection, timeout, and
  unavailability;
- does not cache or simulate core trust decisions;
- has a separate secrets scope and rollback path.

## Surface-specific test command and CI gate

Test command:

```bash
bash tools/test_heartfield_adjacent_intake.sh
```

CI gate: repository hygiene / documentation guard until a runtime surface is
introduced. A future application must add its own build, test, lint, and
deployment gate before claiming production readiness.

## Secrets inventory and runtime configuration source

Current scaffold secrets: none.

Current runtime configuration: none.

Future deployments must inventory DNS, hosting, analytics, email, CRM, auth,
database, signing, and EXOCHAIN adapter credentials before launch. Missing or
malformed required secrets must fail closed.

## Rollback or disablement path

Current rollback: revert the documentation PR.

Future deployment rollback must include:

- disable or redirect HeartField.ai DNS/hosting;
- revoke any surface-specific secrets;
- disable any EXOCHAIN adapter route;
- remove unsupported trust claims from public copy;
- preserve incident evidence for adjudication.
