#!/usr/bin/env bash
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

set -euo pipefail
cd "$(dirname "$0")/.."

# This is a source routing contract, not proof of GitHub permissions, human
# approval, or enforcement of the separate human review and audit policy.
python3 -B - <<'PY'
from pathlib import Path

maintainers = ("@bob-stewart", "@mstewartbz", "@robst3w")
# Preserve the complete original precedence order. A later rule replaces, not
# augments, an earlier rule; existing security/compliance paths remain explicit.
expected = [
    ("*", maintainers),
    ("/crates/", maintainers),
    ("/crates/exo-core/src/crypto.rs", maintainers),
    ("/crates/exo-identity/", maintainers),
    ("/crates/exo-proofs/", maintainers),
    ("/crates/exo-governance/", maintainers),
    ("/crates/decision-forum/", maintainers),
    ("/governance/", maintainers),
    ("/crates/exo-legal/", maintainers),
    ("/crates/exo-consent/", maintainers),
    ("/TERMS-CONDITIONS-AND-PRIVACY.md", maintainers),
    ("/demo/", maintainers),
    ("/demo/infra/", maintainers),
    ("/.github/workflows/", maintainers),
    ("/Dockerfile", maintainers),
    ("/docker-compose.yml", maintainers),
    ("/docs/", maintainers),
    ("/docs/council/", maintainers),
    ("/EXOCHAIN_Specification_v2.2.pdf", maintainers),
    ("/CONTRIBUTING.md", maintainers),
]


def validate(source):
    rules = []
    for line in source.splitlines():
        fields = line.split("#", 1)[0].split()
        if fields:
            rules.append((fields[0], tuple(fields[1:])))
    if rules != expected:
        raise ValueError(
            "CODEOWNERS routing differs from the reviewed beta contract: "
            "retain explicit area paths and rule precedence; route reviews "
            "only to bob-stewart, mstewartbz, and robst3w"
        )


source = Path(".github/CODEOWNERS").read_text()
validate(source)

# Deliberate negative inputs must be rejected; no fixture claims live authority.
mutations = {
    "remove Robert": source.replace(" @robst3w", "", 1),
    "misspell Max": source.replace("@mstewartbz", "@mstewart", 1),
    "unknown delegate": source.replace("@robst3w", "@unreviewed-delegate", 1),
    "duplicate actor": source.replace("@robst3w", "@mstewartbz", 1),
    "stale panel": source.replace(" ".join(maintainers), "@exochain/architecture", 1),
    "stale Security team": source.replace(
        "/crates/exo-proofs/ " + " ".join(maintainers),
        "/crates/exo-proofs/ @exochain/security",
    ),
    "stale Legal team": source.replace(
        "/crates/exo-legal/ " + " ".join(maintainers),
        "/crates/exo-legal/ @exochain/legal",
    ),
    "override specialists": source + "\n* " + " ".join(maintainers) + "\n",
    "ownerless override": source + "\n/crates/exo-proofs/\n",
    "remove CI routing": "\n".join(
        line for line in source.splitlines() if not line.startswith("/.github/workflows/")
    ),
    "reorder specific rule": "\n".join(reversed(source.splitlines())),
}
for name, mutated in mutations.items():
    try:
        validate(mutated)
    except ValueError:
        continue
    raise SystemExit(f"beta CODEOWNERS negative case unexpectedly accepted: {name}")

print(f"beta CODEOWNERS routing contract passed; {len(mutations)} negative cases rejected")
PY
