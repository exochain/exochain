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

fail() {
  printf 'release SBOM boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
ci_workflow=".github/workflows/ci.yml"

[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

sbom_block=$(job_block "sbom-and-attest")
[[ -n "$sbom_block" ]] || fail "sbom-and-attest job is missing"

grep -F 'name: "SBOM + SLSA Attestation"' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest must remain the release SBOM and SLSA attestation job"
grep -F 'contents: read' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest needs contents: read for checkout and live tag revalidation"
grep -F 'attestations: write' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest needs attestations: write for build provenance"
grep -F 'id-token: write' <<<"$sbom_block" >/dev/null \
  || fail "sbom-and-attest needs id-token: write for keyless signing"
grep -F 'bash tools/ci_cargo_retry.sh cargo install cargo-cyclonedx --version 0.5.9 --locked' <<<"$sbom_block" >/dev/null \
  || fail "release SBOM job must pin cargo-cyclonedx 0.5.9"
grep -F 'cargo cyclonedx -f json --all' <<<"$sbom_block" >/dev/null \
  || fail "release SBOM job must use cargo-cyclonedx 0.5.9 compatible --all workspace generation"
grep -F 'cargo metadata --no-deps --format-version 1 --locked >/dev/null' <<<"$sbom_block" >/dev/null \
  || fail "release SBOM job must prove the workspace lock is current before cargo-cyclonedx"
grep -F 'git diff --exit-code -- Cargo.lock' <<<"$sbom_block" >/dev/null \
  || fail "release SBOM job must reject any lockfile mutation before upload or attestation"

if grep -F 'cargo cyclonedx -f json --workspace' <<<"$sbom_block" >/dev/null; then
  fail "cargo-cyclonedx 0.5.9 does not support --workspace in the release SBOM job"
fi

grep -F "find crates -type f -name '*.cdx.json'" <<<"$sbom_block" >/dev/null \
  || fail "release SBOM job must collect cargo-cyclonedx crate-local SBOM output"
grep -F 'path: sbom/exochain-${{ needs.validate-release-inputs.outputs.version }}-*.cdx.json' <<<"$sbom_block" >/dev/null \
  || fail "release SBOM artifacts must be uploaded with versioned names"
grep -F 'uses: actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45' <<<"$sbom_block" >/dev/null \
  || fail "release build provenance must remain attested by the pinned SLSA action"
grep -F 'bash tools/test_release_sbom_boundary.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the release SBOM boundary guard"

printf 'release SBOM boundary test passed\n'
