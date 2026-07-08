#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "LYNK receipt privacy test failed: $*" >&2
  exit 1
}

overclaim_predicate="never stores decryptable payload material"
overclaim_matches=$(
  rg -n -i -F "$overclaim_predicate" \
    INTEGRATION.md docs crates packages tools site \
    --glob '!docs/superpowers/plans/2026-07-08-llm-usage-receipt-extensions.md' \
    | grep -Ei 'EXOCHAIN' || true
)
if [[ -n "$overclaim_matches" ]]; then
  fail "custody docs must distinguish receipt minimization from DAG DB custody: $overclaim_matches"
fi

receipt_body_key_matches_file="$(mktemp)"
set +e
rg -n '"(prompt|messages|completion|response_text|raw_output|raw_prompt|provider_api_key|bearer_token|kms_key|object_uri)"[[:space:]]*:' \
  INTEGRATION.md docs/dagdb crates/exo-avc/src crates/exo-node/src/avc.rs \
  packages/exochain-llm-proxy/src packages/exochain-llm-proxy/README.md \
  packages/exochain-llm-proxy/AGENTS.md packages/exochain-llm-proxy/snippets \
  packages/exochain-llm-proxy/examples tools/llm_usage_receipt_smoke.mjs \
  site/src/app/'(internet)'/lynk site/public/llms.txt site/README.md site/SPEC.md \
  --glob '!**/dist/**' >"$receipt_body_key_matches_file"
receipt_body_key_status=$?
set -e
if ((receipt_body_key_status > 1)); then
  rm -f "$receipt_body_key_matches_file"
  fail "raw/decryptable key scan failed"
fi
receipt_body_key_matches="$(cat "$receipt_body_key_matches_file")"
rm -f "$receipt_body_key_matches_file"
if [[ -n "$receipt_body_key_matches" ]]; then
  fail "LYNK receipt bodies must not define raw/decryptable payload keys: $receipt_body_key_matches"
fi

rg -n 'assertNoRawPayload|assertNoForbiddenReceiptMaterial|production_source_excludes_decryptable_field_names|avc_llm_usage_receipts_emit_rejects_raw_payload_json_keys' \
  crates/exo-avc/src/llm_usage_receipt.rs crates/exo-node/src/avc.rs \
  packages/exochain-llm-proxy/src/evidence.ts tools/llm_usage_receipt_smoke.mjs >/dev/null \
  || fail "expected LYNK privacy rejection/redaction tests and guards to exist"

rg -n 'sk-live|s3://|customer://opaque|provider_api_key|bearer_token|kms_key' \
  packages/exochain-llm-proxy/README.md packages/exochain-llm-proxy/AGENTS.md \
  packages/exochain-llm-proxy/examples packages/exochain-llm-proxy/snippets \
  site/src/app/'(internet)'/lynk site/public/llms.txt site/README.md site/SPEC.md \
  --glob '!**/dist/**' >/tmp/lynk-release-secret-scan.txt || true
if [[ -s /tmp/lynk-release-secret-scan.txt ]]; then
  cat /tmp/lynk-release-secret-scan.txt >&2
  rm -f /tmp/lynk-release-secret-scan.txt
  fail "release docs/examples/snippets must not contain secret-shaped values"
fi
rm -f /tmp/lynk-release-secret-scan.txt

pack_json=$(
  cd packages/exochain-llm-proxy
  npm pack --dry-run --json
)
PACK_JSON="$pack_json" node <<'NODE'
const packs = JSON.parse(process.env.PACK_JSON ?? "[]");
const files = new Set((packs[0]?.files ?? []).map((entry) => entry.path));
const required = [
  "README.md",
  "AGENTS.md",
  "dist/index.js",
  "dist/index.d.ts",
  "examples/openai-responses.ts",
  "snippets/agent-integration-brief.md",
];
for (const path of required) {
  if (!files.has(path)) {
    console.error(`missing from npm dry-run package: ${path}`);
    process.exit(1);
  }
}
for (const path of files) {
  if (path.startsWith("node_modules/") || path.startsWith("dist-test/") || path.startsWith("test/")) {
    console.error(`forbidden package artifact: ${path}`);
    process.exit(1);
  }
}
NODE

echo "LYNK receipt privacy test passed"
