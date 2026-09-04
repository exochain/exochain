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

# EXOCHAIN 0.2.6 Changed-Path Classification

This inventory classifies every path changed from validation baseline
`8020ceab355eefa7f5185d9cdd0436da7af46efb` through committed source checkpoint
`368721a1ea3577481cf73cdee6d811623159faec`, plus the six evidence documents in
the evidence commit, including this record. The same reconciliation is required
against the committed evidence head; this inventory alone is not worktree-
custody or release-authorization proof.
The downloaded HTML report is not changed or committed; it remains read-only
imported evidence outside this inventory.

Checkpoints `2e286e21` and `e73dcf53` change only the already-listed
`tools/publish_release_npm_package.sh` and
`tools/test_release_publish_boundaries.sh` core-runtime-adapter paths, so they
do not change the inventory cardinality or digest from the preceding source
checkpoint. Later test and repository-truth commits also stay within paths
already listed below: `760613e6` and `3b98fd11` modify
`crates/exo-root/src/dkg.rs`; `a6058966` and `368721a1` modify `README.md`; and
`96318413` and `a3d1e2f3` modify
`tools/test_wasm_npm_package_boundary.sh`. They therefore do not change the
315-path cardinality, class totals, or path digest.

The baseline-to-source series contains 83 commits in oldest-first order. The
SHA-256 of that newline-delimited full commit-hash sequence is
`8e00dda15d12d008f55705fe74fac1f8164daa0df42763e133704e050d89d369`.

## Classification totals

| Class | Paths |
| --- | ---: |
| EXOCHAIN core | 59 |
| Core runtime adapter | 154 |
| Adjacent surface | 14 |
| Imported evidence | 0 |
| Third-party/vendor | 88 |
| **Total** | **315** |

Generated JavaScript, declaration, source-map, lock, and SBOM dependency records
are classified as third-party/vendor artifacts even when their owned source is a
core adapter. Tracked validation and release records are EXOCHAIN core
governance evidence; they do not import the external HTML.

## Exact path inventory

| Path | Classification |
| --- | --- |
| `.github/workflows/ci.yml` | core runtime adapter |
| `.github/workflows/release.yml` | core runtime adapter |
| `CHANGELOG.md` | EXOCHAIN core |
| `Cargo.lock` | third-party/vendor |
| `Cargo.toml` | EXOCHAIN core |
| `README.md` | EXOCHAIN core |
| `VERSIONING.md` | EXOCHAIN core |
| `crates/decision-forum/Cargo.toml` | EXOCHAIN core |
| `crates/exo-api/Cargo.toml` | core runtime adapter |
| `crates/exo-authority/Cargo.toml` | EXOCHAIN core |
| `crates/exo-avc/Cargo.toml` | EXOCHAIN core |
| `crates/exo-catapult/Cargo.toml` | EXOCHAIN core |
| `crates/exo-cgr-methods/Cargo.toml` | EXOCHAIN core |
| `crates/exo-cgr-methods/guest/Cargo.lock` | third-party/vendor |
| `crates/exo-cgr-methods/guest/Cargo.toml` | EXOCHAIN core |
| `crates/exo-cgr-prover/Cargo.toml` | EXOCHAIN core |
| `crates/exo-consensus/Cargo.toml` | EXOCHAIN core |
| `crates/exo-consent/Cargo.toml` | EXOCHAIN core |
| `crates/exo-dag-db-core/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-domain/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-exchange/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-graph/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-lab/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-lab/src/bin/dagdb_kg_export_manifest.rs` | core runtime adapter |
| `crates/exo-dag-db-lab/src/bin/dagdb_kg_import_candidates.rs` | core runtime adapter |
| `crates/exo-dag-db-lab/src/bin/dagdb_kg_import_persist.rs` | core runtime adapter |
| `crates/exo-dag-db-lab/src/diagnostics.rs` | core runtime adapter |
| `crates/exo-dag-db-lab/src/kg_markdown_manifest.rs` | core runtime adapter |
| `crates/exo-dag-db-postgres/Cargo.toml` | core runtime adapter |
| `crates/exo-dag-db-retrieval/Cargo.toml` | core runtime adapter |
| `crates/exo-dag/Cargo.toml` | EXOCHAIN core |
| `crates/exo-economy/Cargo.toml` | EXOCHAIN core |
| `crates/exo-economy/src/price.rs` | EXOCHAIN core |
| `crates/exo-economy/src/revenue_share.rs` | EXOCHAIN core |
| `crates/exo-economy/src/settlement.rs` | EXOCHAIN core |
| `crates/exo-escalation/Cargo.toml` | EXOCHAIN core |
| `crates/exo-gatekeeper/Cargo.toml` | EXOCHAIN core |
| `crates/exo-gateway/Cargo.toml` | core runtime adapter |
| `crates/exo-gateway/src/auth.rs` | core runtime adapter |
| `crates/exo-governance/Cargo.toml` | EXOCHAIN core |
| `crates/exo-governance/src/crosscheck.rs` | EXOCHAIN core |
| `crates/exo-identity/Cargo.toml` | EXOCHAIN core |
| `crates/exo-identity/src/did_verification.rs` | EXOCHAIN core |
| `crates/exo-identity/src/shamir.rs` | EXOCHAIN core |
| `crates/exo-identity/src/vault.rs` | EXOCHAIN core |
| `crates/exo-legal/Cargo.toml` | EXOCHAIN core |
| `crates/exo-legal/src/dgcl144.rs` | EXOCHAIN core |
| `crates/exo-messaging/Cargo.toml` | EXOCHAIN core |
| `crates/exo-messaging/src/compose.rs` | EXOCHAIN core |
| `crates/exo-messaging/src/envelope.rs` | EXOCHAIN core |
| `crates/exo-messaging/src/lib.rs` | EXOCHAIN core |
| `crates/exo-node/Cargo.toml` | core runtime adapter |
| `crates/exo-node/fixtures/lynk/rust_receipt_emit_response_v1.json` | core runtime adapter |
| `crates/exo-node/fixtures/lynk/typescript_receipt_emit_request_v1.json` | core runtime adapter |
| `crates/exo-node/src/auth.rs` | core runtime adapter |
| `crates/exo-node/src/avc.rs` | core runtime adapter |
| `crates/exo-node/src/crosschecked_anchor_authority_admin_cli.rs` | core runtime adapter |
| `crates/exo-node/src/identity.rs` | core runtime adapter |
| `crates/exo-node/src/livesafe_public_output_ceremony_cli.rs` | core runtime adapter |
| `crates/exo-node/src/main.rs` | core runtime adapter |
| `crates/exo-node/src/mcp/mod.rs` | core runtime adapter |
| `crates/exo-node/src/passport.rs` | core runtime adapter |
| `crates/exo-node/src/pdp_store.rs` | core runtime adapter |
| `crates/exo-node/src/private_file.rs` | core runtime adapter |
| `crates/exo-node/src/root_genesis.rs` | core runtime adapter |
| `crates/exo-node/src/root_genesis_cli.rs` | core runtime adapter |
| `crates/exo-node/src/store/store_postgres.rs` | core runtime adapter |
| `crates/exo-node/src/zerodentity/onboarding.rs` | core runtime adapter |
| `crates/exo-node/src/zerodentity/scoring.rs` | core runtime adapter |
| `crates/exo-node/src/zerodentity/tests.rs` | core runtime adapter |
| `crates/exo-pdp/Cargo.toml` | EXOCHAIN core |
| `crates/exo-pdp/src/http.rs` | core runtime adapter |
| `crates/exo-pdp/src/lib.rs` | EXOCHAIN core |
| `crates/exo-pdp/src/pack.rs` | EXOCHAIN core |
| `crates/exo-pdp/src/service.rs` | EXOCHAIN core |
| `crates/exo-proofs/Cargo.toml` | EXOCHAIN core |
| `crates/exo-proofs/src/snark.rs` | EXOCHAIN core |
| `crates/exo-proofs/src/verifier.rs` | EXOCHAIN core |
| `crates/exo-root/Cargo.toml` | EXOCHAIN core |
| `crates/exo-root/src/bundle.rs` | EXOCHAIN core |
| `crates/exo-root/src/dkg.rs` | EXOCHAIN core |
| `crates/exo-root/src/lib.rs` | EXOCHAIN core |
| `crates/exo-root/src/portal.rs` | EXOCHAIN core |
| `crates/exo-root/src/signing.rs` | EXOCHAIN core |
| `crates/exo-root/tests/dkg_patch_compat.rs` | EXOCHAIN core |
| `crates/exo-root/tests/root_genesis.rs` | EXOCHAIN core |
| `crates/exo-tenant/Cargo.toml` | EXOCHAIN core |
| `crates/exo-tenant/src/error.rs` | EXOCHAIN core |
| `crates/exo-tenant/src/metering.rs` | EXOCHAIN core |
| `crates/exo-tenant/src/store.rs` | EXOCHAIN core |
| `crates/exochain-sdk/Cargo.toml` | core runtime adapter |
| `crates/exochain-sdk/src/dagdb.rs` | core runtime adapter |
| `crates/exochain-sdk/src/governance.rs` | core runtime adapter |
| `crates/exochain-sdk/src/lib.rs` | core runtime adapter |
| `crates/exochain-wasm/Cargo.toml` | core runtime adapter |
| `crates/exochain-wasm/src/governance_bindings.rs` | core runtime adapter |
| `crates/exochain-wasm/src/identity_bindings.rs` | core runtime adapter |
| `crates/exochain-wasm/src/legal_bindings.rs` | core runtime adapter |
| `crates/exochain-wasm/src/messaging_bindings.rs` | core runtime adapter |
| `docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md` | EXOCHAIN core |
| `docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md` | EXOCHAIN core |
| `docs/audit/exochain-code-review-report-run4-validation-2026-08-28.md` | EXOCHAIN core |
| `docs/guides/sdk-quickstart-python.md` | core runtime adapter |
| `docs/guides/sdk-quickstart-typescript.md` | core runtime adapter |
| `docs/superpowers/plans/2026-08-28-release-0.2.6-security-remediation.md` | EXOCHAIN core |
| `fuzz/Cargo.lock` | third-party/vendor |
| `fuzz/Cargo.toml` | EXOCHAIN core |
| `governance/releases/v0.2.6/PATH-CLASSIFICATION.md` | EXOCHAIN core |
| `governance/releases/v0.2.6/RC.md` | EXOCHAIN core |
| `governance/releases/v0.2.6/TEST-PLAN.md` | EXOCHAIN core |
| `livesafe/client/package-lock.json` | third-party/vendor |
| `livesafe/client/package.json` | adjacent surface |
| `livesafe/docs/TEST_PLAN.md` | adjacent surface |
| `livesafe/docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | adjacent surface |
| `livesafe/package-lock.json` | third-party/vendor |
| `livesafe/responder/package-lock.json` | third-party/vendor |
| `livesafe/responder/package.json` | adjacent surface |
| `livesafe/server/package-lock.json` | third-party/vendor |
| `livesafe/server/package.json` | adjacent surface |
| `livesafe/src/ai_help_session_transcript.rs` | adjacent surface |
| `livesafe/src/ai_help_unanswered_topic.rs` | adjacent surface |
| `livesafe/src/ai_help_usage_summary.rs` | adjacent surface |
| `livesafe/src/feedback_mandated_reporter.rs` | adjacent surface |
| `livesafe/tests/ai_help_session_transcript.rs` | adjacent surface |
| `livesafe/tests/ai_help_unanswered_topic.rs` | adjacent surface |
| `livesafe/tests/ai_help_usage_summary.rs` | adjacent surface |
| `livesafe/tests/context-docs.test.ts` | adjacent surface |
| `livesafe/tests/feedback_mandated_reporter.rs` | adjacent surface |
| `packages/README.md` | core runtime adapter |
| `packages/exochain-llm-proxy/README.md` | core runtime adapter |
| `packages/exochain-llm-proxy/dist/attestation.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/attestation.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/attestation.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/attestation.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/cli.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/cli.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/http.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/http.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/http.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/http.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/index.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/index.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/index.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/index.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/mcp.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/mcp.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/mcp.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/openai.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/openai.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/openai.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/receipt.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/receipt.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/receipt.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/receipt.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/types.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/types.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/wire.d.ts` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/wire.d.ts.map` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/wire.js` | third-party/vendor |
| `packages/exochain-llm-proxy/dist/wire.js.map` | third-party/vendor |
| `packages/exochain-llm-proxy/examples/chat-completions.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/examples/external-payload-ref.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/examples/mcp-tool-call.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/examples/openai-responses.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/examples/receipt-authority.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/examples/receipt-pending-retry.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/package-lock.json` | third-party/vendor |
| `packages/exochain-llm-proxy/package.json` | core runtime adapter |
| `packages/exochain-llm-proxy/snippets/env-template.md` | core runtime adapter |
| `packages/exochain-llm-proxy/src/attestation.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/cli.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/http.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/index.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/mcp.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/openai.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/receipt.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/types.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/src/wire.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/cli.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/delivery.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/http.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/mcp.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/object-store.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/openai.test.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/receipt-fixture.ts` | core runtime adapter |
| `packages/exochain-llm-proxy/test/wire-contract.test.ts` | core runtime adapter |
| `packages/exochain-py/README.md` | core runtime adapter |
| `packages/exochain-py/exochain/__init__.py` | core runtime adapter |
| `packages/exochain-py/exochain/client.py` | core runtime adapter |
| `packages/exochain-py/exochain/governance/decision.py` | core runtime adapter |
| `packages/exochain-py/exochain/transport/http.py` | core runtime adapter |
| `packages/exochain-py/pyproject.toml` | core runtime adapter |
| `packages/exochain-py/tests/test_crypto.py` | core runtime adapter |
| `packages/exochain-py/tests/test_governance.py` | core runtime adapter |
| `packages/exochain-py/tests/test_transport.py` | core runtime adapter |
| `packages/exochain-sdk/README.md` | core runtime adapter |
| `packages/exochain-sdk/dist-test/src/client.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/client.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/crypto/hash.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/crypto/hash.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/governance/decision.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/governance/decision.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/identity/did.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/identity/did.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/index.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/index.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/transport/http.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/transport/http.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/transport/index.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/src/transport/index.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/client.test.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/client.test.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/governance.test.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/governance.test.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/http_transport.test.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/http_transport.test.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/identity.test.js` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/identity.test.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist-test/test/index.test.js` | third-party/vendor |
| `packages/exochain-sdk/dist/client.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/client.js` | third-party/vendor |
| `packages/exochain-sdk/dist/client.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/crypto/hash.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/crypto/hash.js` | third-party/vendor |
| `packages/exochain-sdk/dist/crypto/hash.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/governance/decision.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/governance/decision.js` | third-party/vendor |
| `packages/exochain-sdk/dist/governance/decision.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/identity/did.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/identity/did.js` | third-party/vendor |
| `packages/exochain-sdk/dist/identity/did.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/index.d.ts` | third-party/vendor |
| `packages/exochain-sdk/dist/index.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/index.js` | third-party/vendor |
| `packages/exochain-sdk/dist/index.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/http.d.ts` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/http.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/http.js` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/http.js.map` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/index.d.ts` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/index.d.ts.map` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/index.js` | third-party/vendor |
| `packages/exochain-sdk/dist/transport/index.js.map` | third-party/vendor |
| `packages/exochain-sdk/package-lock.json` | third-party/vendor |
| `packages/exochain-sdk/package.json` | core runtime adapter |
| `packages/exochain-sdk/src/client.ts` | core runtime adapter |
| `packages/exochain-sdk/src/crypto/hash.ts` | core runtime adapter |
| `packages/exochain-sdk/src/governance/decision.ts` | core runtime adapter |
| `packages/exochain-sdk/src/identity/did.ts` | core runtime adapter |
| `packages/exochain-sdk/src/index.ts` | core runtime adapter |
| `packages/exochain-sdk/src/transport/http.ts` | core runtime adapter |
| `packages/exochain-sdk/src/transport/index.ts` | core runtime adapter |
| `packages/exochain-sdk/test/client.test.ts` | core runtime adapter |
| `packages/exochain-sdk/test/governance.test.ts` | core runtime adapter |
| `packages/exochain-sdk/test/http_transport.test.ts` | core runtime adapter |
| `packages/exochain-sdk/test/identity.test.ts` | core runtime adapter |
| `packages/exochain-sdk/test/index.test.ts` | core runtime adapter |
| `packages/exochain-wasm/test/bridge_verification.mjs` | core runtime adapter |
| `packages/exochain-wasm/wasm/package.json` | third-party/vendor |
| `tools/capture_release_helper.sh` | core runtime adapter |
| `tools/check_cratesio_namespace_ownership.mjs` | core runtime adapter |
| `tools/llm_usage_receipt_smoke.mjs` | core runtime adapter |
| `tools/preflight_release_crates.sh` | core runtime adapter |
| `tools/publish_release_crates.sh` | core runtime adapter |
| `tools/publish_release_npm_package.sh` | core runtime adapter |
| `tools/publish_sealed_crate.py` | core runtime adapter |
| `tools/python-release-requirements.in` | core runtime adapter |
| `tools/python-release-requirements.lock` | third-party/vendor |
| `tools/resolve_release_tool_path.sh` | core runtime adapter |
| `tools/stage_llm_release_package.sh` | core runtime adapter |
| `tools/test_capture_release_helper.sh` | core runtime adapter |
| `tools/test_cratesio_release_packaging.sh` | core runtime adapter |
| `tools/test_gateway_db_ci.sh` | core runtime adapter |
| `tools/test_github_actions_pinned.sh` | core runtime adapter |
| `tools/test_publish_release_crates_registry_validation.sh` | core runtime adapter |
| `tools/test_publish_release_npm_registry_validation.sh` | core runtime adapter |
| `tools/test_publish_sealed_crate.py` | core runtime adapter |
| `tools/test_publish_sealed_crate_cargo_parity.py` | core runtime adapter |
| `tools/test_python_sdk_ci_boundary.sh` | core runtime adapter |
| `tools/test_release_dry_run_boundaries.sh` | core runtime adapter |
| `tools/test_release_llm_lifecycle_boundary.sh` | core runtime adapter |
| `tools/test_release_npm_config_boundary.sh` | core runtime adapter |
| `tools/test_release_publish_boundaries.sh` | core runtime adapter |
| `tools/test_release_sbom_boundary.sh` | core runtime adapter |
| `tools/test_release_sdk_python_lifecycle_boundary.sh` | core runtime adapter |
| `tools/test_release_signed_tag_trust_boundary.sh` | core runtime adapter |
| `tools/test_release_version_alignment.sh` | core runtime adapter |
| `tools/test_release_version_input_boundary.sh` | core runtime adapter |
| `tools/test_release_workflow_ref_binding.sh` | core runtime adapter |
| `tools/test_stage_llm_release_package.sh` | core runtime adapter |
| `tools/test_transport_release_build_output.sh` | core runtime adapter |
| `tools/test_transport_release_file_set.sh` | core runtime adapter |
| `tools/test_transport_wasm_release_output.sh` | core runtime adapter |
| `tools/test_verify_crate_release_archive.py` | core runtime adapter |
| `tools/test_verify_npm_registry_attestation.sh` | core runtime adapter |
| `tools/test_verify_npm_release_tarball.sh` | core runtime adapter |
| `tools/test_verify_python_release_package.sh` | core runtime adapter |
| `tools/test_verify_release_sbom.sh` | core runtime adapter |
| `tools/test_verify_sdk_npm_release_package.sh` | core runtime adapter |
| `tools/test_wasm_npm_package_boundary.sh` | core runtime adapter |
| `tools/transport_release_build_output.py` | core runtime adapter |
| `tools/transport_release_file_set.py` | core runtime adapter |
| `tools/transport_wasm_release_output.py` | core runtime adapter |
| `tools/verify_crate_release_archive.py` | core runtime adapter |
| `tools/verify_cratesio_release_packaging.mjs` | core runtime adapter |
| `tools/verify_npm_registry_attestation.mjs` | core runtime adapter |
| `tools/verify_npm_release_package.mjs` | core runtime adapter |
| `tools/verify_npm_release_tarball.py` | core runtime adapter |
| `tools/verify_python_release_package.py` | core runtime adapter |
| `tools/verify_release_cargo_config.sh` | core runtime adapter |
| `tools/verify_release_sbom.py` | core runtime adapter |
| `tools/verify_release_side_effect.sh` | core runtime adapter |
| `tools/verify_release_source.sh` | core runtime adapter |
| `tools/verify_release_tag.sh` | core runtime adapter |
| `tools/verify_release_tag_signer.sh` | core runtime adapter |

## Mechanical reconciliation

The sorted newline-delimited path set has SHA-256
`e8ee17a01f4b0f7c05dfd346fcf789d141e1cbb5882227a38ed28e6feebbb5eb`.
Run from the candidate worktree with generated test outputs removed:

```bash
set -euo pipefail
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import re
import subprocess

baseline = '8020ceab355eefa7f5185d9cdd0436da7af46efb'
document = Path('governance/releases/v0.2.6/PATH-CLASSIFICATION.md')
committed_or_modified = subprocess.run(
    ['git', 'diff', '--name-only', baseline],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
untracked = subprocess.run(
    ['git', 'ls-files', '--others', '--exclude-standard'],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
actual = sorted(set(committed_or_modified + untracked))
rows = re.findall(r'^\| `([^`]+)` \| (EXOCHAIN core|core runtime adapter|adjacent surface|imported evidence|third-party/vendor) \|$', document.read_text(), re.MULTILINE)
listed = [path for path, _ in rows]
assert len(listed) == len(set(listed)) == 315
assert listed == actual
digest = sha256(('\n'.join(listed) + '\n').encode()).hexdigest()
assert digest == 'e8ee17a01f4b0f7c05dfd346fcf789d141e1cbb5882227a38ed28e6feebbb5eb'
counts = {}
for _, classification in rows:
    counts[classification] = counts.get(classification, 0) + 1
assert counts == {'core runtime adapter':154,'EXOCHAIN core':59,'third-party/vendor':88,'adjacent surface':14}
print(f'path_classification=PASS count={len(listed)} sha256={digest} counts={counts}')
PY
```

## Adjacent LiveSafe intake

The authoritative surface boundary remains
`livesafe/docs/EXOCHAIN_APP_BOUNDARY.md`; this release slice does not change
that boundary.

| Intake field | 0.2.6 remediation disposition |
| --- | --- |
| Owner and accountable maintainer | `bob-stewart` |
| Deployment status | Production-shaped Railway surface; the changed arithmetic/dependency slice is adjacent code and is not deployed by this branch |
| Constitutional trust claims | Not allowed; `public_claims_allowed: false` remains unchanged |
| Core state/signature/credential access | None from the changed files; they do not read or write EXOCHAIN state, signatures, credentials, consent, authority, governance, or provenance |
| Exact trust boundary | Separate proprietary subtree excluded from the Rust workspace; this slice cannot mint or simulate EXOCHAIN outcomes |
| Test command and CI | Four clean `npm ci` installs, `npm run quality`, `npm run build`, Docker build, and the `LiveSafe CI` workflow |
| Secrets and runtime configuration | No secret is added; deployed values remain in Railway secret storage and must not share EXOCHAIN signing/bootstrap scopes |
| Rollback/disablement | Revert the isolated LiveSafe commits or decline this candidate; no deployment is performed by the branch |

## Core regression firewall

The changed LiveSafe files are confined to the adjacent subtree and its isolated
commits. They do not modify `crates/`, `packages/exochain-wasm/`,
`governance/`, release CI, or deployment contracts within those commits.
The complete branch separately changes core and adapter paths in isolated
commits and therefore must pass the full workspace, adapter, release, and
bypass gates in `TEST-PLAN.md`. LiveSafe uses separate locks and secret scopes,
and its focused gates do not substitute for EXOCHAIN core verification.
