# LYNK Coverage Evidence - 2026-07-08

This note records the Task 8 coverage-first packaging evidence for the EXOCHAIN LYNK Protocol. It is a release-hardening evidence note, not a deployment or registry publish claim.

## Thresholds

- Rust focused LYNK coverage: at least 90% line coverage for touched LYNK Rust evidence code.
- Rust full Gate 3: at least 90% line coverage under the scoped workspace tarpaulin exclusions.
- TypeScript package coverage: at least 95% lines, at least 95% functions, and at least 90% branches for package source.
- Package artifact gate: README, AGENTS guidance, examples, snippets, compiled JavaScript, and declaration files must be present in the dry-run package.

## Focused Rust Gates

```bash
cargo test -p exochain-avc llm_usage -- --nocapture
cargo test -p exochain-avc receipt -- --nocapture
cargo test -p exochain-avc validation -- --nocapture
cargo test -p exochain-node avc_llm_usage -- --nocapture
cargo test -p exochain-node avc_receipts_emit -- --nocapture
cargo tarpaulin -p exochain-avc --include-files crates/exo-avc/src/llm_usage_receipt.rs --out xml --output-dir coverage/lynk-focused --engine llvm --timeout 900 --fail-under 90 -- llm_usage
```

Result: all focused Rust tests passed. The focused LYNK evidence tarpaulin run covered `crates/exo-avc/src/llm_usage_receipt.rs` at 94.23% line coverage, producing the local/CI artifact `coverage/lynk-focused/cobertura.xml`.

## Package Gates

```bash
cd packages/exochain-llm-proxy
npm test
npm run build
npm run test:coverage
npm run check:package
npm run pack:dry-run
```

Result: all package gates passed. `npm run test:coverage` passed 42 tests and reported 99.71% lines, 95.92% functions, and 96.17% branches overall. `npm run pack:dry-run` confirmed the npm package includes README, AGENTS guidance, compiled JavaScript, declarations, examples, and snippets.

## Smoke And Privacy Gates

```bash
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode external_payload_ref
node tools/llm_usage_receipt_smoke.mjs --fixture fake-mcp --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-mcp --storage-mode external_payload_ref
node tools/llm_usage_receipt_smoke.mjs --expect-failure receipt_unavailable
node tools/llm_usage_receipt_smoke.mjs --expect-failure idempotency_conflict
node tools/llm_usage_receipt_smoke.mjs --expect-failure tenant_mismatch
node tools/llm_usage_receipt_smoke.mjs --expect-failure missing_custody
node tools/llm_usage_receipt_smoke.mjs --expect-failure dagdb_custody_unavailable --storage-mode dagdb_custody
node tools/llm_usage_receipt_smoke.mjs --expect-failure incomplete_usage_required
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_lynk_receipt_privacy.sh
```

Result: all smoke and privacy gates passed. The privacy guard covers LYNK docs, examples, snippets, smoke fixtures, package metadata, and the public `/site` LYNK copy.

## Public Site Gates

```bash
cd site
npm run security:lynk-public-claims
npm run typecheck
npm run lint
npm run build
npm run security:auth-boundary
npm run security:contact-disclosure
npm run security:contact-intake
```

Result: all public site gates passed. The `/site` LYNK page is classified as an adjacent public surface and points users to the tested core/API receipt path without claiming that the site itself enforces EXOCHAIN constitutional decisions.

## Full Gate 3

```bash
cargo tarpaulin --workspace --exclude exochain-wasm --exclude exochain-proofs --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90
```

Result: passed at 91.35% scoped workspace line coverage, covering 42,702 of 46,746 lines. The full Gate 3 local/CI artifact is `coverage/cobertura.xml`.

## Scope Wording

The full Rust percentage is a scoped Gate 3 tarpaulin result using the command above and its exclusions. It should not be restated as unqualified whole-repository coverage. The focused LYNK Rust percentage is scoped to `crates/exo-avc/src/llm_usage_receipt.rs`; route, receipt, smoke, privacy, package, and site behavior are covered by the separate focused gates listed in this note.
