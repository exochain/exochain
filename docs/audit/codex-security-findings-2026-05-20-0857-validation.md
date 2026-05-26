# Codex Security Findings Validation - 2026-05-20 08:57 Eastern

Source evidence: `/Users/bobstewart/Downloads/codex-security-findings-2026-05-20T17-11-36.753Z.csv`

Validated against `origin/main` at `45332561ca92e535d27301846e2af566335d8143`
and remediation branch `bob-stewart/codex-security-20260520-0857-triage`.
The CSV contains 67 findings. The downloaded CSV is imported evidence and is
not committed as source.

## Validation Rubric

- The affected path is classified as EXOCHAIN core, core runtime adapter,
  adjacent surface, imported evidence, or third-party/vendor.
- The claimed attacker input still reaches the alleged sink on current main.
- Existing merged code or a new failing regression test proves the current
  disposition.
- Live core/runtime-adapter issues are remediated before adjacent cleanup.
- Open stale PRs are not treated as merged source of truth.

## Closure Summary

Rows 4 and 6 identified live gateway rate-limit regressions introduced by the
recent preflight hardening. Row 15 is the same no-DB HLC rate-limit class stated
more generally. These rows are remediated on this branch by:

- pruning stale tracked-client buckets during the cheap preflight path before
  enforcing the max-client cap;
- using an HLC rate-limit scalar that includes logical progress only for the
  no-database gateway rate-limit fallback, without changing session validation,
  adjudication, or uptime timestamp semantics.

Rows 1, 2, 3, and 5 were revalidated as stale or already remediated on current
main. Rows 7-67 repeat findings already covered by
`docs/audit/codex-security-findings-2026-05-20-validation.md`; the focused
commands below rechecked the repeated high rows and the touched gateway surface.

## Row Disposition

| Row | Finding | Classification | Disposition |
| --- | --- | --- | --- |
| 1 | Unauthenticated eDiscovery export issues trusted results | Core runtime adapter | Already remediated by `#664`; unauthenticated export is rejected and requester spoofing fails. |
| 2 | Schema enables ssh_host command injection path | Adjacent CommandBase surface | Already remediated by current CommandBase route/bootstrap validation; unsafe `ssh_host` is rejected before shell execution. |
| 3 | Untrusted ExoForge issues can drive unapproved code changes | Adjacent workflow surface | Already remediated by workflow argument/output trust boundaries and finite loop guards. |
| 4 | Rate-limit preflight can lock out new clients | Core runtime adapter | Live on current main; fixed by stale-bucket pruning in `GatewayRateLimiter::preflight_limit`. |
| 5 | Rate limiter now performs unauthenticated DB query per request | Core runtime adapter | Already remediated by `#664`; known over-budget clients are rejected before DB-backed trusted time lookup. |
| 6 | Default gateway rate limits no longer reset | Core runtime adapter | Live on current main; fixed by rate-limit-only HLC logical progress fallback. |
| 7-14 | Merkle, consent log, contact, Syntaxis, metrics, MCP audit, Shamir, STARK repeats | Core/core-adapter/adjacent as listed in the CSV | Repeated from the 2026-05-20 validation closure; no new current-main source path survived revalidation. |
| 15 | Deterministic default HLC weakens gateway rate limiting | Core runtime adapter | Covered by the row 6 fix; no-DB fallback rate-limit windows now progress deterministically. |
| 16-34 | Remaining medium findings | Core/core-adapter/adjacent as listed in the CSV | Repeated from the 2026-05-20 validation closure and already represented by merged remediation PRs. |
| 35-52 | Low findings | Core/core-adapter/adjacent as listed in the CSV | Repeated from the 2026-05-20 validation closure and already represented by merged remediation PRs. |
| 53-67 | Informational findings | Core/core-adapter/adjacent as listed in the CSV | Repeated from the 2026-05-20 validation closure and already represented by merged remediation PRs or adjacent-surface quarantine. |

## Red / Green Evidence

The following tests failed against current main before the production change:

```bash
cargo test -p exo-gateway gateway_rate_limit -- --nocapture
cargo test -p exo-gateway gateway_default_hlc_rate_limit_window_resets_from_hlc_progress -- --nocapture
```

Expected red failures:

- `gateway_rate_limit_preflight_prunes_stale_clients_before_max_client_rejection`
  returned `Some(Limited { retry_after_ms: 10 })` instead of `None`.
- `gateway_default_hlc_rate_limit_window_resets_from_hlc_progress` returned
  HTTP `429` instead of `200` on the post-window request.

The same tests pass after the fix.

## Validation Commands

```bash
cargo test -p exo-gateway gateway_rate_limit -- --nocapture
cargo test -p exo-gateway gateway_default_hlc_rate_limit_window_resets_from_hlc_progress -- --nocapture
cargo test -p exo-gateway -- --nocapture
cargo test -p exo-gateway ediscovery_export -- --nocapture
cargo clippy -p exo-gateway --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
node --test command-base/app/lib/bootstrap-schema.test.js command-base/app/schema-bootstrap.routes.test.js
bash tools/test_github_issue_workflow_boundaries.sh
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_agent_workflow_bounds.sh
```

## Stale PR Cleanup

Open remediation PRs were reviewed as GitHub state, not as merged code. The
following PRs were closed as stale/current-main unsafe after this validation
pass: `#336`, `#337`, `#338`, `#339`, `#345`, `#346`, `#347`, `#348`, `#349`,
`#350`, `#351`, `#354`, `#357`, `#370`, `#371`, `#372`, `#373`, `#375`, `#376`,
`#396`, `#397`, `#481`, `#482`, `#484`, `#485`, `#486`, `#487`, `#488`, `#490`,
`#498`, `#500`, `#501`, and `#502`.

Each closed PR received a comment stating that it was not merged and must be
re-cut from current `origin/main` with AGENTS.md path classification, TDD
reproduction, focused gates, and an isolated PR if the concern still survives.

After cleanup, the only remaining open PR is draft PR `#99`, the broad breaking
DID-unification epic. It is not part of the remediation queue and must not be
treated as merged or mergeable without fresh current-main review.
