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

# ULTRAPLAN — GAP-007: LiveSafe Integration

**Status:** CLOSED  
**Crates affected:** `exo-gateway`, `exo-identity`  
**Author:** Aeon (Chief-of-Staff AI, EXOCHAIN)  
**Date:** 2025

---

## 1. Current State: What Works, What's Mocked, What's Broken

### What Works

- **`resolve_query_db`** — correctly queries PostgreSQL for all four query variants
  (`Identity`, `ScanHistory`, `ConsentLog`, `PaceStatus`). The DB layer calls are
  sound and produce well-formed JSON from real row data.
- **`resolve_mutation_db`** — correctly persists scan receipts, consent anchors,
  identity registrations, and audit receipts to Postgres, logging on error.
- **All LiveSafe types** (`LiveSafeIdentity`, `ScanReceipt`, `ConsentAnchor`,
  `TrusteeShardStatus`) are fully defined and serialize cleanly.
- **PACE API** (`pace.rs`) — complete and well-tested: `PaceConfig`, `PaceState`,
  `resolve_operator`, `escalate`, `deescalate` — all with unit tests.
- **Shamir API** (`shamir.rs`) — GF(256) implementation with constant-time field
  arithmetic, property tests, and full coverage.

### What Was Mocked (the bug)

- **`resolve_query`** was a thin wrapper that called `resolve_query_mock()` unconditionally.
  No pool was accepted. Every production query silently returned hardcoded test data
  (`odentityComposite: 72.5`, `scan-001`, etc.).
- **`resolve_mutation`** similarly called `resolve_mutation_mock()` unconditionally,
  so no mutation ever touched the database.
- **`resolve_query_db`** had a second silent mock fallback: on DB error *or* empty result
  set, it returned mock data instead of an honest empty/error response. This masked
  DB connectivity issues and data-not-found conditions.
- **Integration tests** (`livesafe_integration.rs`) contained a single placeholder test
  referencing a stale pre-refactor API (`PaceEnrollment`, `split_secret`, etc.) and were
  entirely disabled.

### What Was Broken

1. Production resolver path never hit the database — mock data in live environments.
2. DB errors in `resolve_query_db` were invisible to callers (silent fallback to mock).
3. Integration test suite was dead weight — zero real coverage of the PACE or Shamir APIs.

---

## 2. Fix Plan: Mock Fallback Removal

### `resolve_query` → Require a Pool

The old sync signature `fn resolve_query(query: &LiveSafeQuery) -> serde_json::Value`
was replaced with:

```rust
pub async fn resolve_query(
    query: &LiveSafeQuery,
    pool: &sqlx::PgPool,
) -> Result<serde_json::Value, sqlx::Error>
```

This forces all call sites to provide a real database pool. There is no fallback.
Any call site that was relying on the mock behavior will fail to compile — which is
the desired outcome; those sites need to be plumbed with a real pool.

### `resolve_mutation` → Require a Pool

Similarly:

```rust
pub async fn resolve_mutation(
    mutation: &LiveSafeMutation,
    pool: &sqlx::PgPool,
) -> serde_json::Value
```

Delegates directly to `resolve_mutation_db`. No mock path.

### `resolve_query_db` → Honest Error Handling

Removed the silent `_ => resolve_query_mock(query)` arms. Replaced with:
- `Ok(None)` → `serde_json::Value::Null` (identity not found — honest)
- `Err(e)` → log via `tracing::error!`, return `Null` or `json!([])` (still opaque
  to callers, but the error is now observable in logs and not silently masked by mock data)
- Empty result sets now return `[]`, not a fake populated list

### Mock Functions Retained — Labeled `FOR TESTING ONLY`

`resolve_query_mock` and `resolve_mutation_mock` are preserved and made `pub` so tests
can use them directly. Both carry the doc comment:

```
/// FOR TESTING ONLY — returns deterministic mock data. Never call in production resolvers.
```

### Existing Unit Tests Updated

The `#[cfg(test)]` block in `livesafe.rs` was updated to call `resolve_query_mock` and
`resolve_mutation_mock` directly (since `resolve_query`/`resolve_mutation` now require
an async pool). All 11 existing unit tests pass unchanged.

---

## 3. Integration Test Rewrite

### Approach

The old tests referenced `PaceEnrollment`, `ContactRelationship`, `split_secret`, and
`reconstruct_secret` — names that no longer exist after the API simplification. The
entire file was rewritten against the current API surface.

No database is needed for these tests — PACE and Shamir are pure-logic crates.

### Test Coverage (12 tests, all passing)

| Test | What it covers |
|------|---------------|
| `test_pace_config_creation` | PaceConfig fields, DID format, `validate()` pass |
| `test_pace_config_invalid_empty_alternates` | `validate()` rejects empty alternates |
| `test_pace_config_invalid_empty_contingency` | `validate()` rejects empty contingency |
| `test_pace_config_invalid_empty_emergency` | `validate()` rejects empty emergency |
| `test_pace_config_duplicate_did_rejected` | `validate()` rejects cross-level DID duplication |
| `test_pace_state_transitions` | Full escalation chain; over-escalation fails; full de-escalation chain; under-de-escalation fails |
| `test_pace_resolve_operator` | `resolve_operator` at each of the 4 PACE states |
| `test_pace_escalate_deescalate` | Escalation changes operator; de-escalation restores it |
| `test_shamir_split_reconstruct` | 3-of-5 split; threshold reconstruct; commitment check |
| `test_shamir_split_reconstruct_any_threshold_subset` | All 2-of-4 combos reconstruct correctly |
| `test_shamir_insufficient_shares` | Reconstruct with 2 of 3-threshold fails with correct error |
| `test_pace_operator_continuity` | Operator stable within state; changes on transition; restored on de-escalation |

### Architectural note on `test_pace_operator_continuity`

This test directly encodes the LiveSafe continuity guarantee: the operator DID must be
stable and predictable within a PACE state, change deterministically on transition, and
be fully reversible via de-escalation. This is the property that LiveSafe's emergency
response system depends on.

---

## 4. Constitutional Notes

- **No floating point introduced.** The pre-existing `odentity_composite: f64` field in
  `LiveSafeIdentity` was noted but not modified (out of scope for GAP-007; tracked separately).
- **No unsafe code.** All changes are pure safe Rust.
- **`thiserror` used throughout** in `IdentityError` — no changes needed here.
- **Zero clippy warnings** (`-D warnings`) across both crates after all changes.

---

## 5. Files Changed

| File | Change |
|------|--------|
| `crates/exo-gateway/src/livesafe.rs` | `resolve_query` and `resolve_mutation` now require `&sqlx::PgPool`; `resolve_query_db` no longer falls back to mock; mock functions labeled `FOR TESTING ONLY`; unit tests updated to call mock functions directly |
| `crates/exo-identity/tests/livesafe_integration.rs` | Fully rewritten — 12 real integration tests against current PACE + Shamir API |
| `gap/ULTRAPLAN-GAP-007-LIVESAFE.md` | This document |

**GAP-007 closed.**
