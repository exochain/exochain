# WO-009 No-Admin Preservation — Security Audit Report

**Date:** 2026-03-30
**Auditor:** Governance/Constitutional Engineer (APE-49)
**Commit audited:** `8b583b7`
**Specification:** CR-001 §8.9 — No-Admin Preservation
**Branch:** `feat/APE-28-gateway-auth-and-routes`

---

## Executive Summary

Full audit of all 16 crates in the ExoChain workspace for admin-bypass paths. **No bypass paths found.**

`Kernel::adjudicate` is the single constitutional adjudication codepath. No shortcuts, backdoors, privilege escalations, or routes that circumvent AEGIS invariant checking were identified. The workspace remains in compliance with the constitutional invariant that "no admins" is the definitive security posture.

---

## Scope

| Crate | Focus | Finding |
|-------|-------|---------|
| `exo-gatekeeper` | `Kernel::adjudicate`, combinators, invariant engine | No bypass. Adjudication is the only codepath. |
| `exo-governance` | Admin role checks, emergency.rs, clearance, quorum | No bypass. Emergency requires ratification. |
| `exo-gateway` | `AppState::build_adjudication_context`, route handlers | No bypass. Context is deny-all scaffold (see §3). |
| `decision-forum` | Forum admin paths, governance integration | No bypass. All actions route through gatekeeper. |
| `exo-escalation` | Sybil adjudication, escalation paths | No bypass. Escalations produce `Verdict::Escalated`, not `Permitted`. |
| `exo-legal` | Jurisdiction rules | No bypass paths exist. |
| All test utilities | Backdoor / dev-only code paths | No library-reachable test backdoors found. |

---

## Detailed Findings

### §1 — `Kernel::adjudicate` is the Single Codepath

`crates/exo-gatekeeper/src/kernel.rs`: The `adjudicate` method runs all eight constitutional invariants in sequence. No method bypasses this path. There are no `force_approve`, `admin_override`, `skip_adjudication`, or feature-gated alternate paths.

### §2 — Emergency Actions Require Ratification

`crates/exo-governance/src/emergency.rs`: Emergency halt/resume actions require explicit ratification via the governance quorum path. This is not a bypass — it is an explicit constitutional mechanism documented in the AEGIS framework.

### §3 — Gateway Dev Scaffold is Deny-All (Not a Bypass)

`crates/exo-gateway/src/server.rs` — `AppState::build_adjudication_context`:

The gateway constructs `AdjudicationContext` with:
- `BailmentState::None` — fails `ConsentRequired` invariant
- `AuthorityChain::default()` — fails `AuthorityChainValid` invariant

This scaffold **always produces a denial from `Kernel::adjudicate`**. It is a deliberate placeholder, not a bypass. A `WO-009` safety doc comment has been added to warn future developers against converting this scaffold into a bypass by populating `bailment_state` with `Active` or adding authority links without a real DB-backed resolver.

### §4 — DID Registration Grants No Permissions

`POST /auth/register` in the gateway only stores a DID's public key. No permissions, roles, or authority chain links are granted at registration. No escalation to permitted state is possible via registration alone.

### §5 — No Dev/Test Backdoors in Library Code

All test utilities (`#[cfg(test)]` modules, `test_kernel()`, `valid_context()`, helper functions) are gated with `#[cfg(test)]`. They are not reachable from production library code. No `#[allow(dead_code)]` bypass scaffolds or conditional compilation paths that reach production were found.

---

## Tests Added (Bypass Verification)

Six new tests were added to `crates/exo-gatekeeper/src/kernel.rs` under `mod no_admin_bypass`:

| Test | Bypass Scenario | Expected Result | Status |
|------|----------------|-----------------|--------|
| `dev_scaffold_context_is_deny_all` | `BailmentState::None` + empty chain | Denied | PASS |
| `all_government_branches_simultaneously_denied` | Actor holds Executive + Legislative + Judicial roles | Denied (SeparationOfPowers) | PASS |
| `maximum_permissions_cannot_bypass_consent` | Permissions include "admin", "override", "execute" | Denied (ConsentRequired) | PASS |
| `empty_authority_chain_not_permitted` | `AuthorityChain::default()` with valid other fields | Not Permitted (Escalated or Denied) | PASS |
| `human_override_suppression_is_non_bypassable` | `human_override_preserved = false` | Denied (HumanOverride) | PASS |
| `kernel_modification_always_denied` | `action.modifies_kernel = true` | Denied (KernelImmutability) | PASS |

Total workspace tests after implementation: **1,443** (all passing). Clippy clean.

---

## Constitutional Invariants Verified

| Invariant | Bypass Attempted | Rejection Confirmed |
|-----------|-----------------|---------------------|
| `SeparationOfPowers` | Multi-branch omnipotent actor | Yes — test §2 |
| `ConsentRequired` | `BailmentState::None` with any permissions | Yes — tests §1, §3 |
| `HumanOverride` | `human_override_preserved = false` | Yes — test §5 |
| `KernelImmutability` | `modifies_kernel = true` | Yes — test §6 |
| `AuthorityChainValid` | `AuthorityChain::default()` | Yes — test §4 |

---

## Conclusion

The ExoChain workspace satisfies CR-001 §8.9 — No-Admin Preservation:

1. **Zero admin bypass paths** exist in library code.
2. `Kernel::adjudicate` is the **sole** constitutional adjudication codepath.
3. The `KernelImmutability` invariant covers kernel modification attempts unconditionally.
4. The gateway dev scaffold is documented as deny-all and protected against future drift.
5. Six bypass verification tests ensure regressions are caught immediately.

No further remediation required for WO-009.
