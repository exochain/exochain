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

# ULTRAPLAN: Bailment Contract Engine

**Status**: Implementation  
**Crate**: `exo-consent`  
**Module**: `contract.rs`  
**Author**: Aeon (Chief-of-Staff AI)  
**Date**: 2026-04-14  

---

## 1. Contract Template Engine Architecture

The contract engine introduces clause-based composition to the bailment lifecycle. Rather than hashing raw bytes as `terms_hash`, bailments now reference a **ComposedContract** — a deterministic, content-addressed document built from parameterized clause templates.

**Template Registry.** Each `BailmentType` (Custody, Processing, Delegation, Emergency) has a default `ContractTemplate` containing clauses across eight categories: DataCustody, ProcessingRights, BreachRemedies, LiabilityCaps, DisputeResolution, Termination, Jurisdiction, and Indemnification. Templates are versioned strings (semver). The registry is code-defined (no external storage) — `default_template(BailmentType)` returns the canonical template for each type. Custom templates can be constructed by modifying the default.

**Jurisdiction-Aware Clause Selection.** Clauses carry an optional `jurisdiction: Option<String>`. During composition, if a clause specifies a jurisdiction that doesn't match the contract params' jurisdiction, it is excluded. If a clause has `jurisdiction: None`, it applies universally. This allows templates to contain jurisdiction-specific clauses (e.g., GDPR data residency for "EU", CCPA for "US-CA") alongside universal clauses, with the composition step filtering to the relevant set.

**Data Classification Tiers.** `DataClassification` (Public, Internal, Confidential, Restricted, Regulated) affects which clauses are included and how liability caps are assessed. Higher classifications trigger stricter clauses — Restricted/Regulated data mandates encryption-at-rest clauses, breach notification timelines, and elevated liability caps. The classification is a parameter on `ContractParams`, and clause bodies reference `{{data_classification}}` for human-readable rendering.

**Composition is Pure.** `compose()` is a pure function: same template + same params = same `ComposedContract` with identical `contract_hash`. This is constitutionally required — determinism is non-negotiable. All intermediate serialization uses canonical CBOR via `exo_core::hash::hash_structured`.

---

## 2. Contract Data Model

### Types

```
ContractTemplate → contains Vec<Clause> for a BailmentType
    ↓ compose(template, params)
ComposedContract → rendered clauses, deterministic hash
    ↓ contract_hash
Bailment.terms_hash (existing field, now backed by structured contract)
```

**`Clause`**: Template-level definition. Contains `id`, `category: ClauseCategory`, `title`, `body` (with `{{param}}` placeholders), `required: bool`, and `jurisdiction: Option<String>`. Required clauses must be present in every composition for that template; optional clauses may be jurisdiction-filtered.

**`ContractTemplate`**: Named, versioned collection of clauses for a specific `BailmentType`. The `id` is a stable identifier (e.g., `"custody-standard-v1"`), `name` is human-readable, `version` tracks the template revision.

**`ContractParams`**: All values needed to bind a template into a concrete contract. Includes party names and DIDs, effective/expiry dates (as `Timestamp` — HLC, no std::time), jurisdiction string, `DataClassification`, `liability_cap_bps` (basis points, u64 — no floating point), and `custom_params: DeterministicMap<String, String>` for extensibility.

**`ComposedContract`**: The fully rendered contract. `rendered_clauses: Vec<RenderedClause>` contains each clause with params substituted and section numbers assigned. `contract_hash: Hash256` is the CBOR-canonical hash of all rendered clauses plus params — this value becomes `terms_hash` on the `Bailment` struct. `version: u32` starts at 1, increments on amendments. `parent_contract_id: Option<String>` links amendments to their predecessor.

**`RenderedClause`**: A single clause with all placeholders resolved. `section_number` uses hierarchical numbering (e.g., "1", "2", "3.1") — currently flat by clause index but extensible.

**Relationship to Bailment**: `ComposedContract.contract_hash` is what gets set as `Bailment.terms_hash`. The bailment lifecycle (`propose → accept → active`) remains unchanged. The contract engine sits alongside it: compose a contract, get its hash, pass that hash to `bailment::propose()` as the terms bytes (or directly set `terms_hash`).

---

## 3. Clause Library

### Standard Clauses by BailmentType

**Custody** (8 clauses — one per category):
- DataCustody: "Bailee shall hold {{bailor_name}}'s data in secure custody without modification..."
- ProcessingRights: "No processing rights are granted. Bailee may only store and return data..."
- BreachRemedies: "Upon breach, {{bailor_name}} shall receive notice within {{breach_notice_days}} days..."
- LiabilityCaps: "Total liability capped at {{liability_cap_bps}} basis points of assessed value..."
- DisputeResolution: "Disputes under jurisdiction {{jurisdiction}} resolved via binding arbitration..."
- Termination: "Either party may terminate with {{termination_notice_days}} days written notice..."
- Jurisdiction: "This agreement governed by laws of {{jurisdiction}}..."
- Indemnification: "{{bailee_name}} shall indemnify {{bailor_name}} against third-party claims..."

**Processing** extends Custody clauses with:
- ProcessingRights: "Bailee may process data for purposes defined in this agreement. Processing scope: {{data_classification}} tier data..."
- Additional breach clauses for unauthorized processing

**Delegation** extends Processing with:
- Sub-delegation terms, chain-of-custody requirements
- Sub-bailee must maintain equivalent or stricter terms

**Emergency** has time-limited variants:
- All clauses include "Emergency access expires {{expiry_date}}..."
- Justification requirements in DataCustody clause
- Elevated audit logging requirements

### Parameterized Clauses

All clause bodies use `{{param_name}}` syntax. Standard parameters: `bailor_name`, `bailee_name`, `bailor_did`, `bailee_did`, `effective_date`, `expiry_date`, `jurisdiction`, `data_classification`, `liability_cap_bps`. Custom parameters from `ContractParams.custom_params` are also substituted.

### Clause Precedence

Required clauses (`required: true`) must always be present. Jurisdiction-specific clauses override universal clauses in the same category when the jurisdiction matches. If multiple clauses share a category, they are all included with sequential section numbers.

---

## 4. Contract Composition Flow

1. **Bailment Proposed**: Caller determines `BailmentType` and constructs `ContractParams`.
2. **Template Selected**: `default_template(bailment_type)` returns the canonical template. (Future: custom template registry.)
3. **Clauses Filtered**: Clauses with `jurisdiction: Some(j)` where `j != params.jurisdiction` are excluded. Required clauses with mismatched jurisdiction raise an error (constitutional: required clauses cannot be silently dropped).
4. **Parameters Bound**: Each clause body has `{{placeholder}}` strings replaced with concrete values from `ContractParams`. Standard params mapped first, then `custom_params`.
5. **Section Numbers Assigned**: Clauses numbered sequentially: "1", "2", "3", etc.
6. **Contract Hash Computed**: All `RenderedClause` structs plus key params serialized to canonical CBOR, then BLAKE3-hashed → `contract_hash: Hash256`.
7. **`terms_hash` Set**: `contract_hash` bytes passed to `Bailment.terms_hash` — the existing field now has a structured, verifiable backing.
8. **Parties Sign**: Bailment acceptance proceeds via existing `bailment::accept()` with signature.
9. **Contract Active**: The `ComposedContract` is stored alongside the `Bailment` for audit, rendering, and breach assessment.

---

## 5. Breach Detection & Settlement

### Breach Classification

- **Minor**: Non-material violation of a non-critical clause (e.g., late reporting). Remedy: `Notice`.
- **Material**: Violation of a substantive clause affecting data integrity or processing rights. Remedy: `Cure { cure_period_days: 30 }`.
- **Fundamental**: Violation that destroys trust basis (unauthorized data disclosure, identity fraud). Remedy: `Termination` + `Indemnification { amount_bps }`.

### Assessment Flow

`assess_breach(contract, breached_clause_ids, severity)`:

1. Validate all `breached_clause_ids` exist in the contract's rendered clauses. Unknown clause IDs → error (prevents phantom breach claims).
2. Assess severity against breached clause categories:
   - Minor → `Remedy::Notice`
   - Material → `Remedy::Cure { cure_period_days: 30 }`
   - Fundamental → `Remedy::Termination` if no LiabilityCaps clause breached; `Remedy::Indemnification { amount_bps: contract.params.liability_cap_bps }` if LiabilityCaps involved.
3. Generate `BreachAssessment` with: contract ID, severity, breached clause list, liability assessment in basis points, recommended remedy, timestamp.

### Settlement Integration

`BreachAssessment` feeds into the escalation crate (future integration). The `recommended_remedy` maps to bailment lifecycle transitions:
- `Notice` → no state change, informational
- `Cure` → bailment remains Active, cure period tracked
- `Suspension` → `bailment.status = Suspended`
- `Termination` → `bailment::terminate()`
- `Indemnification` → Termination + financial settlement record

---

## 6. Contract Versioning & Amendments

### Amendment Model

Amendments never modify the original `ComposedContract`. Instead, `amend()` creates a **new** `ComposedContract` with:
- `version` incremented (original is 1, first amendment is 2, etc.)
- `parent_contract_id = Some(original.id.clone())` — chain link
- New params and/or replaced clauses applied
- New `contract_hash` computed — the original's hash is untouched

### Diff Tracking

The amendment carries `parent_contract_id`, enabling reconstruction of the full amendment chain. Callers can diff rendered clauses between versions by comparing `rendered_clauses` vectors.

### Hash Chain Integrity

Each contract's `contract_hash` is self-contained — it hashes its own rendered content, not the parent. The `parent_contract_id` is a reference, not included in the hash (to keep hashes stable across chain lookups). Verification: `verify_hash(contract)` recomputes the hash from the contract's own `rendered_clauses` and `params`, independent of any parent.

---

## 7. Human-Readable Output

### Markdown Rendering

`render_markdown(contract)` produces a complete Markdown document:

```markdown
# Bailment Contract: {template_name}

**Contract ID**: {id}
**Version**: {version}
**Composed**: {composed_at}
**Effective**: {effective_date}
**Expires**: {expiry_date or "No expiration"}
**Jurisdiction**: {jurisdiction}
**Data Classification**: {data_classification}

## Parties

- **Bailor**: {bailor_name} ({bailor_did})
- **Bailee**: {bailee_name} ({bailee_did})

## {section_number}. {clause_title}

{rendered_body}

...

---
Contract Hash: {contract_hash}
```

### Section Numbering

Clauses are numbered sequentially starting from 1. Categories provide logical grouping in the template; the rendered document uses flat numbering for simplicity and legal clarity.

### Party Names

DID strings resolved to human-readable names via `ContractParams.bailor_name` / `bailee_name`. Both the name and DID appear in the Parties section for binding legal identity.

### PDF Generation Strategy

Same pipeline as the Board Book: render Markdown → HTML via template → PDF via server-side Puppeteer. Not implemented in this crate (exo-consent is a pure logic crate with no I/O dependencies), but the Markdown output is designed for direct conversion.

---

## 8. Integration Points

### bailment.rs (Extend, Don't Replace)

The contract engine is additive. Existing `bailment::propose()` still works with raw bytes. New workflow: `compose()` a contract, get `contract_hash`, pass `contract_hash.as_bytes()` as terms to `propose()`, or directly construct a `Bailment` with `terms_hash = contract.contract_hash`. No changes to `bailment.rs`, `policy.rs`, or `gatekeeper.rs`.

### Gatekeeper Integration

`ConsentGate` currently checks bailment status. Extension point: gatekeeper can also verify that a `ComposedContract` exists for the bailment's `terms_hash` and that `verify_hash()` passes. This adds structured contract validation to the consent check without modifying the gatekeeper's deny-by-default posture.

### Evidence Bundles

`ComposedContract` and its rendered Markdown output can be included in evidence bundles for disputes. The `contract_hash` provides content-addressed proof that the contract terms were agreed upon. `BreachAssessment` records reference specific clause IDs, enabling precise evidentiary linking.

### BCTS Lifecycle

The BCTS state machine (14-state lifecycle in `exo-core::bcts`) can reference `contract_hash` in transaction metadata. Receipt chaining includes the contract hash as part of the consent reference, tying every transaction to its governing contract.

---

## 9. Implementation Plan

### Build Sequence (Test-First)

1. **Error variants**: Add `ContractError` variant to `ConsentError` if needed, or use existing variants. (Decision: use existing `ConsentError` variants — `InvalidState`, `Unauthorized`, `Denied` cover all contract error cases, plus add a generic contract error.)

2. **Data types first**: Define all structs and enums in `contract.rs`. Derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize` where appropriate. No floating point anywhere — all monetary/percentage values are `u64` basis points.

3. **Write all 16 tests**: Tests define the contract (TDD). Each test compiles against the type signatures before implementations exist.

4. **`default_template()`**: Four match arms, one per `BailmentType`. Each returns 8 clauses (one per `ClauseCategory`). Templates are deterministic — no randomness.

5. **`compose()`**: Filter clauses by jurisdiction → substitute params → assign section numbers → serialize to CBOR → hash → build `ComposedContract`. Uses `hash_structured()` from `exo_core::hash`.

6. **`render_markdown()`**: String building with proper Markdown formatting. Pure function, no I/O.

7. **`assess_breach()`**: Validate clause IDs → classify severity → compute liability → recommend remedy.

8. **`amend()`**: Clone original → apply new params and clause replacements → increment version → set parent_contract_id → recompose → rehash.

9. **`verify_hash()`**: Recompute hash from contract contents → compare with stored `contract_hash`.

10. **Run tests, clippy, commit, push.**

### Constitutional Compliance Checklist

- [x] No floating point — `liability_cap_bps: u64`, `liability_assessment_bps: u64`
- [x] No HashMap — `DeterministicMap<String, String>` for custom_params
- [x] No unsafe code
- [x] No std::time — `Timestamp` (HLC) only
- [x] Canonical CBOR for hashing — `hash_structured()` from exo-core
- [x] All errors via thiserror — `ConsentError` variants
- [x] 90%+ test coverage — 16 tests covering all functions, edge cases, and invariants
