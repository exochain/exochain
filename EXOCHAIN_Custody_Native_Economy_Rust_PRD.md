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

# PRD: EXOCHAIN Custody-Native Transaction Economy

**Working title:** EXO Settlement / Custody Economy  
**Target repo:** `exochain/exochain`  
**Language:** Rust  
**Primary crate to add:** `crates/exo-economy`  
**Product thesis:** EXOCHAIN should preserve the transaction mechanism of a blockchain while making most human trust operations zero-cost or near-zero-cost. Fees should appear where autonomous actors, holons, commercial workflows, compute, value, or legal-grade custody create economic consequence.

---

## 1. Executive Summary

EXOCHAIN should not price itself as “blockchain transactions for everything.” That would tax trust and harm adoption.

Instead, EXOCHAIN should operate as a **custody-native blockchain**:

- Humans get a near-free trust fabric.
- Autonomous agents and holons pay low-friction vigorish where they create commercial value, consume compute, require high-assurance custody, or externalize risk.
- Every custody-significant event may still have a transaction envelope, quote, receipt, and settlement record — even when the charged price is `0`.
- Pricing should be adaptive but deterministic: governed by integer-only rate cards, basis points, floors, ceilings, subsidies, and revenue-sharing policies.

The core product outcome:

> Stand up an EXOCHAIN node and humans get a near-free platform for identity, consent, trust, and chain-of-custody; holons, agents, commercial automations, and compute-heavy workflows provide the economic metabolism of the network.

---

## 2. Strategic Decision

### Should value/use/compute “market” be the price?

**Yes — but not as an unbounded spot market.**

The price should be produced by a deterministic **Value × Use × Compute** quote engine:

1. **Value**: value-at-risk, realized value, revenue-generating status, legal/commercial consequence.
2. **Use**: event type, assurance level, retention needs, custody anchoring, validation frequency, network utilization.
3. **Compute**: model calls, verification work, proof generation, enclave use, storage, bandwidth, policy evaluation.

The output is a `SettlementQuote` with:

- deterministic price
- zero-fee reason if applicable
- fee breakdown
- revenue-share breakdown
- expiry
- policy version
- hashable canonical payload

The system should support adaptive price plasticity, but all adaptation must be:

- deterministic
- bounded
- auditable
- explainable
- integer-only
- governed by policy
- never dependent on floating-point arithmetic

---

## 3. Brand / Category Frame

### Public framing

**EXOCHAIN**  
Chain-of-custody for autonomous execution.

### Mechanism framing

A custody-native blockchain with transaction envelopes, receipts, settlement, and decentralized verification.

### Economic framing

A decentralized evidence economy where the network is paid when trust, compute, value, or custody become economically meaningful.

### Core maxim

> Do not charge every breath. Charge the moments where autonomous trust becomes economically consequential.

---

## 4. Goals

1. Add a Rust-native economic policy and settlement layer.
2. Preserve transaction envelopes for zero-fee and paid events alike.
3. Default low-risk human trust operations to `0` or near-zero charges.
4. Charge holons, agents, and commercial workflows using governed adaptive pricing.
5. Support tiered revenue sharing across protocol, node operators, validators, app layer, credential issuers, compute providers, and other contributors.
6. Produce signed, hash-chained settlement receipts.
7. Provide quote-before-settlement APIs.
8. Make pricing explainable and auditable from receipts.
9. Keep all arithmetic deterministic and integer-only.
10. Ensure no fee setting can bypass constitutional governance or chain-of-custody invariants.

---

## 5. Non-Goals

1. Do not implement a public token launch in this PR.
2. Do not integrate fiat rails in this PR.
3. Do not implement external exchange pricing in this PR.
4. Do not implement ML-driven pricing in this PR.
5. Do not create a speculative fee market that makes human trust expensive.
6. Do not block zero-fee actions from producing receipts.
7. Do not require every low-value validation to anchor full state on-chain.
8. Do not introduce floating-point arithmetic.

---

## 6. Key Concepts

### 6.1 Custody Transaction

A custody transaction is any event that EXOCHAIN should be able to prove, price, subsidize, settle, or revenue-share.

Examples:

- AVC issuance
- AVC validation
- AVC delegation
- AVC revocation
- agent passport lookup
- consent grant
- consent revocation
- trust receipt anchoring
- legal-grade evidence export
- compute invocation
- holon commercial action
- governance vote
- escalation action
- human approval
- agent-to-agent settlement

A custody transaction may have `charged_amount = 0`.

Zero-priced does **not** mean untracked. It means subsidized, free-tier, public-good, human baseline, or policy-waived.

---

### 6.2 Adaptive Price Plasticity

Price plasticity means the quote engine can adjust price based on value, use, compute, risk, assurance, and demand.

However, EXOCHAIN price plasticity must be bounded by policy:

- floor
- ceiling
- subsidy allowance
- actor class cap
- assurance class cap
- revenue-share rules
- quote expiry
- governance version

This makes pricing dynamic enough to feed the network, but predictable enough for enterprise trust.

---

### 6.3 Vigorish

Vigorish is the small network take on economically meaningful agent/holon activity.

In EXOCHAIN terms, vigorish is not a tax on trust. It is a protocol fee applied to:

- commercial value capture
- compute consumption
- high-assurance custody
- legal-grade proof
- autonomous settlement
- agent/holon marketplace activity

---

### 6.4 Revenue Sharing

Every paid transaction may distribute proceeds across recipients using basis points.

Potential recipients:

- protocol treasury
- node operator
- validator set
- custody verifier
- CommandBase / app layer
- credential issuer
- compute provider
- data subject / data owner
- referral / originator
- policy domain treasury
- insurance / reserve pool

Revenue sharing must be deterministic and auditable.

---

## 7. Proposed Rust Architecture

### 7.1 New Crate

Add:

```text
crates/exo-economy/
```

Suggested modules:

```text
crates/exo-economy/src/lib.rs
crates/exo-economy/src/error.rs
crates/exo-economy/src/types.rs
crates/exo-economy/src/policy.rs
crates/exo-economy/src/quote.rs
crates/exo-economy/src/price.rs
crates/exo-economy/src/settlement.rs
crates/exo-economy/src/revenue_share.rs
crates/exo-economy/src/receipt.rs
crates/exo-economy/src/store.rs
crates/exo-economy/src/tests.rs
```

Add `crates/exo-economy` to workspace members in root `Cargo.toml`.

---

### 7.2 Integrations

Integrate with:

- `exo-core` for `Did`, `Hash256`, `Timestamp`, canonical hashing, signatures.
- `exo-catapult` for budget and cost-event compatibility.
- `exo-node` for HTTP routes.
- `exo-api` for exported API types if appropriate.
- `exochain-sdk` for client wrappers.
- `exo-avc` if/when the AVC crate exists.
- `exo-governance` for governed policy updates.

---

## 8. Data Model

### 8.1 Amount Type

Use integer-only amounts.

```rust
pub type MicroExo = u128;
pub type BasisPoints = u32; // 0..=10_000
```

Rationale:

- `u128` gives room for high-value settlements.
- `MicroExo` supports tiny micro-fees without floats.
- Basis points maintain deterministic percentages.

No floating-point arithmetic is permitted.

---

### 8.2 ActorClass

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActorClass {
    Human,
    HumanSponsoredAgent,
    AutonomousAgent,
    Holon,
    Enterprise,
    Validator,
    PublicGood,
    Unknown,
}
```

---

### 8.3 EventClass

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventClass {
    IdentityResolution,
    AgentPassportLookup,
    AvcIssue,
    AvcValidate,
    AvcDelegate,
    AvcRevoke,
    ConsentGrant,
    ConsentRevoke,
    TrustReceiptCreate,
    CustodyAnchor,
    ComputeInvocation,
    ValueSettlement,
    GovernanceVote,
    Escalation,
    LegalEvidenceExport,
    HolonCommercialAction,
    AgentToAgentHandshake,
}
```

---

### 8.4 AssuranceClass

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssuranceClass {
    Free,
    Standard,
    Anchored,
    LegalGrade,
    Regulated,
    Critical,
}
```

---

### 8.5 PricingMode

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingMode {
    Zero,
    CostRecovery,
    UsageMetered,
    ValueShare,
    ComputeMarket,
    Hybrid,
}
```

---

### 8.6 ZeroFeeReason

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroFeeReason {
    HumanBaseline,
    PublicGood,
    FreeTier,
    Subsidized,
    PolicyWaived,
    InternalTest,
    GovernanceWaiver,
}
```

---

### 8.7 PricingInputs

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingInputs {
    pub actor_did: Did,
    pub actor_class: ActorClass,
    pub event_class: EventClass,
    pub assurance_class: AssuranceClass,

    /// Optional value-at-risk or declared economic value in MicroExo.
    pub declared_value_micro_exo: Option<MicroExo>,

    /// Optional realized value in MicroExo for revenue-sharing events.
    pub realized_value_micro_exo: Option<MicroExo>,

    /// Estimated compute units for model calls, proof generation, enclave work, etc.
    pub compute_units: u64,

    /// Estimated storage bytes for durable custody.
    pub storage_bytes: u64,

    /// Number of verification operations.
    pub verification_ops: u64,

    /// Network load index in basis points. 10_000 = normal.
    pub network_load_bp: BasisPoints,

    /// Risk score in basis points. 0 = no risk, 10_000 = maximum risk.
    pub risk_bp: BasisPoints,

    /// Optional tenant, policy domain, or market namespace.
    pub market_domain: Option<String>,

    pub timestamp: Timestamp,
}
```

---

### 8.8 EconomyPolicy

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomyPolicy {
    pub id: String,
    pub version: String,
    pub is_active: bool,

    /// Unit rates.
    pub compute_unit_price_micro_exo: MicroExo,
    pub storage_byte_price_micro_exo: MicroExo,
    pub verification_op_price_micro_exo: MicroExo,

    /// Global protocol vigorish.
    pub protocol_vig_bp: BasisPoints,

    /// Human baseline rules.
    pub human_zero_fee_enabled: bool,
    pub human_max_charge_micro_exo: MicroExo,

    /// Floors and ceilings.
    pub global_floor_micro_exo: MicroExo,
    pub global_ceiling_micro_exo: MicroExo,

    /// Value-share defaults.
    pub value_share_bp: BasisPoints,
    pub risk_share_bp: BasisPoints,

    /// Multipliers are represented as basis points.
    /// 10_000 = 1.0x, 20_000 = 2.0x, 5_000 = 0.5x.
    pub actor_multipliers: Vec<ActorMultiplier>,
    pub event_multipliers: Vec<EventMultiplier>,
    pub assurance_multipliers: Vec<AssuranceMultiplier>,

    /// Revenue sharing templates by event class.
    pub revenue_share_templates: Vec<RevenueShareTemplate>,
}
```

Validation rules:

- `id` and `version` must not be empty.
- All basis point values must be `<= 10_000` unless explicitly documented as multipliers that may exceed `10_000`.
- Multipliers must have a bounded maximum, e.g. `<= 100_000` for 10x.
- `global_floor_micro_exo <= global_ceiling_micro_exo`.
- If `human_zero_fee_enabled`, human baseline events must quote `0` unless event class is excluded by policy.

---

### 8.9 SettlementQuote

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementQuote {
    pub id: String,
    pub policy_id: String,
    pub policy_version: String,
    pub actor_did: Did,
    pub actor_class: ActorClass,
    pub event_class: EventClass,
    pub assurance_class: AssuranceClass,

    pub pricing_mode: PricingMode,
    pub zero_fee_reason: Option<ZeroFeeReason>,

    pub gross_amount_micro_exo: MicroExo,
    pub discount_amount_micro_exo: MicroExo,
    pub subsidy_amount_micro_exo: MicroExo,
    pub charged_amount_micro_exo: MicroExo,

    pub breakdown: PriceBreakdown,
    pub revenue_shares: Vec<RevenueShareLine>,

    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub quote_hash: Hash256,
}
```

---

### 8.10 PriceBreakdown

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceBreakdown {
    pub compute_component_micro_exo: MicroExo,
    pub storage_component_micro_exo: MicroExo,
    pub verification_component_micro_exo: MicroExo,
    pub value_component_micro_exo: MicroExo,
    pub risk_component_micro_exo: MicroExo,
    pub assurance_component_micro_exo: MicroExo,
    pub network_load_component_micro_exo: MicroExo,
    pub protocol_vig_micro_exo: MicroExo,
}
```

---

### 8.11 RevenueShareLine

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevenueRecipient {
    ProtocolTreasury,
    NodeOperator { did: Did },
    ValidatorSet,
    CustodyVerifier { did: Did },
    AppLayer { app_id: String },
    CredentialIssuer { did: Did },
    ComputeProvider { did: Did },
    DataSubject { did: Did },
    InsuranceReserve,
    PolicyDomain { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueShareLine {
    pub recipient: RevenueRecipient,
    pub share_bp: BasisPoints,
    pub amount_micro_exo: MicroExo,
}
```

Validation:

- Sum of `share_bp` must be `<= 10_000`.
- Sum of allocated amounts must be `<= charged_amount_micro_exo`.
- Remainder may go to `ProtocolTreasury` or be explicitly recorded as `UnallocatedRemainder` if needed.

---

### 8.12 SettlementReceipt

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub id: String,
    pub quote_hash: Hash256,
    pub actor_did: Did,
    pub event_class: EventClass,
    pub charged_amount_micro_exo: MicroExo,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub revenue_shares: Vec<RevenueShareLine>,
    pub custody_transaction_hash: Hash256,
    pub prev_settlement_receipt: Hash256,
    pub timestamp: Timestamp,
    pub content_hash: Hash256,
    pub signature: Signature,
}
```

---

## 9. Pricing Algorithm

### 9.1 Deterministic Formula

Pseudo-code:

```rust
fn quote(policy: &EconomyPolicy, input: &PricingInputs) -> Result<SettlementQuote> {
    validate_policy(policy)?;
    validate_inputs(input)?;

    if qualifies_for_zero_fee(policy, input) {
        return zero_fee_quote(policy, input, ZeroFeeReason::HumanBaseline);
    }

    let compute = u128::from(input.compute_units)
        .saturating_mul(policy.compute_unit_price_micro_exo);

    let storage = u128::from(input.storage_bytes)
        .saturating_mul(policy.storage_byte_price_micro_exo);

    let verification = u128::from(input.verification_ops)
        .saturating_mul(policy.verification_op_price_micro_exo);

    let cost_base = compute
        .saturating_add(storage)
        .saturating_add(verification);

    let value_component = match input.realized_value_micro_exo.or(input.declared_value_micro_exo) {
        Some(value) => apply_bp(value, policy.value_share_bp),
        None => 0,
    };

    let risk_component = match input.declared_value_micro_exo {
        Some(value) => apply_bp(value, policy.risk_share_bp)
            .saturating_mul(u128::from(input.risk_bp))
            .saturating_div(10_000),
        None => 0,
    };

    let actor_mult = actor_multiplier(policy, input.actor_class);
    let event_mult = event_multiplier(policy, input.event_class);
    let assurance_mult = assurance_multiplier(policy, input.assurance_class);

    let mut gross = cost_base
        .saturating_add(value_component)
        .saturating_add(risk_component);

    gross = apply_multiplier(gross, actor_mult);
    gross = apply_multiplier(gross, event_mult);
    gross = apply_multiplier(gross, assurance_mult);
    gross = apply_multiplier(gross, input.network_load_bp);

    let protocol_vig = apply_bp(gross, policy.protocol_vig_bp);
    gross = gross.saturating_add(protocol_vig);

    let charged = gross
        .max(policy.global_floor_micro_exo)
        .min(policy.global_ceiling_micro_exo);

    build_quote(policy, input, gross, charged, breakdown)
}
```

`apply_bp(amount, bp)` and `apply_multiplier(amount, multiplier_bp)` must use saturating integer arithmetic.

---

### 9.2 Zero-Fee Rules

Default zero-fee candidates:

- Human identity resolution.
- Human agent passport lookup below abuse thresholds.
- Basic AVC validation for personal/non-commercial use.
- Consent grant/revocation by a human data subject.
- Public-good governance access.
- Low-volume human approval receipts.

Never zero by default:

- legal-grade evidence export
- regulated custody anchoring
- high-volume holon validation
- commercial agent-to-agent activity
- compute-heavy proof generation
- autonomous settlement
- revenue-generating holon action

---

### 9.3 Policy Examples

#### Human baseline

```text
ActorClass: Human
EventClass: AvcValidate
AssuranceClass: Standard
charged_amount_micro_exo: 0
zero_fee_reason: HumanBaseline
```

#### Holon commercial action

```text
ActorClass: Holon
EventClass: HolonCommercialAction
AssuranceClass: Anchored
PricingMode: Hybrid
Price = compute + custody anchor + value share + protocol vig
```

#### Legal-grade evidence export

```text
ActorClass: Enterprise
EventClass: LegalEvidenceExport
AssuranceClass: LegalGrade
PricingMode: UsageMetered
Price = verification + storage + legal-grade assurance multiplier + protocol vig
```

#### Compute invocation

```text
ActorClass: AutonomousAgent
EventClass: ComputeInvocation
AssuranceClass: Standard
PricingMode: ComputeMarket
Price = compute pass-through + network vig + compute provider revenue share
```

---

## 10. Tiered Revenue Sharing

### 10.1 Tiers

#### Tier 0: Human / Public Trust Fabric

- Mostly free.
- Receipts still generated.
- Subsidy accounting optional.
- Abuse thresholds may apply.

Revenue:

- 0 charged.
- Optional public-good subsidy ledger.

---

#### Tier 1: Agent / Holon Micro-Use

- Very low cost.
- High volume.
- Minimal friction.

Revenue split example:

```text
ProtocolTreasury: 2000 bp
NodeOperator: 3000 bp
ValidatorSet: 3000 bp
AppLayer: 1000 bp
InsuranceReserve: 1000 bp
```

---

#### Tier 2: Commercial Value Capture

- Applies when action creates revenue, performs paid work, executes a transaction, or settles value.

Revenue split example:

```text
ProtocolTreasury: 1500 bp
NodeOperator: 1500 bp
ValidatorSet: 2000 bp
AppLayer: 2000 bp
CredentialIssuer: 1000 bp
ComputeProvider: 1000 bp
InsuranceReserve: 1000 bp
```

---

#### Tier 3: Regulated / Legal-Grade Custody

- Higher assurance.
- Longer retention.
- More verification.
- More formal receipts.

Revenue split example:

```text
ProtocolTreasury: 2000 bp
NodeOperator: 2000 bp
ValidatorSet: 2500 bp
CustodyVerifier: 1500 bp
InsuranceReserve: 1500 bp
AppLayer: 500 bp
```

---

#### Tier 4: Compute Market

- Compute provider receives pass-through economics.
- EXOCHAIN takes a small network vigorish.
- Quote must show compute, custody, and vig separately.

Revenue split example:

```text
ComputeProvider: 8000 bp
ProtocolTreasury: 500 bp
NodeOperator: 500 bp
ValidatorSet: 500 bp
AppLayer: 500 bp
```

---

## 11. API Requirements

Add economy routes to `exo-node`.

### 11.1 Quote

```http
POST /api/v1/economy/quote
```

Request:

```json
{
  "actor_did": "did:exo:agent-123",
  "actor_class": "Holon",
  "event_class": "HolonCommercialAction",
  "assurance_class": "Anchored",
  "declared_value_micro_exo": "100000000",
  "realized_value_micro_exo": null,
  "compute_units": 1200,
  "storage_bytes": 2048,
  "verification_ops": 3,
  "network_load_bp": 10000,
  "risk_bp": 1500,
  "market_domain": "commandbase",
  "timestamp": { "physical_ms": 1765000000000, "logical": 0 }
}
```

Response:

```json
{
  "quote_id": "quote_...",
  "charged_amount_micro_exo": "12345",
  "zero_fee_reason": null,
  "pricing_mode": "Hybrid",
  "quote_hash": "...",
  "expires_at": { "physical_ms": 1765000060000, "logical": 0 },
  "breakdown": { ... },
  "revenue_shares": [ ... ]
}
```

---

### 11.2 Settle

```http
POST /api/v1/economy/settle
```

Request:

```json
{
  "quote_hash": "...",
  "custody_transaction_hash": "...",
  "actor_signature": "..."
}
```

Response:

```json
{
  "settlement_receipt_id": "setrec_...",
  "charged_amount_micro_exo": "12345",
  "content_hash": "...",
  "signature": "..."
}
```

---

### 11.3 Read Receipt

```http
GET /api/v1/economy/receipts/:id
```

---

### 11.4 Policy

```http
GET /api/v1/economy/policy/active
```

Governed update endpoint:

```http
POST /api/v1/economy/policy/propose
```

Policy updates must go through governance; no unauthenticated policy mutation.

---

## 12. SDK Requirements

Add SDK functions:

```rust
pub async fn quote_economy_event(input: PricingInputs) -> Result<SettlementQuote>;
pub async fn settle_economy_event(input: SettlementInput) -> Result<SettlementReceipt>;
pub async fn get_settlement_receipt(id: &str) -> Result<SettlementReceipt>;
pub async fn get_active_economy_policy() -> Result<EconomyPolicy>;
```

---

## 13. Storage Requirements

For initial implementation, support in-memory store with deterministic tests.

If `exo-node` has persistence available, add SQL-backed storage later.

Minimum store trait:

```rust
pub trait EconomyStore {
    fn put_quote(&mut self, quote: SettlementQuote) -> Result<()>;
    fn get_quote(&self, quote_hash: &Hash256) -> Result<Option<SettlementQuote>>;
    fn put_receipt(&mut self, receipt: SettlementReceipt) -> Result<()>;
    fn get_receipt(&self, id: &str) -> Result<Option<SettlementReceipt>>;
    fn get_active_policy(&self) -> Result<EconomyPolicy>;
    fn set_active_policy(&mut self, policy: EconomyPolicy) -> Result<()>;
}
```

---

## 14. Receipt / Hashing Requirements

Every quote and settlement receipt must be canonical-hashed.

Use explicit domain tags:

```rust
pub const ECONOMY_QUOTE_HASH_DOMAIN: &str = "exo.economy.quote.v1";
pub const SETTLEMENT_RECEIPT_HASH_DOMAIN: &str = "exo.economy.settlement_receipt.v1";
```

Settlement receipts must form a hash chain per node or per policy domain:

```rust
prev_settlement_receipt: Hash256
```

---

## 15. Abuse / Safety Requirements

Zero-fee does not mean unlimited.

Add optional free-tier controls:

- per-DID quote rate limit
- per-DID zero-fee daily quota
- per-event abuse counter
- governance override
- quarantine integration with agent standing

If abuse thresholds are exceeded, the actor may be quoted under `UsageMetered` or `CostRecovery` even for otherwise free event classes.

---

## 16. Test Plan

### Unit Tests

1. Human baseline event quotes zero.
2. Zero-fee quote still produces non-zero `quote_hash`.
3. Holon commercial event produces non-zero charge.
4. Compute invocation includes compute component.
5. Legal-grade export applies assurance multiplier.
6. Revenue share basis points sum to `<= 10_000`.
7. Revenue share amounts sum to `<= charged_amount_micro_exo`.
8. Policy rejects invalid basis points.
9. Policy rejects floor greater than ceiling.
10. Quote rejects expired timestamp or invalid input.
11. Settlement rejects expired quote.
12. Settlement rejects tampered quote hash.
13. Settlement receipt verifies content hash.
14. Price calculation is deterministic across repeated runs.
15. Saturating arithmetic prevents overflow.
16. Human max charge cap is enforced.
17. Network load multiplier is bounded.
18. Subsidy amount cannot exceed gross amount.
19. Zero-fee event records `ZeroFeeReason`.
20. No floating-point arithmetic is introduced.

### Integration Tests

1. `POST /api/v1/economy/quote` returns a valid quote.
2. `POST /api/v1/economy/settle` creates a receipt.
3. Quote + settle works for zero-fee human event.
4. Quote + settle works for paid holon event.
5. Revenue-share breakdown is present in settlement receipt.
6. Active policy endpoint returns deterministic policy.
7. Invalid actor DID returns 400.
8. Expired quote settlement returns 409 or 422.

---

## 17. Acceptance Criteria

A PR is accepted when:

1. `crates/exo-economy` builds under workspace constraints.
2. Root workspace includes the new crate.
3. Unit tests pass.
4. Integration tests for quote and settlement pass.
5. Human baseline quote can return `charged_amount_micro_exo = 0`.
6. Holon/commercial quote can return a non-zero charge.
7. Settlement receipts are canonical-hashed and signed or signing-ready.
8. Revenue-share lines are deterministic and validated.
9. No floats are used.
10. Public API exposes quote-before-settle behavior.
11. Zero-fee transactions still produce quote hashes and settlement receipts.
12. The implementation does not require a public token launch.

---

## 18. Suggested Implementation Phases

### Phase 1: Core Crate

- Create `exo-economy`.
- Implement types, policy validation, quote function, revenue-share function.
- Implement in-memory store.
- Add unit tests.

### Phase 2: Settlement Receipts

- Add canonical hash payloads.
- Add receipt content hashing.
- Add receipt chain field.
- Add settlement validation.

### Phase 3: Node API

- Add `exo-node` routes.
- Add state wiring.
- Add JSON request/response types.
- Add integration tests.

### Phase 4: SDK

- Export quote and settlement helpers from `exochain-sdk`.

### Phase 5: Governance Wiring

- Require governed policy update path.
- Add active policy versioning.
- Add policy receipt event.

---

## 19. Suggested PR Title

```text
Add custody-native economy crate with zero-fee human trust and adaptive holon settlement
```

---

## 20. Suggested PR Description

```text
This PR introduces `exo-economy`, a deterministic Rust settlement layer for EXOCHAIN custody transactions.

The economy layer preserves transaction envelopes for all custody-significant events while allowing most human trust operations to settle at zero cost. Holons, autonomous agents, commercial workflows, compute-heavy actions, legal-grade exports, and high-assurance custody events can be priced through a governed Value × Use × Compute quote engine.

Key features:
- integer-only `MicroExo` accounting
- zero-fee human baseline policy
- adaptive but bounded pricing
- revenue-share templates in basis points
- canonical quote hashes
- settlement receipts
- quote-before-settle API model
- deterministic tests

This PR does not implement a public token launch or external fiat rails. It provides the internal economic substrate required for EXOCHAIN to function as a custody-native blockchain for autonomous execution.
```

---

## 21. North Star

EXOCHAIN should feel free to humans and inevitable to agents.

The chain should not tax trust.

It should collect a small, transparent share where autonomous action creates value, consumes compute, requires legal-grade custody, or settles across trust boundaries.

> Human trust layer: near-free.  
> Holon economy: metered.  
> Compute market: pass-through plus vigorish.  
> Commercial autonomy: value-share.  
> Legal custody: premium assurance.  
> Everything: receipted.
