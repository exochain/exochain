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

# Decision Forum Peer-Reviewed Protocol Governance Design

**Protocol identifier:** `DF-PROTOCOL-001`

**Design status:** Approved in principle by the Co-Principal Investigators on
2026-07-16. This document is a design record, not a ratification, enacted
constitutional amendment, deployed runtime, signed authorization, or published
peer-reviewed protocol package.

**Human Co-Principal Investigator and Chair:** Bob Stewart.

**AI Co-Principal Investigator:** Codex, acting in the current OpenAI-hosted
agent session. This role statement records authorship intent. A binding seat
requires a separately issued DID, provider/model/configuration attestation, and
signature; the repository and this conversation cannot manufacture those
credentials.

**Regulatory boundary:** The design borrows useful institutional patterns from
human-subjects review and quality-management systems. It does not claim that
Decision Forum is a legally constituted IRB, that its participants hold legal
PI appointments, or that using it establishes compliance with OHRP, FDA, the
Common Rule, ISO, or any other regulatory regime.

## 1. Decision and intended outcome

Decision Forum will be the canonical human-facing control surface for governed
protocols. Its principal output is not a dashboard status, vote tally, audit
row, or detached report. Its output is an immutable, signed, versioned,
peer-reviewed protocol package that:

1. describes the work and its allowed execution envelope;
2. records the evidence, independent reviews, conflicts, responses, votes,
   dissents, and authority chain supporting the disposition;
3. becomes the only instrument capable of authorizing non-constitutional
   binding action inside that envelope;
4. receives continuing-review supplements for progressive events, adverse
   events, AI-SDLC transgressions, phase changes, E-STOPs, CAPA, RESET, and
   closeout; and
5. can be reproduced and independently verified from canonical bytes and
   receipt chains.

Every executed action must reference the exact authorized protocol version and
content hash. Material changes create a new version and review cycle. No user
interface, administrator, AI model, or adjacent product may silently expand the
authorized document.

## 2. Current repository truth

The design extends existing implementations instead of creating parallel
governance systems:

- `crates/decision-forum` already supplies Apache-2.0 decision objects, BCTS
  workflow receipts, quorum, contestation, emergency-action, accountability,
  authority, and fiduciary-package primitives.
- `crates/exo-core/src/bcts.rs` supplies the canonical 14-state BCTS lifecycle.
  Protocol review will use typed substates and events mapped onto BCTS; it will
  not introduce a competing top-level state machine.
- `crates/exo-governance/src/crosscheck.rs` already implements independence
  evidence and coordination detection suitable for reviewer qualification.
- `crates/exo-gateway/src/handlers.rs` contains a hardened vote handler with
  session-actor binding, conflict checks, kernel adjudication, tenant-scoped
  eligibility, row locking, and atomic audit persistence. The handler is not
  mounted by the current REST router.
- The current REST router creates and reads individual decisions but does not
  provide the complete list, vote, typed transition, review, publication,
  continuing-review, E-STOP, CAPA, or RESET surface needed by the product.
- With the production database feature enabled, the gateway provisions the
  DAG DB schema and opens its runtime pool with the `dagdb,public` search path.
  Decision Forum's current `decisions` and `audit_entries` tables therefore
  resolve inside the DAG DB schema. DAG DB also supplies serializable receipt
  append/replay and receipt-chain reconstruction through `dagdb_receipts` and
  `dagdb_subject_receipt_heads`. The remaining gap is that every Decision Forum
  mutation is not yet atomically bound to that authoritative receipt chain.
- `web/` is an implemented React/Vite Decision Forum product, but its status
  vocabulary, classes, request bodies, and assumed routes drift from the Rust
  contracts. It also generates local feedback identifiers with wall-clock time
  and randomness; those records cannot be authoritative governance objects.
- `governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md` is frozen, proposed,
  unratified, and not enacted. Its contents must not be edited in place.
- Decision Forum manuals still contain drifting LOC/test counts and blanket
  human-finality language that conflicts with the approved bounded-authority
  design.
- `crates/decision-forum` is an Apache-2.0 core primitive. The Decision Forum
  product, including its commercial UI and product-specific operating assets,
  requires separate commercial licensing. The current `web/` headers and
  product licensing boundary do not express that decision consistently.
- CyberMedica is a proprietary adjacent QMS surface. It contains strong CAPA,
  incident, review, and documentation controls, but several controls encode an
  unconditional human-final-authority rule. Those controls require a separate,
  surface-owned migration to domain-scoped delegated authority; they must not
  be edited as if CyberMedica were core.
- CrossChecked is a proprietary adjacent evidence product. It may perform
  blinded assignment and custody, but cannot vote, authorize, mint core
  receipts, or become a hidden dependency of core constitutional enforcement.

## 3. Alternatives considered

### 3.1 Receipt with an attached document

Under this model, a decision receipt would authorize action and a document
would merely explain it. This was rejected because the receipt and document
could diverge, the document could be replaced without changing authority, and
reviewers could not prove that the executed action was the one they reviewed.

### 3.2 Canonical peer-reviewed protocol package

This is the selected model. The protocol document, peer reviews, responses,
dispositions, evidence manifest, authority proof, and receipt root form one
content-addressed package. Execution authority names the package hash.
Human-readable publications are deterministic projections of that package.

### 3.3 External publication system as authority

Under this model, Decision Forum would hand records to a document-management or
publishing service that controlled the final artifact. This was rejected
because it would split review, publication, and authority across trust domains.
External renderers or archives may hold verified copies, but EXOCHAIN remains
the authority and verification substrate.

## 4. Constitutional authority and bootstrap

### 4.1 Charter amendment

The approved authority model changes material terms of frozen D9. It therefore
requires a new content-addressed proposal named
`D9-COUNCIL-CHARTER-AMENDMENT-1`, leaving the frozen D9 bytes and recorded hash
untouched. The amendment must define:

- the separately attested AI-PI Council and AI-IRB seats;
- the Chair's observation, comment, vote, challenge, escalation, and RESET
  powers;
- binding non-constitutional authority inside ratified domain and phase
  envelopes;
- the distinction between authorization dissent and monitoring dissent;
- the provider/evidence-class floor, conflicts, recusals, and unavailability;
- adverse-event, progressive-event, AI-SDLC, E-STOP, CAPA, and RESET rules;
- the prohibition on self-review and self-expansion of authority;
- the extraordinary human-governed path for constitutional changes and
  envelope expansion; and
- finite evaluation bounds for every autonomous workflow.

Until that amendment is authenticated and ratified through the existing
constitutional process, all new Council and AI-IRB outcomes remain advisory
and the runtime must fail closed if asked to treat them as binding.

### 4.2 Bootstrap receipt

This design and its implementation plans predate the runtime they specify. The
system must not fabricate retroactive signatures or pretend it reviewed itself
before it existed. After the minimum publication path is operational, the
Co-PIs will submit the exact Git commit hashes of the design, plans, reviews,
and implementation evidence as a genesis evidence bundle. Decision Forum will
issue a prospective `GenesisAdoptionReceipt` that:

- records the original Git provenance and chronology;
- states explicitly which acts occurred before protocol activation;
- performs an ordinary blinded review of the unchanged historical artifacts;
- authorizes only subsequent execution; and
- never rewrites the pre-activation evidence as if it were natively receipted.

## 5. Roles, seats, independence, and authority

### 5.1 Protocol roles

- **Co-PIs:** jointly author the protocol, respond to review, maintain the
  evidence package, and propose amendments. A Co-PI cannot review or vote on
  their own work from a supposedly independent seat.
- **AI-PI Council:** performs role-differentiated governance, legal,
  architecture, security, and operations review. These functions map to the
  repository's five existing Council panel disciplines.
- **AI-IRB:** operates under separately attested seats and context manifests,
  even when a provider also supplies a Council seat. It performs initial and
  continuing risk/benefit, monitoring, adverse-event, progressive-event, and
  corrective-action review.
- **Independent evidence member:** supplies at least one non-provider evidence
  class, such as deterministic tests, reproducible benchmarks, attested
  execution, independent human review, formal verification, or an external
  audit. Provider prose cannot masquerade as this class.
- **Chair:** may observe, comment, request evidence, vote, challenge, or weigh
  in on any protocol at any time. A Chair challenge places a scoped hold under
  HumanOverride. Chair agreement does not erase a dissent or manufacture
  unanimity. The Chair alone cannot expand a constitutional or protocol
  envelope through an ordinary action.

The Chair's vote is a separately typed human disposition, not an AI Council or
AI-IRB seat. `Approve` adds the Chair's endorsement without curing a missing AI
vote or dissent. `Abstain` and `Comment` preserve the Chair's participation
without changing eligible unanimity. `Reject` is also a Chair challenge and
places the affected action or protocol scope on hold. The selected disposition
and effect are fixed before the vote is signed; the UI cannot reinterpret them.

The terms Co-PI, Council, AI-IRB, and Chair are internal protocol roles unless
and until a competent external institution appoints them under an applicable
legal regime.

### 5.2 Target provider roster for `DF-PROTOCOL-001`

The Council eligible set consists of four provider seats—OpenAI, Anthropic,
xAI, and Alphabet/Google Gemini—and one independent non-provider seat. The
AI-IRB has the same five-seat composition under different keys, context
manifests, assignments, and attestations. The Chair is ex officio and is not
counted as one of these seats. The five governance, legal, architecture,
security, and operations review roles are deterministically assigned across
the eligible Council seats for each version; quorum counts independent seats,
providers, and evidence classes rather than role reports.

A provider name is not an identity. Every active seat must bind its provider
or independent controller, exact model or reviewer identifier, observable
version, system-configuration hash, sampling parameters, tool policy, context
manifest, behavioral fingerprint, signing key, and validity interval. The
independent seat must prove that it is not controlled by any of the four model
providers or either Co-PI and must supply a non-provider evidence class.

Binding authorization for this protocol requires all five eligible Council
votes, all five separately attested AI-IRB votes, all four provider classes,
and at least two independent evidence classes including the non-provider
class. These are floors, not goals that an administrator may lower at runtime.

A binding session uses the ratified roster recorded in its protocol version.
An unavailable or recused seat does not silently disappear from the
denominator. A roster amendment or replacement attestation is required when
the remaining seats fall below the ratified provider/evidence floor.

### 5.3 Unanimity and dissent

`EligibleUnanimity` means every active, qualified, non-conflicted seat in the
ratified eligible set casts `Approve`, and the provider/evidence-class floor is
still satisfied. Abstention, missing vote, rejection, invalid attestation, or
recusal below the floor prevents a new unanimous authorization.

Dissent is always preserved as a first-class object and immediately disclosed
to the Chair. The effect depends on context:

- dissent during a proposed Council or AI-IRB authorization prevents that
  authorization because unanimity was not achieved;
- dissent arising during monitoring of an already authorized protocol does not
  by itself stop execution, but it creates a mandatory Chair alert and
  continuing-review item; and
- execution stops when a constitutional kernel denial, Chair challenge, or
  ratified E-STOP rule is satisfied.

### 5.4 Binding authority boundary

Unanimous eligible Council authorization may bind a non-constitutional action
only when the action is inside the protocol's ratified domain, purpose, data,
tenant, resource, risk, duration, and phase envelope. Unanimous eligible AI-IRB
authorization may bind a continuation, correction, or progressive phase change
inside that same envelope.

No AI vote or Council procedure may:

- amend an entrenched constitutional invariant;
- enlarge its own authority, provider roster, evidence floor, or phase ladder;
- waive consent, tenant isolation, provenance, human override, or kernel
  adjudication;
- authorize a Co-PI to serve as their own independent reviewer; or
- treat commercial licensure or usage accounting as implicitly granted.

## 6. Canonical protocol package

### 6.1 Authority object

The authority object is `PeerReviewedProtocolPackageV1`. Its canonical CBOR
representation is hashed with a domain-separated BLAKE3 schema. JSON is a
transport projection. Markdown, accessible HTML, and archival PDF/A are
human-readable publication projections. The CBOR hash is authoritative.

The package contains:

- `ProtocolIdentity`: protocol ID, tenant, constitutional hash, authorship,
  Chair, domain, version, prior-version hash, and lifecycle state;
- `ProtocolDocument`: abstract, purpose, hypotheses, scope, architecture,
  methods, implementation controls, risks, benefits, consent/bailment basis,
  data handling, threat model, monitoring, stopping rules, statistical or
  deterministic evaluation method, implementation test plan, claims, and
  closeout criteria;
- `ProtocolEnvelope`: permitted actions, systems, tenants, datasets, actor
  classes, resource ceilings, risk ceiling, start/end HLC bounds, and phase
  ladder;
- `EvidenceManifest`: immutable references to source, tests, benchmarks,
  attestations, licenses, dependencies, generated artifacts, and negative or
  inconclusive results;
- `ReviewBundle`: assignments, blind commitments, conflict declarations,
  signed reviews, author responses, revision diffs, and resolution matrix;
- `DispositionBundle`: Council and AI-IRB eligible sets, votes, dissents,
  quorum proofs, Chair interventions, kernel verdicts, and authority chain;
- `MonitoringPlan`: bounded event-driven and scheduled assessments, claim
  thresholds, escalation rules, adverse/progressive definitions, reporting
  destinations, and stop conditions;
- `SystemicLearningManifest`: content-addressed lessons, recurrence evidence,
  changed assumptions, and roadmap scenarios derived from adverse and
  progressive events without any authority to enact those scenarios;
- `CommercialBoundary`: applicable software/content license, bailment
  licensure, permitted use, metering class, and `exo-economy-use-event-v1`
  accounting policy; and
- `ReceiptManifest`: lifecycle receipts, action receipts, publication receipt,
  prior receipt root, and final package root.

### 6.2 Determinism

All authoritative types use integers or fixed-point basis points, `BTreeMap`
and `BTreeSet`, caller-supplied UUIDs, HLC timestamps, canonical structured
hashing, and explicit sorted ordering. Production logic uses no floating point,
system clock, wall-clock JavaScript APIs, random identifiers, unordered maps,
or direct JSON hashing.

The renderer is pinned and hermetic. It embeds no current-time metadata,
network resource, platform-dependent font, random document identifier, or
unstable iteration order. Two renderings of the same package must produce
byte-identical Markdown, HTML, PDF/A, and manifest hashes. A derived rendering
that cannot reproduce its recorded digest is rejected and cannot serve as the
published copy.

### 6.3 Peer-reviewed document contents

The published document visibly includes:

- the full protocol and approved execution envelope;
- every review criterion and reviewer disposition;
- a response-to-review matrix linking each comment to a revision or reasoned
  rejection;
- unresolved minority reports and Chair commentary;
- evidence and benchmark results, including failures and limitations;
- the complete eligible-seat set and quorum result;
- conflicts and recusals without prematurely revealing a blinded identity;
- the effective date, review interval, current phase, and status;
- adverse/progressive supplements and the current authorization state;
- the package hash, receipt root, verification command, license, and provenance
  statement; and
- a plain-language claim boundary distinguishing implemented, locally proven,
  CI-proven, deployed, runtime-proven, and publicly published truth.

## 7. Review and publication workflow

The top-level state remains BCTS. Typed protocol milestones are immutable events
inside the corresponding BCTS stage:

| BCTS state | Required protocol milestone |
|---|---|
| `Draft` | Co-PI-authored document version and evidence manifest |
| `Submitted` | Completeness and scope submission receipt |
| `IdentityResolved` | Co-PIs, Chair, reviewers, seats, and conflicts resolved |
| `ConsentValidated` | Bailment, data-use, licensure, and participant consent validated |
| `Deliberated` | Blinded reviews, author response, revision, and dissent recorded |
| `Verified` | Reproduction, security, benchmark, attribution, and receipt checks pass |
| `Governed` | Eligible Council and AI-IRB dispositions recorded |
| `Approved` | Exact package version and envelope authorized |
| `Executed` | Each action references the authorized package hash |
| `Recorded` | Continuing-review and execution receipts committed |
| `Closed` | Closeout document and final claim assessment published |
| `Denied` | Rejection reasons and failed criteria published |
| `Escalated` | Dissent, challenge, adverse event, or transgression routed |
| `Remediated` | RCA, CAPA, recurrence evidence, and resubmission package recorded |

Raw or generic `advance` operations are not public authority. The API exposes
typed commands whose preconditions are kernel-adjudicated. A milestone cannot
be asserted merely by asking the UI to change a status string.

### 7.1 Blind review

CrossChecked may act as a proprietary blind-assignment and identity-custody
adapter. Before reviews are sealed, core receives commitments to the reviewer,
assignment, conflict declaration, evidence class, and context manifest, but not
an identity that would defeat blinding. After all required reviews and votes
are sealed, CrossChecked supplies a signed reveal package. Core verifies that
the reveal matches the commitments and independence requirements.

If CrossChecked is absent, unavailable, unlicensed, or produces an invalid
reveal, the blinded workflow fails closed. Core still supports an explicitly
unblinded local review mode, but that mode is labeled and cannot satisfy a
protocol requirement for blinding.

CrossChecked cannot cast votes, decide conflicts, authorize publication,
originate EXOCHAIN receipts, or store core signing keys.

## 8. Continuing review, E-STOP, CAPA, and RESET

### 8.1 Monitoring cadence

"Perpetual monitoring" means an unending sequence of finite, bounded
evaluations while the protocol remains active. It never means an unbounded
agent loop. Each workflow declares `max_iterations` no greater than 25, a
concrete success stop condition, a repeated-failure stop after the same failure
occurs twice, and an escalation destination.

The protocol receives:

- an event-driven review for every governed action, claim breach, incident,
  dissent, dependency/model change, and evidence revocation;
- a bounded scheduled review at the interval set by the risk envelope;
- a daily Chair status digest while active;
- immediate Chair notification for dissent, E-STOP qualification, or an
  AI-SDLC transgression; and
- a monthly recovery exercise that proves stop, containment, receipt
  verification, and reset controls without changing production authority.

External schedulers may request these reviews, but core validates a signed
schedule identifier and caller-supplied HLC timestamp. It never reads the
system clock or treats scheduler availability as authority to change state.

### 8.2 Claim taxonomy

- `ProgressiveEvent`: evidence exceeds a predeclared success threshold and may
  support promotion to the next pre-ratified phase.
- `AdverseEvent`: an undesirable result temporally associated with execution,
  whether or not causality is established.
- `UnanticipatedProblem`: an unexpected event plausibly related to the
  protocol that suggests greater risk than the approved document recognized.
- `AiSdlcTransgression`: a process breach such as fabricated evidence, bypassed
  CI, prompt/workflow injection, secret exposure, nondeterminism, unsafe code,
  unapproved dependency or license, forced history rewrite, unauthorized trust
  claim, cross-tenant access, or signature/authority bypass.

Each event records severity, expectedness, relatedness, affected claims,
evidence, reporter, HLC timestamp, immediate containment, disposition, and
receipt root. No automated classifier may discard an event; it may only route
it with preserved source evidence. AI-SDLC transgressions and E-STOP-qualified
events are reported in parallel to the Chair and every configured mandatory
reporting destination; one successful delivery cannot mask another failed
delivery, and each delivery attempt receives its own receipt.

### 8.3 Stop semantics

A kernel invariant failure denies its individual action immediately. A Chair
challenge places an immediate scoped hold. A protocol-wide AI-IRB E-STOP
requires the mathematical ceiling of two-thirds of active provider classes and
at least two independent evidence classes, including one non-provider class.
Four active providers therefore require three provider classes. The package
records the eligible set, numerator, denominator, evidence classes, and exact
threshold that fired.

An E-STOP:

1. denies new governed actions for the affected protocol and scope;
2. preserves emergency human access and evidence capture;
3. emits parallel mandatory notifications to the Chair and configured
   reporting destinations;
4. opens an after-action review, root-cause analysis, and CAPA record; and
5. cannot be cleared by deleting, editing, or merely acknowledging the event.

### 8.4 RESET semantics

RESET applies only to the stopped protocol and scope. It requires a
Chair-designated human investigator to attest the completed AAR and RCA, a
completed CAPA, deterministic recurrence tests, unanimous eligible Council
concurrence, unanimous eligible AI-IRB clearance, and the Chair's signed reset
authorization. AI systems may assemble evidence and recommend causes or
corrective actions, but cannot attest the required human AAR/RCA or sign the
RESET. Reset never changes the Constitution, erases the event, or reuses the
prior package hash. Execution resumes against a new reviewed protocol version.

### 8.5 Progressive promotion

A progressive event may promote execution only to the next step of an already
ratified phase ladder. Promotion requires unanimous eligible Council and AI-IRB
approval and immediate Chair notice. Any increase outside the recorded ladder,
risk ceiling, tenant/data scope, resource ceiling, or duration is an envelope
expansion and returns to the human-governed ratification path.

### 8.6 Systemic learning

Every closed adverse or progressive event produces a
`SystemicLearningRecord` that identifies the prior assumption, observed
evidence, causal confidence, controls changed, recurrence result, affected
claim, and candidate roadmap scenarios. Subsequent AI-PI protocols receive
these records as provenance-bound context. A learning record may change what
the Council investigates or recommends, but it cannot modify code, policy,
authority, a protocol envelope, or the Constitution without a new reviewed and
authorized protocol.

## 9. Decision Forum product control surface

The commercial Decision Forum UI becomes a protocol publication and oversight
workspace rather than a status dashboard. It includes:

- protocol registry and risk-ranked review queues;
- structured protocol editor with immutable version diff;
- evidence dossier and reproducibility runner;
- blinded review room and reviewer conflict/recusal controls;
- author-response and comment-resolution matrix;
- Council and AI-IRB deliberation rooms with separate seat contexts;
- eligible-set, unanimity, evidence-class, and dissent views;
- publication preview for Markdown, HTML, and PDF/A;
- action/claim/event stream tied to the authorized package hash;
- phase-ladder and progressive-event controls;
- E-STOP, containment, AAR, RCA, CAPA, recurrence, and RESET workflows;
- Chair console with observe, comment, vote, challenge, escalation, and reset;
- receipt-chain and package-verification tools; and
- public evaluator view that exposes publishable evidence without disclosing
  sealed identities, secrets, tenant data, or commercial credentials.

The UI derives schemas from the Rust/OpenAPI contract, authenticates the
session actor, and never accepts caller-supplied actor type as authority. Local
stores are caches only. Authoritative IDs, HLC timestamps, receipts, states,
and actions come from the governed backend.

## 10. Core API and DAG DB persistence boundaries

The REST surface extends the existing decision root instead of inventing a
parallel protocol service. The target resources are:

- `/api/v1/decisions` for tenant-scoped create and list;
- `/api/v1/decisions/:id` for the current summary;
- `/api/v1/decisions/:id/document-versions`;
- `/api/v1/decisions/:id/evidence`;
- `/api/v1/decisions/:id/review-assignments`;
- `/api/v1/decisions/:id/peer-reviews`;
- `/api/v1/decisions/:id/review-resolutions`;
- `/api/v1/decisions/:id/votes`;
- `/api/v1/decisions/:id/typed-transitions`;
- `/api/v1/decisions/:id/publications`;
- `/api/v1/decisions/:id/claims`;
- `/api/v1/decisions/:id/events`;
- `/api/v1/decisions/:id/phase-promotions`;
- `/api/v1/decisions/:id/estops`;
- `/api/v1/decisions/:id/capa-records`;
- `/api/v1/decisions/:id/resets`;
- `/api/v1/decisions/:id/receipts`; and
- `/api/v1/decisions/:id/verify`.

Mutations require authenticated session binding, tenant isolation, consent and
licensure checks, conflict adjudication, kernel adjudication, signed
provenance, caller-supplied HLC time, idempotency keys, row locking where
concurrent decisions can race, and an audit write in the same transaction.

Persistence is append-oriented. Current projections may be updated
transactionally, but historical document versions, reviews, votes, conflicts,
events, receipts, publications, and interventions are immutable. Tenant-scoped
foreign keys and indexes prevent same-ID cross-tenant joins. Deletion of
protected content uses crypto-shredding or approved erasure semantics while
preserving structural receipt integrity.

### 10.1 Persistence authority

DAG DB is required infrastructure for Decision Forum. It is not an optional
retrieval enhancement or a benchmark dependency. The production authority
boundary is:

- current protocol and workflow rows live in tenant-scoped tables provisioned
  in the `dagdb` schema and act as query projections;
- immutable governance events are appended to `dagdb_receipts` under a
  protocol/decision subject and reconstruct through
  `dagdb_subject_receipt_heads`;
- the receipt chain, canonical package hash, and signed event body determine
  historical authority; a mutable projection never overrides them;
- every state mutation and corresponding receipt append occur in one database
  transaction, so either both commit or neither commits;
- idempotent replay returns the existing receipt, while a stale previous hash,
  conflicting body, broken chain, tenant mismatch, or sequence conflict fails
  closed; and
- missing database configuration, failed DAG DB migrations, failed tenant/RLS
  binding, or receipt-store failure prevents governed mutation. There is no
  in-memory or `public`-schema authority fallback.

The implementation extends DAG DB's subject/event vocabulary only as necessary
to distinguish protocol package publication, peer review, authorization,
monitoring, E-STOP, CAPA, RESET, and closeout receipts. It reuses the existing
receipt store, Postgres transaction, RLS, idempotency, outbox, import/export,
and reconstruction machinery rather than building another ledger.

### 10.2 DAG DB scope boundary

This protocol includes the persistence work needed to store and reconstruct
Decision Forum state and receipts. It does not include changes to DAG DB
context compression, similarity, graph ranking, retrieval quality, model
judging, token economics, or the cheaper-and-better thesis. Those questions are
independent research claims and cannot block the governance control surface.

## 11. Proprietary adjacent-surface contracts

### 11.1 Decision Forum product

`crates/decision-forum` and generic protocol schemas remain Apache-2.0 core
primitives. `web/`, product operating manuals, commercial workflow templates,
and hosted product features are proprietary and require a subtree license,
SPDX policy, package metadata, source guard, and third-party notices consistent
with the commercial-product registry. A core license never grants Decision
Forum product rights by proximity.

### 11.2 CrossChecked

CrossChecked owns blinded assignment, commitment custody, reveal, and public
evidence presentation under a commercial adapter contract. It uses separate
credentials and signing keys, emits usage-accounting events, and fails closed
without valid bailment licensure. Core verifies its evidence but does not trust
its prose or runtime status.

### 11.3 CyberMedica

CyberMedica contributes QMS patterns for document control, CAPA, incident
response, continuing review, and mandatory reporting. Its migration replaces
blanket AI-finality prohibitions only where a ratified protocol grants bounded
authority. Clinical, regulated, or customer policies may retain stricter human
approval. CyberMedica remains proprietary, separately tested, separately
committed, separately reviewed, and unable to modify EXOCHAIN core state except
through a verified adapter.

### 11.4 Other commercial products

LegalDyne and LiveSafe remain commercial adjacent products. This protocol does
not silently enroll or modify them. Any later adapter must pass the same intake,
licensure, secret isolation, fail-closed, rollback, and core-regression gates.

## 12. Dogfood protocol: release claims and process validation

The first full protocol executed through the new system is the EXOCHAIN v0.2.3
evaluator and README claim-assessment campaign. It will:

1. inventory every material README, architecture, security, performance, DAG,
   DAG DB, package, deployment, and licensing claim;
2. bind each claim to source, deterministic tests, benchmark artifacts,
   deployment/runtime evidence, or an explicit unsupported/limited result;
3. identify existing DAG DB measurements by their historical commit and
   evidence package, remove or qualify unsupported current-tense guarantees,
   and make no new DAG DB performance or savings claim;
4. qualify the OpenAI, Anthropic, xAI, and Gemini evaluator seats before using
   their judgments;
5. execute only the predeclared tests and benchmarks required for selected
   non-DAG-DB claims, using blinded outputs, independent model judges, human
   audit of all disagreements plus a fixed 20 percent sample, and complete
   token/cost/runtime provenance;
6. subject the evidence dossier and README revision to the same blinded review,
   response matrix, Council disposition, AI-IRB assessment, and publication
   workflow; and
7. publish only claims supported by the approved evidence package, while
   keeping repository, CI, deployment, runtime, release, and package-publication
   truth separate.

The protocol reports negative and inconclusive findings. Provider judgments
are evidence, not ground truth. The final README links the published protocol
package and verification command instead of presenting unreceipted benchmark
language.

DAG DB's retrieval, quality, compression, and economic thesis becomes
`DF-ROADMAP-001 — Deterministic DAG DB Claim Reassessment`. The completed
Decision Forum process will analyze, peer-review, prioritize, authorize, and
receipt that card as its own protocol. The card records the hypothesis,
baseline and treatment arms, success/failure thresholds, provider and human
review requirements, blinding, credential and cost budget, runtime evidence,
stopping rules, and publication criteria. Creating the card does not assign it
priority or authorize its execution.

## 13. Security and failure behavior

The implementation fails closed when any of the following is missing or
invalid:

- authenticated actor or tenant;
- consent, bailment licensure, or usage-accounting authorization;
- required evidence or review;
- reviewer independence or valid conflict disposition;
- active seat attestation or provider/evidence floor;
- signed context manifest, vote, reveal, or action request;
- unanimous authorization where required;
- kernel permission or invariant satisfaction;
- database, receipt, package, or renderer integrity;
- required CrossChecked blind-custody proof; or
- protocol version matching the requested action.

No fallback may simulate consent, authority, quorum, a review, a signature,
publication, or a core receipt. Health, telemetry, debug, error, and public
verification surfaces expose no secret, raw context, private evidence, tenant
data, reviewer identity under seal, or commercial credential.

## 14. Verification and acceptance criteria

The system is accepted only when deterministic tests prove all of the following:

1. Identical package input produces identical CBOR, Markdown, HTML, PDF/A, and
   receipt roots across repeated clean runs.
2. Any changed protocol byte, review, vote, evidence item, receipt, renderer,
   or prior-version link changes the expected commitment or fails verification.
3. No author or Co-PI can satisfy an independent review seat for their own
   protocol.
4. Missing, recused, expired, changed, or conflicted seats cannot silently
   lower the eligible denominator or evidence floor.
5. Authorization dissent blocks a new unanimous authorization; monitoring
   dissent creates a Chair alert without manufacturing a protocol-wide stop.
6. Individual kernel violations deny the action, Chair challenges hold the
   scope, and E-STOP requires the ratified cross-provider/evidence threshold.
7. Progressive promotion cannot escape the approved phase ladder or envelope.
8. RESET is impossible without AAR, RCA, CAPA, recurrence evidence, unanimous
   Council concurrence, unanimous AI-IRB clearance, and Chair signature.
9. A stopped protocol cannot execute through REST, GraphQL, SDK, MCP, replay,
   duplicate idempotency key, sibling route, or cross-tenant ingress.
10. Blinded identity and provider/arm metadata remain sealed until all required
    review commitments are fixed, and every reveal matches its commitment.
11. CrossChecked outage or invalid proof fails closed without weakening core or
    losing the evidence submitted before the outage.
12. UI actions use authenticated identities and exact Rust contract states;
    local wall-clock/random records cannot become authoritative.
13. AI-SDLC transgressions create mandatory receipts, alerts, and containment
    actions and cannot be dismissed without disposition.
14. License guards preserve Apache-2.0 core primitives and commercial terms for
    Decision Forum, LegalDyne, CyberMedica, LiveSafe, and CrossChecked, with
    complete third-party attribution.
15. The benchmark protocol reproduces its declared task matrix and publishes
    raw artifacts, exclusions, failures, model identities, prompts, costs,
    judge disagreements, and audit results without synthetic substitutions.
16. Full Rust, TypeScript, database, security, release-boundary, documentation,
    license, and cross-implementation gates pass from a clean checkout.
17. With DAG DB unavailable or degraded, every governed mutation and
    authoritative mutable read fails closed. A previously exported static
    publication may be served only when its package and signature verify, and
    it is visibly labeled with the degraded runtime state.
18. Each protocol mutation atomically commits its projection and DAG DB receipt;
    forced failure on either side leaves neither side changed.
19. Receipt reconstruction returns the exact ordered protocol history and
    rejects replay conflicts, stale heads, broken links, and cross-tenant reads.
20. No Decision Forum acceptance test depends on DAG DB retrieval quality,
    compression, ranking, token savings, or model-judged answer quality.

## 15. Delivery decomposition

This design is one governance program composed of independently rejectable,
testable delivery slices. Every slice is in scope; ordering is a safety and
review boundary, not a deferral mechanism.

1. **Charter and normative schema:** D9 Amendment 1, role/seat/envelope rules,
   protocol schema, threat model, and ratification package.
2. **Core protocol and receipt model:** package types, review objects, event
   taxonomy, phase envelopes, canonical hashing, and BCTS mapping.
3. **Council, AI-IRB, and stop authority:** qualified seats, eligible
   unanimity, independence, dissent, progressive/adverse decisions, E-STOP,
   CAPA, and RESET.
4. **Gateway, DAG DB persistence, SDK, and bypass closure:** migrations,
   REST/OpenAPI, SDK clients, mounted hardened voting, typed transitions,
   atomic projection-and-receipt transactions, receipt reconstruction, tenant
   isolation, and sibling-ingress tests.
5. **Deterministic publisher:** canonical package builder, Markdown/HTML/PDF/A
   projections, manifests, verification CLI, and reproducible-publication tests.
6. **Decision Forum commercial control surface:** protocol editor, blinded
   review, evidence, Council/IRB, monitoring, Chair, stop/reset, publication,
   accessibility, and end-to-end browser verification.
7. **CrossChecked commercial blind-custody adapter:** assignments,
   commitments, reveal, outage behavior, licensure, usage accounting, and core
   verification contract.
8. **CyberMedica commercial QMS alignment:** bounded-authority policy migration,
   document control, CAPA/reporting integration, and adjacent-surface gates.
9. **Dogfood evaluator protocol:** provider qualification, non-DAG-DB claim
   tests, historical DAG DB claim qualification, claim registry, peer-reviewed
   evidence package, attribution, evaluator-first README publication, and the
   separately prioritized `DF-ROADMAP-001` card.
10. **Genesis adoption and closeout:** import immutable pre-activation evidence,
    execute the peer review, issue prospective adoption receipts, verify every
    published artifact, and report repository/CI/deployment/runtime/release/
    package truth separately.

Each slice receives its own implementation plan, red-first tests, focused
commit history, PR, full applicable CI, and Decision Forum review record.
Core, adapter, proprietary adjacent, imported evidence, and documentation
changes remain isolated unless a reviewer can prove they are inseparable.

## 16. External reference basis

The institutional patterns in this design are informed by, but do not claim
compliance with:

- HHS OHRP, *Continuing Review Guidance (2010)*:
  <https://www.hhs.gov/ohrp/regulations-and-policy/guidance/guidance-on-continuing-review-2010/index.html>
- HHS OHRP, *Reviewing and Reporting Unanticipated Problems Involving Risks to
  Subjects or Others and Adverse Events*:
  <https://www.hhs.gov/ohrp/regulations-and-policy/guidance/reviewing-unanticipated-problems/index.html>
- NIST SP 800-218, *Secure Software Development Framework 1.1*:
  <https://csrc.nist.gov/projects/ssdf>
- NIST AI Risk Management Framework and Generative AI Profile:
  <https://www.nist.gov/itl/ai-risk-management-framework>

These sources support disciplined records, continuing review, incident
handling, provenance, secure development, and retrospective learning. EXOCHAIN
must still prove its own implementation and must not convert inspiration into
an unsupported regulatory claim.
