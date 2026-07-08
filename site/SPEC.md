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

# EXOCHAIN Web Presence — Specification

**Document status:** v1.0 — initial scoping and MVP build plan
**Scope:** Public website, authenticated extranet, internal intranet
**Owners:** EXOCHAIN product, protocol, and operations leads
**Posture:** Alpha. Nothing on this site claims production decentralization, regulatory approval, or completed audit unless explicitly backed by published artifacts.

---

## 1. Positioning

**Primary headline:** EXOCHAIN is chain-of-custody for autonomous execution.

**Subheadline:** Credential autonomous intent, verify delegated authority, and preserve evidentiary custody for agents, holons, humans, and AI-native systems.

**Frame to keep in mind:** *Credentialed volition. Evidentiary execution. Chain-of-custody for autonomous systems.*

EXOCHAIN is a custody-native blockchain. Blockchain is the mechanism. Chain-of-custody is the purpose. EXOCHAIN preserves custody of what autonomous actors actually do. AVC (Autonomous Volition Credential) credentials what an autonomous actor is authorized to pursue.

The economic layer is **zero-priced launch settlement**: the transaction mechanism exists, quotes and receipts can be issued, but every active price resolves to zero with an explicit `ZeroFeeReason` until governance amends the policy.

---

## 2. Three surfaces at a glance

| Surface | Audience | Auth | Domain (proposed) | Purpose |
|---|---|---|---|---|
| **Internet** | Public — developers, enterprises, researchers, regulators, press, candidates | None | `exochain.io` | Authoritative public narrative, docs, trust center, status |
| **Extranet** | Authenticated external users — devs, customers, partners, validators, auditors, agent operators | OIDC + role | `app.exochain.io` | Issue AVCs, validate, view custody trails, run nodes, export audit packets |
| **Intranet** | Internal EXOCHAIN operators, maintainers, governance, security, support, legal | OIDC + SSO + role + step-up MFA | `internal.exochain.io` | Network ops, governance controls, pricing policy, content, incidents |

All three surfaces are served by a single Next.js app behind a CDN, with hard route separation enforced by middleware and a session-scoped role check at the layout boundary. In production, the three host names should resolve to separate Vercel/Cloud Run deployments with distinct environment variables and access policies.

---

## 3. Brand and voice

- Serious, technical, trustworthy, future-forward, institution-grade.
- *Evidentiary trust substrate*, not crypto startup. *Custody and accountability*, not AI buzzword. *Protocol and governance infrastructure*, not dashboard SaaS.
- Clear enough for developers. Credible enough for boards, auditors, insurers, legal teams, and regulators. Inspiring enough for autonomous-systems researchers and AI-native venture builders.
- **Avoid leading with:** crypto, token, speculation, DeFi, Web3 hype, AI wrapper, generic agent platform, generic automation platform.
- **Avoid imagery:** neon crypto clichés, generic AI robot art, glowing cubes, glitch fonts.
- **Use imagery:** custody trails, chains, credentials, receipts, command/control surfaces, network nodes, evidence packets, restrained line diagrams.

### 3.1 Vocabulary (use consistently)

EXOCHAIN · Autonomous Volition Credential · AVC · chain-of-custody · custody-native blockchain · autonomous execution · evidentiary execution · trust receipt · settlement receipt · delegated authority · agent identity · holon · consent · revocation · custody verifier · governance · policy enforcement · zero-priced launch settlement · custody fabric · agent economy · human trust layer · machine-readable trust.
LYNK Protocol · receipted LLM usage · MCP tools/call receipt · receipt_minimized · LLM usage evidence.

### 3.2 Conceptual one-liners

- Blockchain is the mechanism. Chain-of-custody is the purpose.
- AVC credentials intent. EXOCHAIN receipts execution.
- Identity proves who an actor is. AVC proves what it may pursue.
- Trust is not paywalled. Value-bearing autonomous execution can be metered later.
- EXOCHAIN turns autonomous action into evidentiary custody.

---

## 4. Information architecture

### 4.1 Internet (public) — sitemap

```
/
├── /why                         Why EXOCHAIN
├── /chain-of-custody            Chain-of-custody for AI
├── /avc                         Autonomous Volition Credentials
├── /trust-receipts              Trust receipts
├── /lynk                        LYNK Protocol public discovery
├── /custody-native-blockchain   Custody-native blockchain
├── /developers                  Developer landing
├── /docs                        Docs index
│   ├── /docs/getting-started
│   ├── /docs/concepts
│   ├── /docs/avc
│   ├── /docs/trust-receipts
│   ├── /docs/settlement
│   ├── /docs/node-api
│   ├── /docs/validator-guide
│   ├── /docs/security
│   ├── /docs/governance
│   ├── /docs/glossary
│   └── /docs/faq
├── /api                         API reference (OpenAPI viewer)
├── /node                        Node / validator overview
├── /trust-center                Trust center
├── /security                    Security page
├── /governance                  Governance overview
├── /research                    Whitepapers & technical notes
├── /status                      Public status
├── /blog                        Field notes
├── /contact                     Contact / early access
├── /brand                       Brand & press kit
└── /legal
    ├── /legal/privacy
    └── /legal/terms
```

### 4.2 Extranet (authenticated) — sitemap

```
/app
├── /app/login                   Auth
├── /app                         Dashboard
├── /app/org                     Organization profile
├── /app/actors                  Actor registry (humans, orgs, agents, holons, services, validators)
├── /app/avcs                    AVC index
│   ├── /app/avcs/issue          Issue AVC
│   └── /app/avcs/validate       Validate AVC
├── /app/revocations             Revocations
├── /app/trust-receipts          Trust receipt explorer
├── /app/settlement-quotes       Zero-priced settlement quotes
├── /app/settlement-receipts     Settlement receipts (amount = 0)
├── /app/custody-trails          Custody trail explorer
├── /app/nodes                   Node operations (operator role)
├── /app/validators              Validator onboarding (validator role)
├── /app/api-keys                API keys
├── /app/webhooks                Webhooks
├── /app/audit-exports           Audit packet exports
├── /app/policy-domains          Policy domain registry
├── /app/consent-records         Consent records
├── /app/support                 Support requests
├── /app/security-requests       Responsible-disclosure submissions
└── /app/settings                Account / org settings
```

### 4.3 Intranet (internal) — sitemap

```
/internal
├── /internal/login              Internal SSO
├── /internal                    Operations dashboard
├── /internal/network            Network operations
├── /internal/nodes              Node health
├── /internal/validators         Validator registry
├── /internal/actors             Actor registry (read/quarantine)
├── /internal/avcs               AVC registry
├── /internal/revocations        Revocation console
├── /internal/trust-receipts     Trust receipt explorer
├── /internal/settlement         Settlement receipt explorer
├── /internal/pricing-policy     Zero pricing policy config + future config
├── /internal/governance         Governance controls
├── /internal/security           Security review queue
├── /internal/incidents          Incident management
├── /internal/audit              Audit export queue
├── /internal/content            Content management (public site + docs)
├── /internal/docs-mgmt          Documentation management
├── /internal/users              User / org management
├── /internal/support            Support queue
├── /internal/research           Research library
├── /internal/releases           Release notes / feature flags
├── /internal/feature-flags      Feature flag console
└── /internal/logs               System logs
```

---

## 5. Roles and permissions

### 5.1 Extranet roles

| Role | Capabilities | Notes |
|---|---|---|
| `org_admin` | Manage org profile, users, API keys, billing config (placeholder) | One per org minimum |
| `developer` | Issue/validate AVCs in test scope, manage API keys, view docs | Default new-user role |
| `enterprise_user` | Read-only over org's AVCs, receipts, custody trails | For non-engineering enterprise stakeholders |
| `partner` | Federated read across declared shared scopes | Requires partnership agreement |
| `validator_operator` | Validator onboarding, key rotation, node telemetry | Gated by hardware attestation |
| `node_operator` | Run a node, view local telemetry | Lower bar than validator |
| `auditor` | Read-only across all org AVCs, receipts, custody trails, with exportable audit packets | Time-bounded scope |
| `researcher` | Read-only over anonymized aggregate metrics; no PII | For approved academic or industry research |
| `credential_issuer` | Issue AVCs on behalf of declared issuer scope | Requires issuer registration |
| `custody_verifier` | Run verifier service; see verification logs | Verifier daemons, not humans |
| `agent_operator` | Manage agent/holon actors, scope, parent delegations | Operates on behalf of agents |
| `legal_reviewer` | View consent records, policy domains, audit exports | No issuance, no revocation |
| `support_user` | Submit and track tickets only | Default for invited business contacts |

### 5.2 Intranet roles

| Role | Capabilities | Step-up MFA required |
|---|---|---|
| `super_admin` | Full read/write across intranet | Yes, for any write |
| `protocol_maintainer` | Releases, feature flags, network ops | Yes |
| `security_admin` | Security queue, revocation, incident command | Yes |
| `governance_admin` | Governance controls, pricing policy edits | Yes (and quorum) |
| `node_ops` | Node health, validator registry | Yes for writes |
| `support` | Read-only over user issues | No |
| `legal_compliance` | Consent records, audit exports, policy review | Yes for exports |
| `product` | Content, docs, release notes, feature flag reads | Yes for content publish |
| `devrel` | Public blog, developer docs publish | Yes for publish |
| `content_admin` | Public site CMS | Yes for publish |
| `incident_commander` | Open/close incidents, status writes | Yes |
| `auditor_internal` | Read-only over governance and audit trails | No |

### 5.3 Permission matrix (excerpt)

| Action | Public | Extranet roles | Intranet roles |
|---|---|---|---|
| View public docs | ✅ | ✅ | ✅ |
| Issue AVC | — | `developer`, `org_admin`, `credential_issuer`, `agent_operator` | `super_admin` (test only) |
| Revoke AVC | — | Issuer org admins for own scope | `security_admin`, `governance_admin` (with quorum) |
| Edit pricing policy | — | — | `governance_admin` (with quorum + step-up) |
| Publish blog post | — | — | `devrel`, `content_admin`, `super_admin` |
| Open incident | — | — | `incident_commander`, `security_admin`, `super_admin` |
| Export audit packet | — | `auditor`, `legal_reviewer`, `org_admin` (own org) | `legal_compliance`, `super_admin` |

Every administrative action — extranet or intranet — writes an audit log entry with actor, scope, action, target, and outcome. Audit logs are append-only and surfaced to the relevant org or internal team.

---

## 6. Page-by-page content outline

### 6.1 Internet

#### `/` Home
- Hero: headline + subheadline + two primary CTAs (`/developers`, `/contact`).
- Architecture band: Identity → Authority → Volition → Consent → Execution → Custody Receipt.
- Three-pillar block: AVC explainer · Trust receipt explainer · Zero-priced launch settlement explainer.
- "Blockchain is the mechanism. Chain-of-custody is the purpose." callout.
- Three CTAs by audience: Developers · Enterprises · Validators / Researchers.
- Status strip: alpha · network mode · last release · public status link.
- Footer with full sitemap, legal, brand, contact.

#### `/why`
- Problem: autonomous systems can act faster than institutions can verify authority.
- Gap: identity alone is not enough; access control alone is not enough; logs alone are not enough.
- Solution: chain-of-custody for autonomous execution.
- Worked examples: a delegated trade, a delegated procurement action, a delegated medical workflow assist (each as a small narrative, never reproducing third-party content).

#### `/chain-of-custody`
- What chain-of-custody means in evidentiary contexts (general, then technical).
- How EXOCHAIN extends it to autonomous execution.
- Diagram: human → AVC → agent → EXOCHAIN → trust receipt → revocation/extension cycle.
- Distinction between chain (sequence) and custody (responsibility).

#### `/avc`
- Definition: AVC is a portable, signed, machine-verifiable credential that declares what an autonomous actor is authorized to pursue **before** it acts.
- Identity vs. authority vs. volition vs. execution.
- Important disclaimer: AVC does not claim consciousness or human-like will. *Volition* here is delegated operational intent, scoped and revocable.
- Worked examples: human → agent, enterprise → department agent, agent → child agent, holon participation, revocation cascade.
- Validity is fail-closed and deterministic. Delegation strictly narrows scope.

#### `/trust-receipts`
- Definition: a trust receipt is a hash-chained, signed record proving identity, authority, consent, policy, action, timestamp, revocation state, and custody hash for a single execution event.
- Sample receipt fields with annotated JSON.
- Trust receipt vs. settlement receipt: trust receipts always exist; settlement receipts exist when the economic layer is invoked.

#### `/lynk`
- Public discovery page for the EXOCHAIN LYNK Protocol.
- Classify `/site` as an adjacent public surface: the page may describe the tested adapter path, but must not imply the public site performs constitutional enforcement.
- Name V1 tested lanes: OpenAI Responses, OpenAI Chat Completions, and MCP `tools/call`.
- Point to the actual core receipt endpoint: `POST /api/v1/avc/llm-usage/receipts/emit`.
- Explain `receipt_minimized` privacy posture without including prompts, completions, tool arguments, tool results, provider keys, bearer credentials, KMS material, object-store locations, or decryptable payload material.
- Future waves remain fail-closed until separately implemented and tested.

#### `/custody-native-blockchain`
- The blockchain mechanism is preserved. The "chain" is reframed as chain-of-custody.
- Validators are *custody verifiers*. Block production is custody attestation, not just transaction ordering.
- Determinism, post-quantum readiness, constitutional governance, no floating-point arithmetic.
- Zero-priced launch settlement: every active price resolves to zero with explicit `ZeroFeeReason`.

#### `/developers`
- Quickstart: install the SDK, register an actor, issue an AVC, validate, generate a trust receipt, generate a zero settlement quote, fetch a settlement receipt.
- SDK matrix (Rust today; Node/TypeScript and Python on the roadmap).
- API surface overview, links to `/api` and `/docs`.
- Run-a-node link (`/node`) and validator guide (`/docs/validator-guide`).
- GitHub link placeholder.

#### `/docs`
- Sidebar navigation across the 11 doc sections.
- Each doc page is a structured Markdown document rendered through MDX in a future iteration; in the MVP, doc pages are hand-authored TSX.
- Mark unstable APIs clearly with an "Unstable" pill.

#### `/api`
- Embeds an OpenAPI viewer (Swagger UI / Redocly) once `exo-gateway` ships its public OpenAPI document. Until then, link to spec snapshot in `/docs/node-api`.

#### `/node`
- What an EXOCHAIN node is. Operator vs. validator roles.
- Hardware and network expectations. Attestation requirements for validators (placeholder copy until verified).
- Where to onboard: `/app/validators`.

#### `/trust-center`
- Security posture, threat model link (link to public summary, full matrix internal).
- Cryptographic assumptions: ML-DSA-65 (CRYSTALS-Dilithium) signatures, hybrid signature support, deterministic signing.
- Responsible disclosure policy.
- Audit readiness statement (current capabilities vs. roadmap, clearly distinguished).
- Compliance roadmap (SOC 2 Type I/II, ISO 27001, NIST AI RMF mapping — listed as roadmap items, not claims of certification).
- Privacy and data-custody posture.
- Zero-priced launch policy (with link to `/internal/pricing-policy` for operators only).
- Status link.

#### `/security`
- Threat model summary, public bug bounty intent (placeholder).
- Coordinated disclosure email, PGP key, scope statement.

#### `/governance`
- Constitutional invariants (governance kernel summary).
- How protocol changes happen (proposal lifecycle, quorum, ratification).
- Where governance lives in the codebase (link to public governance documents in `governance/`).

#### `/research`
- Whitepapers index with abstracts.
- Technical notes index.
- Governance and agent-economy papers as published.

#### `/status`
- Network mode banner: `alpha · testnet · pre-release`.
- Node count placeholder, validator count placeholder, peer count placeholder, last committed height placeholder.
- Uptime widgets per service: gateway, node API, docs, status itself.
- Known incidents list with severity and resolution state. **No fake green checks.** When metrics are mocked, label them `mock`.

#### `/blog`
- Reverse-chron list. Posts are MDX in `/web/content/blog`.

#### `/contact`
- Early access form: name, email, role, organization, intended use, anti-spam.
- Press contact, partnership contact, security contact (links to `/security`).

#### `/brand`
- Logo lockups, color tokens, typography, do/don't usage.

#### `/legal/privacy` and `/legal/terms`
- Boilerplate placeholder authored by counsel before public launch. Not production legal text.

### 6.2 Extranet (`/app`)

Each extranet page presents the same shell (left rail nav, top bar with org switcher and role badge, content area, audit log drawer).

**Dashboard (`/app`)** — counts: active AVCs, active actors, recent trust receipts, recent settlement quotes, pricing-policy banner ("Zero-priced launch settlement is in effect"), API health pill.

**Org profile (`/app/org`)** — org details, verified domains, designated issuer scope, default policy domain, designated auditors.

**Actors (`/app/actors`)** — table over `Actor` records with type filter (human/org/agent/holon/service/validator). Actions: register, deactivate, view trust trail.

**AVCs (`/app/avcs`)** — table over `AVC` records with status filter (active/expired/revoked/quarantined). Detail panel shows scope, parent, expiry, signers, revocation history, derived receipts.

**Issue AVC (`/app/avcs/issue`)** — multi-step form: subject actor → scope (policy domain + actions) → parent delegation (optional) → expiry → policy expressions → review (cryptographic preview of payload) → sign and issue. Generates AVC ID and downloadable JSON.

**Validate AVC (`/app/avcs/validate`)** — paste an AVC token or upload JSON, submit to the validator service, render a structured validation result (PASS / FAIL with deterministic reason codes).

**Revocations (`/app/revocations`)** — list with cause codes, initiator, cascade preview before commit. Revocation requires step-up auth.

**Trust receipts (`/app/trust-receipts`)** — searchable explorer over `TrustReceipt` records. Drill into receipt → custody trail.

**Settlement quotes (`/app/settlement-quotes`)** — generate a quote (always shows `amount = 0` with `ZeroFeeReason: launch_policy_zero`). Visible banner: *Zero-priced launch settlement is in effect. The transaction mechanism is live; pricing is suppressed by policy.*

**Settlement receipts (`/app/settlement-receipts`)** — list of issued receipts; all amounts zero. Clearly distinguishes from trust receipts.

**Custody trails (`/app/custody-trails`)** — given an actor, AVC, or receipt, render the full hash-chained trail with provenance.

**Nodes (`/app/nodes`)** — for `node_operator` role: register a node, view local telemetry (mocked in MVP).

**Validator onboarding (`/app/validators`)** — for `validator_operator` role: hardware attestation upload, key registration, observation period status.

**API keys (`/app/api-keys`)** — create/rotate keys; show key once at creation only. Per-key scopes.

**Webhooks (`/app/webhooks`)** — subscribe to events (AVC.issued, AVC.revoked, TrustReceipt.created, SettlementReceipt.created, etc.) with signed payload verification details.

**Audit exports (`/app/audit-exports`)** — request an audit packet by date range and scope; downloads as a deterministic, signed bundle.

**Policy domains (`/app/policy-domains`)** — registry of declared policy domains the org operates within.

**Consent records (`/app/consent-records`)** — view consent grants attached to AVCs (subject, principal, scope, expiry, revocation status).

**Support (`/app/support`)** and **security requests (`/app/security-requests`)** — ticket submission with severity selector. Security requests are routed to the internal security queue.

**Settings (`/app/settings`)** — user profile, MFA, sessions, notification preferences.

### 6.3 Intranet (`/internal`)

Same shell concept but with stricter chrome (system-status header, environment label, redaction toggles).

**Dashboard (`/internal`)** — health summary, open incidents, security queue depth, pending governance proposals, pricing-policy summary (must show all active prices = 0 with `ZeroFeeReason`).

**Network ops (`/internal/network`)** — gateway status, validator quorum, peer mesh, replication lag.

**Node health (`/internal/nodes`)** — per-node telemetry, alerts.

**Validator registry (`/internal/validators`)** — list of validators, attestation state, slashing history (placeholder).

**Actor registry (`/internal/actors`)** — read-only or quarantine-only over external actors.

**AVC registry (`/internal/avcs`)** — full read access, with redaction defaults; ability to mark suspicious or quarantine where policy allows.

**Revocation console (`/internal/revocations`)** — emergency revocation flow with quorum approval workflow.

**Trust receipt explorer (`/internal/trust-receipts`)** and **settlement explorer (`/internal/settlement`)** — same as extranet, broader scope.

**Pricing policy (`/internal/pricing-policy`)** — current policy state, edit form for future pricing parameters. Active prices remain zero; future config is staged behind a feature flag and a quorum.

**Governance controls (`/internal/governance`)** — open proposals, quorum status, ratification.

**Security review queue (`/internal/security`)** — incoming responsible-disclosure reports, triage, status.

**Incident management (`/internal/incidents`)** — open, update, close, link to public status writes.

**Audit export queue (`/internal/audit`)** — pending packets, signing state, delivery state.

**Content management (`/internal/content`)** — public marketing pages (Home, Why, etc.) editor.

**Documentation management (`/internal/docs-mgmt`)** — docs editor with publish workflow.

**User / org management (`/internal/users`)** — provisioning, deprovisioning, role assignment.

**Support queue (`/internal/support`)** — incoming tickets, owner, SLA.

**Research library (`/internal/research`)** — internal-only drafts, approval workflow before public publish.

**Releases (`/internal/releases`)** — release notes editor, publish workflow.

**Feature flags (`/internal/feature-flags`)** — flags console with environment scoping and audit log.

**System logs (`/internal/logs`)** — searchable, redacted-by-default audit logs.

---

## 7. Component inventory

**Chrome:** `PublicNav`, `PublicFooter`, `AppShell`, `InternalShell`, `RoleBadge`, `OrgSwitcher`, `EnvBanner`.

**Primitives:** `Button`, `Card`, `Section`, `SectionEyebrow`, `Pill`, `Badge`, `KPI`, `StatusPill`, `ZeroPriceBanner`, `Disclaimer`, `Code`, `Pre`, `DataTable`, `EmptyState`, `Stepper`, `Tabs`, `Drawer`, `Dialog`, `Skeleton`.

**Diagrams (SVG, hand-authored):**
1. `CustodyFlowDiagram` — Human → AVC → Agent → EXOCHAIN → Trust Receipt.
2. `IdentityToCustodyDiagram` — Identity → Authority → Volition → Consent → Execution → Custody Receipt.
3. `MechanismVsPurposeDiagram` — blockchain mechanism / chain-of-custody purpose.
4. `SurfaceMapDiagram` — Internet / Extranet / Intranet.
5. `ZeroPricedSettlementDiagram` — quote → receipt with `ZeroFeeReason`.

**Content blocks:** `Hero`, `FeatureGrid`, `PillarThree`, `Quote`, `Callout`, `CTAStrip`, `StatusStrip`, `MetricRow`, `ReceiptCard`, `AVCCard`, `ActorCard`, `IncidentCard`.

**Forms:** `IssueAVCForm`, `ValidateAVCForm`, `RevokeAVCForm`, `EarlyAccessForm`, `SecurityDisclosureForm`, `AuditExportRequestForm`.

---

## 8. Data model (frontend view types)

```ts
// Public types
type Actor = {
  id: string;
  type: 'human' | 'organization' | 'agent' | 'holon' | 'service' | 'validator';
  displayName: string;
  publicKey?: string;
  parentActorId?: string;
  createdAt: string;
  status: 'active' | 'inactive' | 'quarantined';
};

type PolicyDomain = {
  id: string;
  name: string;
  description: string;
  ownerActorId: string;
};

type AVC = {
  id: string;
  subjectActorId: string;
  issuerActorId: string;
  parentAvcId?: string;
  policyDomainId: string;
  scope: { actions: string[]; constraints?: Record<string, unknown> };
  notBefore: string;
  notAfter: string;
  signature: { algorithm: 'ML-DSA-65' | 'Hybrid'; value: string };
  status: 'active' | 'expired' | 'revoked' | 'quarantined';
};

type ConsentRecord = {
  id: string;
  avcId: string;
  principalActorId: string;
  subjectActorId: string;
  grantedAt: string;
  revokedAt?: string;
  scopeHash: string;
};

type TrustReceipt = {
  id: string;
  avcId: string;
  actorId: string;
  policyHash: string;
  actionDescriptor: string;
  outcome: 'permitted' | 'denied' | 'partial';
  custodyHash: string;
  prevHash?: string;
  timestamp: string;
  signature: { algorithm: 'ML-DSA-65'; value: string };
};

type SettlementQuote = {
  id: string;
  avcId: string;
  amount: '0';
  currency: 'EXO';
  zeroFeeReason: 'launch_policy_zero' | 'governance_subsidy' | 'humanitarian_carve_out';
  expiresAt: string;
};

type SettlementReceipt = {
  id: string;
  quoteId: string;
  trustReceiptId: string;
  amount: '0';
  currency: 'EXO';
  zeroFeeReason: SettlementQuote['zeroFeeReason'];
  prevHash?: string;
  timestamp: string;
  signature: { algorithm: 'ML-DSA-65'; value: string };
};

type Revocation = {
  id: string;
  avcId: string;
  cause: 'compromise' | 'scope_change' | 'policy_violation' | 'subject_request' | 'governance_action';
  initiatorActorId: string;
  cascade: string[]; // child AVC ids invalidated
  timestamp: string;
};

type Node = {
  id: string;
  operatorOrgId: string;
  kind: 'node' | 'validator';
  endpoint: string;
  version: string;
  status: 'syncing' | 'healthy' | 'degraded' | 'offline';
  lastHeight?: number;
};

type Incident = {
  id: string;
  severity: 'sev1' | 'sev2' | 'sev3' | 'sev4';
  title: string;
  status: 'open' | 'mitigated' | 'resolved';
  startedAt: string;
  resolvedAt?: string;
  publicSummary?: string;
};
```

All data fields shown to end users must be sourced from typed mocks in `/web/src/lib/mock-data.ts` until the corresponding `exo-gateway` endpoint is wired. Mocked data must be visibly labeled in non-production environments.

---

## 9. Security requirements

- Hard route separation between Internet, Extranet, Intranet via Next.js middleware. Intranet is denied to all sessions whose role is not in the intranet role set, regardless of cookie value.
- Step-up MFA required for: AVC revocation, pricing-policy edits, governance ratification, audit-packet exports, content publish.
- All admin actions write append-only audit log entries (`actor_id`, `scope`, `action`, `target`, `outcome`, `request_id`, `timestamp`).
- No secrets in frontend code. All API calls go through server actions or a backend-for-frontend route handler.
- No private keys in browser storage. Wallet/HSM integration is out of scope for the MVP web layer.
- Public pages must not overstate adoption, decentralization, legal compliance, audit status, or regulatory approval. Where claims are aspirational, a `Roadmap` pill is required.
- Trust Center distinguishes *current capabilities* from *roadmap items* in two clearly-labeled columns.
- Developer docs mark unstable APIs with an `Unstable` pill at the top of the affected section.
- Settlement-related pages must show the zero-pricing banner.
- Status page is the only place public network metrics may appear, and any metric not backed by a live source must be labeled `mock`.

---

## 10. Compliance and disclosures (public copy)

- "EXOCHAIN is in alpha. The protocol, APIs, governance, and economic layer are subject to change without notice."
- "Zero-priced launch settlement is in effect. Every active price resolves to zero with an explicit `ZeroFeeReason`. Future governance amendments may enable nonzero pricing."
- "Statements about cryptographic assumptions reflect implemented primitives at the time of writing. See `/trust-center` for the current attestation."
- "EXOCHAIN does not provide investment, legal, or financial advice. AVCs are operational credentials, not securities."

---

## 11. MVP vs. expansion roadmap

### 11.1 MVP — must ship in v0

- Polished public Internet site with all sections in §6.1, even where pages are short.
- Authenticated Extranet shell with all routes in §4.2, mock data, no real cryptographic operations yet.
- Internal Intranet shell with all routes in §4.3, mock data, role-based gating enforced by middleware.
- Design system primitives, five SVG diagrams, full nav and footer.
- Zero-pricing language and banners wired throughout settlement views.
- Status page with explicit `mock` labels until the live `exo-gateway` status feed is wired.
- Local-only development auth with HMAC-signed server-side cookies. Development login at `/app/login` and `/internal/login` is disabled unless `EXO_SITE_ENABLE_DEV_LOGIN=1`, `NODE_ENV=development`, and `EXO_SITE_SESSION_SECRET` is configured.

### 11.2 v0.5 — short follow-up

- Wire `/api` to `exo-gateway` OpenAPI document.
- Wire `/status` to live network metrics.
- Move docs from hand-authored TSX to MDX.
- Add OG images and per-page meta.
- Add structured data (Organization, BreadcrumbList).

### 11.3 v1.0 — production gating

- Real OIDC + WebAuthn for both Extranet and Intranet.
- Step-up MFA enforcement.
- Live AVC issuance/validation against `exo-node`/`exo-gateway`.
- Live trust-receipt generation and settlement-quote/receipt issuance against `exo-economy`.
- Audit-packet generation backed by `exo-economy` settlement-receipt chain and `exo-node` trust-receipt chain.
- Public bug bounty program live.
- SOC 2 Type I readiness statement (with completion evidence) on the Trust Center.

### 11.4 v1.5+ — expansion

- Validator dashboard with live attestation telemetry.
- Holon registry and inter-holon delegation flows.
- Governance proposal authoring tools (extranet) and ratification UI (intranet).
- Multi-region status page with regional roll-up.
- Public-developer "playground" sandbox for AVC issuance/validation.

---

## 12. Implementation notes

- **Stack:** Next.js 14 (App Router) + React 18 + TypeScript + Tailwind CSS. No external UI kit dependency in v0; primitives are hand-authored to keep the brand precise.
- **Routing:** route groups `(internet)`, with `app/` and `internal/` as top-level segments. Middleware enforces auth and role on the `app` and `internal` trees.
- **Auth (MVP):** server-set HTTP-only cookie `exo-session` containing a canonical session payload and HMAC signature. Raw JSON cookies and unsigned session payloads are rejected.
- **State:** server components by default. Client components only where interactivity is required (forms, drawers, toggles).
- **Styling:** dark and light themes. Restrained palette: ink, slate, vellum, signal-amber, custody-cyan, alert-red. No neon. No glow.
- **Diagrams:** hand-authored SVG so they remain accessible, themeable, and copy-exact. No third-party diagram runtime in v0.
- **Telemetry:** none in v0. Add privacy-preserving telemetry behind a Trust Center disclosure before broad public launch.
- **Build:** standard Next.js build. Deployable to Vercel or any Node 20 host.

---

## 13. Acceptance criteria for v0

- All Internet routes in §4.1 render and link correctly.
- All Extranet routes in §4.2 render and reflect the role badge.
- All Intranet routes in §4.3 render with the environment banner and redaction defaults.
- Five named diagrams render at all viewports without overflow.
- Zero-pricing banner appears on every settlement-related page.
- Status page shows `mock` labels on every numeric metric.
- Middleware blocks unauthenticated `/app/*` and `/internal/*` requests and redirects to the corresponding login.
- No copy on the public site claims completed audits, regulatory approval, or production decentralization.
- Every administrative action page shows a clear "this writes to the audit log" affordance.
- Build passes with no TypeScript errors and no ESLint errors at `next lint` defaults.

---

*End of specification. Implementation lives in `/web` as a Next.js application.*
