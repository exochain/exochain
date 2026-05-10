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

# ULTRAPLAN: Decision Forum — GC Interface Redesign & Board Book Artifact

**Status:** PLAN  
**Author:** Aeon (Chief-of-Staff AI)  
**Date:** 2026-04-14  
**Target Users:** General Counsel, Board Members, C-Suite Executives  
**Crate:** `decision-forum` (Rust) | Frontend: React/TypeScript  

---

## 1. UX Architecture

### Information Hierarchy

The GC sees three layers. Layer 1 is all most users touch daily.

**Layer 1 — Command Surface (Dashboard)**
- Active decisions requiring attention (approve/review/sign)
- BJR health score across portfolio (single number, color-coded)
- Recent Board Books ready for export
- One-click "New Decision" button

**Layer 2 — Decision Detail**
- AI deliberation summary (plain English)
- Convergence meter + dissent flags
- Approval status and quorum tracker
- Board Book preview

**Layer 3 — Forensic Depth (on-demand)**
- Full BCTS lifecycle state diagram
- Raw evidence bundle hashes
- Constitutional compliance details
- Audit trail with timestamps

### Wireframe — Dashboard

```
┌─────────────────────────────────────────────────────────┐
│  decision.forum                    [Bob Stewart ▾] [⚙]  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ NEEDS ACTION │  │  IN PROGRESS │  │   SEALED     │  │
│  │     3        │  │      7       │  │     42       │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                         │
│  Portfolio BJR Score: ████████░░ 82/100  [+] New Decision│
│                                                         │
│  ┌─ Awaiting Your Approval ─────────────────────────┐  │
│  │ ● Series B Term Sheet — Strategic — 4/5 votes    │  │
│  │ ● Vendor Contract (Palantir) — Operational — 2/3 │  │
│  │ ● Privacy Policy Update — Routine — Ready        │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─ Recent Board Books ─────────────────────────────┐  │
│  │ 📄 Q1 Compensation Review — Sealed Apr 10        │  │
│  │ 📄 IP Licensing (ACME) — Sealed Apr 8            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Design Principles

- **No BCTS terminology exposed.** States map to: Draft → Deliberating → Ready for Approval → Approved → Sealed. Backend maps these to the 14 BCTS states internally.
- **Mobile-first responsive.** Cards stack vertically. Board Book PDF is downloadable on any device.
- **Progressive disclosure.** Every summary card has a "Show Details" chevron. Default: collapsed.
- **Board Book is first-class.** Every decision page has a persistent "Generate Board Book" button in the action bar. It's not buried in a menu.

### Components — Reuse vs. Rebuild

| Existing Component     | Action   | Notes                                          |
|------------------------|----------|-------------------------------------------------|
| `DashboardPage`        | Rebuild  | Replace KanbanBoard with priority-sorted list   |
| `CreateDecisionPage`   | Rebuild  | Replace with step wizard (see §3)               |
| `DecisionDetailPage`   | Rebuild  | Three-layer progressive disclosure              |
| `DecisionCard`         | Reuse    | Simplify labels, add BJR badge                  |
| `KanbanBoard`          | Remove   | GCs don't think in kanban                       |
| `CouncilAIPanel`       | Reuse    | Wrap in plain-language presenter (see §4)       |
| `StatusBadge`          | Reuse    | Remap to 5-state vocabulary                     |
| `UrgencyBadge`         | Reuse    | Keep as-is                                      |
| `AuditTrailPage`       | Keep     | Move to Layer 3 depth access                    |
| `CommandCenterPage`    | Remove   | Admin-only, hide from GC view                   |

**New Components to Build:**
- `DecisionWizard` — stepped creation flow
- `BoardBookPreview` — in-app rendered preview
- `BoardBookPDF` — PDF generation pipeline
- `DeliberationSummary` — plain-language AI consensus view
- `ConvergenceMeter` — visual convergence indicator
- `ApprovalBar` — sticky bottom bar with approve/reject/remand
- `SealButton` — DAG anchoring trigger
- `BoardBookGallery` — archive browser with search/filter

### Deliverables
- [ ] New `GCDashboardPage` replacing `DashboardPage` for GC role
- [ ] Responsive layout system (CSS Grid, breakpoints: 375/768/1024/1440)
- [ ] Role-based routing: GC users → simplified views, admins → full views

---

## 2. Board Book Artifact Spec

The Board Book is a PDF document formatted to the standard a GC would present at a board meeting.

### Document Structure

```
BOARD BOOK — [Decision Title]
[Organization Logo]                         [Date] | [Classification]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. EXECUTIVE SUMMARY                                          (1 page)
   - Decision in one paragraph
   - Recommendation
   - BJR Defensibility: [Score] / 10,000 bp

2. DECISION STATEMENT                                         (½ page)
   - Precise statement of what is being decided
   - Classification: [Routine|Operational|Strategic|Constitutional]
   - Stakeholders and authority basis (GOV-003 reference)

3. AI DELIBERATION RECORD                                     (2-3 pages)
   - Panel composition (models used, roles assigned)
   - Per-model position summary (2-3 sentences each)
   - Convergence score and analysis
   - Points of unanimous agreement
   - Points of contention

4. MINORITY REPORT                                            (1 page)
   - Devil's Advocate position
   - Dissenting model perspectives
   - Risk scenarios raised

5. RISK ASSESSMENT                                            (1 page)
   - Identified risks ranked by severity
   - Mitigation strategies proposed
   - Residual risk acknowledgment

6. BJR DEFENSIBILITY SCORE                                    (1 page)
   ┌────────────────────────┬───────────┬─────────┐
   │ Prong                  │ Score(bp) │ Status  │
   ├────────────────────────┼───────────┼─────────┤
   │ Disinterestedness      │ 9,200     │ ✅ PASS │
   │ Informed Basis         │ 8,700     │ ✅ PASS │
   │ Good Faith             │ 9,500     │ ✅ PASS │
   │ Rational Basis         │ 8,100     │ ✅ PASS │
   ├────────────────────────┼───────────┼─────────┤
   │ COMPOSITE              │ 8,875     │ ✅ PASS │
   └────────────────────────┴───────────┴─────────┘
   (Sourced from fiduciary_package.rs FiduciaryPackage struct)

7. EVIDENCE BUNDLE REFERENCE                                  (½ page)
   - BLAKE3 Hash: [64-char hex]
   - Timestamp: [ISO 8601]
   - DAG Anchor TX: [ExoChain reference]
   - Bailment Wrapper: [bailment.ai reference]
   - Verification: [URL to verify independently]
   - FRE Compliance: 901(b)(9), 803(6), 902(13)

8. APPROVAL CHAIN                                             (½ page)
   - Signatories with timestamps and 0dentity verification status
   - Quorum: [achieved/required] per GOV-010
   - Human gate: confirmed per GOV-007

9. CONSTITUTIONAL COMPLIANCE STATEMENT                        (½ page)
   - Applicable constitutional provisions
   - TNC controls satisfied
   - Contestation window status (GOV-008)

APPENDIX A — Full Deliberation Transcript (optional, linked)
APPENDIX B — Raw Evidence Hashes
```

### PDF Generation Strategy

Use **@react-pdf/renderer** for in-browser generation. The Board Book template is a React component tree (`BoardBookTemplate.tsx`) that renders to PDF via `@react-pdf/renderer`'s `pdf()` function. Server-side generation via the same component for async/bulk exports.

Alternatively, for high-fidelity output: **Puppeteer on the backend** rendering a dedicated HTML template → PDF. This gives full CSS control including headers/footers/page numbers.

**Recommended approach:** Dual-path. Quick preview uses `@react-pdf/renderer` client-side. "Download Final" triggers server-side Puppeteer render with branded template, proper fonts, and page numbering.

### File Paths
- `frontend/src/components/BoardBook/BoardBookTemplate.tsx` — React-PDF template
- `frontend/src/components/BoardBook/BoardBookPreview.tsx` — in-app preview
- `backend/src/routes/board_book.rs` — PDF generation endpoint
- `frontend/src/assets/templates/board-book.css` — print stylesheet

### Deliverables
- [ ] `BoardBookTemplate` React-PDF component with all 9 sections
- [ ] Branded CSS template with organization logo slot
- [ ] Server-side PDF endpoint: `POST /api/decisions/{id}/board-book`
- [ ] PDF includes QR code linking to verification URL

---

## 3. Simplified Decision Creation Flow

### Wizard Steps

The `DecisionWizard` component replaces `CreateDecisionPage`. Five steps, each one screen.

**Step 1 — "What are you deciding?"**
- Single text field, large font. Placeholder: "e.g., Approve Series B term sheet from Acme Ventures"
- Optional: paste or upload supporting documents (drag-drop zone)
- Backend: maps to `DecisionObject.title` + `DecisionObject.description`

**Step 2 — "What's at stake?"**
- Three toggles: Financial Impact / Legal Exposure / Reputational Risk
- Dollar range selector for financial (dropdown: <$100K, $100K-$1M, $1M-$10M, $10M+)
- Free-text "Additional context" box
- Backend: feeds `FiduciaryPackage` risk scoring inputs

**Step 3 — "Who needs to weigh in?"**
- People picker (search org directory). Pre-populated from `authority_matrix.rs` based on decision classification.
- Toggle: "Include AI Advisory Panel" (default: on)
- Shows required quorum from `quorum.rs` automatically
- Backend: creates `ActorKind::Human` entries + sets quorum requirements

**Step 4 — "How important is this?"**
- Four visual cards (not a dropdown): Day-to-day / Operational / Strategic / Constitutional
- Each card shows a one-sentence description and example
- System auto-suggests based on Step 2 inputs (highlighted with "Suggested" badge)
- Backend: maps directly to `DecisionClass::Routine | Operational | Strategic | Constitutional`

**Step 5 — "Review & Launch"**
- Summary card showing all inputs
- "Launch Deliberation" button (primary, large)
- Estimated completion time shown
- Backend: creates `DecisionObject`, triggers `workflow.rs` Syntaxis integration

### Wireframe — Step 1

```
┌─────────────────────────────────────────────────┐
│  New Decision                        Step 1 of 5│
│                                                  │
│  What are you deciding?                          │
│  ┌──────────────────────────────────────────┐   │
│  │ Approve Series B term sheet from Acme... │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐   │
│  │  📎 Drop supporting documents here       │   │
│  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘   │
│                                                  │
│                                    [Next →]      │
└─────────────────────────────────────────────────┘
```

### API Endpoint
- `POST /api/decisions` — accepts wizard payload, returns `DecisionObject` ID
- Request body maps wizard fields to `DecisionObject` + `FiduciaryPackage` initialization

### File Paths
- `frontend/src/components/Wizard/DecisionWizard.tsx` — orchestrator
- `frontend/src/components/Wizard/steps/StepDecision.tsx`
- `frontend/src/components/Wizard/steps/StepStakes.tsx`
- `frontend/src/components/Wizard/steps/StepParticipants.tsx`
- `frontend/src/components/Wizard/steps/StepClassification.tsx`
- `frontend/src/components/Wizard/steps/StepReview.tsx`

### Deliverables
- [ ] 5-step wizard with back/next navigation and progress indicator
- [ ] Auto-classification suggestion engine (rule-based on dollar threshold + risk toggles)
- [ ] Under 60 seconds from open to launch (measured, enforced in UX testing)

---

## 4. AI Deliberation View

### Layperson Presentation

Replace raw `CouncilAIPanel` output with `DeliberationSummary`, a structured plain-language view.

```
┌─────────────────────────────────────────────────────┐
│  AI Advisory Panel — Deliberation Complete           │
│                                                      │
│  Consensus: ████████████░░░ 83% Convergence          │
│                                                      │
│  ✅ All models agree:                                │
│  • Term sheet valuation is within market range        │
│  • Board approval authority is properly delegated     │
│  • No conflict of interest detected                  │
│                                                      │
│  ⚠️ Points of contention:                            │
│  • Anti-dilution provisions — 2 models flag risk     │
│  • Liquidation preference stack — split opinion      │
│                                                      │
│  😈 Devil's Advocate (strongest counterargument):    │
│  "The ratchet clause in §4.2 creates downside        │
│   exposure in a down-round scenario that exceeds     │
│   standard market terms by ~15%."                    │
│                                                      │
│  [Show Individual Model Views ▾]                     │
│  [Show Full Transcript ▾]                            │
└─────────────────────────────────────────────────────┘
```

### Expanded Model Views (Layer 2)

Each AI model gets a card:
- Model name + icon (Claude, GPT, Gemini, Grok, DeepSeek)
- Position: Approve / Approve with Conditions / Oppose
- 3-sentence rationale
- Confidence level (bar)

### Live vs. Async Modes

- **Live mode:** WebSocket connection via `GET /api/decisions/{id}/deliberation/stream`. Models report in real-time. Cards animate as each model completes. Convergence meter updates live.
- **Async mode:** Poll `GET /api/decisions/{id}/deliberation/status`. Show progress bar. Email/push notification when complete.

### Backend Mapping
- Convergence score: computed from `VoteChoice` alignment across models in `decision_object.rs`
- Devil's Advocate: dedicated deliberation round output (structured in `workflow.rs`)
- Minority report: dissenting `VoteChoice` entries with rationale text

### Deliverables
- [ ] `DeliberationSummary` component with convergence meter, agreement list, contention list, Devil's Advocate block
- [ ] `ModelPositionCard` component for expanded individual views
- [ ] WebSocket integration for live deliberation streaming
- [ ] Plain-language synthesis engine (LLM post-processing of raw deliberation into summary)

---

## 5. Approval & Signing Flow

### One-Click Approve

Sticky bottom bar on `DecisionDetailPage`:

```
┌─────────────────────────────────────────────────────┐
│  ✅ Approve    │    🔙 Send Back    │    ❌ Oppose   │
│  (Sign & Lock) │  (Request Changes) │  (With Reason) │
└─────────────────────────────────────────────────────┘
```

### Flow
1. User clicks **Approve**
2. 0dentity verification gate fires (biometric/2FA via `human_gate.rs` → GOV-007)
3. Digital signature applied (WebAuthn/FIDO2 or fallback TOTP)
4. Quorum tracker updates in real-time (`quorum.rs` → GOV-010)
5. If quorum met: decision advances to Sealed state
6. Constitutional compliance check runs automatically (`constitution.rs`, `tnc_enforcer.rs`)
7. If compliance fails: blocks with plain-language explanation + remediation steps

### Quorum Tracker UI

```
Approval Progress: ███░░ 3 of 5 required
  ✅ Jane Chen (GC) — Apr 14, 2:30pm
  ✅ Marcus Webb (CFO) — Apr 14, 3:15pm
  ✅ Sarah Kim (Board) — Apr 14, 4:01pm
  ⏳ David Park (CEO) — Pending
  ⏳ Lisa Tran (Board) — Pending
```

### API Endpoints
- `POST /api/decisions/{id}/approve` — sign + approve
- `POST /api/decisions/{id}/reject` — oppose with reason
- `POST /api/decisions/{id}/remand` — send back for revision
- `GET /api/decisions/{id}/quorum` — current quorum status

### Deliverables
- [ ] `ApprovalBar` sticky component with three actions
- [ ] 0dentity WebAuthn integration for signing
- [ ] `QuorumTracker` component with real-time status
- [ ] Constitutional compliance gate with user-friendly error messages

---

## 6. Evidence Bundle & DAG Anchoring

### User-Facing Action

After approval + quorum, the GC sees a "Seal & Certify" button. One click triggers:

1. **BLAKE3 hash** of complete decision record (deliberation, votes, evidence, Board Book PDF)
2. **DAG write** to ExoChain (immutable anchor)
3. **Bailment wrap** via bailment.ai (legal custody chain)
4. **Verification URL** generated: `https://verify.decision.forum/{hash}`

The user sees:

```
┌─────────────────────────────────────────────┐
│  🔒 Decision Sealed                         │
│                                              │
│  Verification Hash: 7a3f...c821              │
│  Sealed: Apr 14, 2026 4:47pm EDT            │
│  DAG Reference: exo:0x8f2a...               │
│                                              │
│  [Copy Verification Link]  [Download Cert]   │
│  [Generate Board Book PDF]                   │
└─────────────────────────────────────────────┘
```

### Backend Integration
- `fiduciary_package.rs` → `EvidenceBundle` struct provides hash computation
- New endpoint: `POST /api/decisions/{id}/seal` — triggers hash + DAG write + bailment
- Returns: `{ hash, dag_tx, bailment_ref, verification_url, timestamp }`

### Deliverables
- [ ] `SealButton` component with confirmation modal
- [ ] `SealCertificate` component (displays post-seal status)
- [ ] `/api/decisions/{id}/seal` endpoint
- [ ] `/api/verify/{hash}` public verification page (standalone, no auth)
- [ ] QR code generation for printed Board Books linking to verification URL

---

## 7. Board Book Gallery / Archive

### Gallery View

```
┌──────────────────────────────────────────────────────┐
│  Board Book Archive                    [🔍 Search]    │
│  ┌──────────┬──────────┬──────────┬────────┐         │
│  │ All (42) │ Strat(8) │ Oper(22)│ Rout(12)│         │
│  └──────────┴──────────┴──────────┴────────┘         │
│                                                       │
│  Sort: [Date ▾]  Filter: [BJR Score ≥ ___] [Year ▾]  │
│                                                       │
│  📄 Series B Term Sheet         Strategic  9,100 bp   │
│     Sealed Apr 14 · 5 approvals · PDF ready           │
│                                                       │
│  📄 Q1 Compensation Review      Operational 8,200 bp  │
│     Sealed Apr 10 · 3 approvals · PDF ready           │
│                                                       │
│  [Select All] [Export Selected as ZIP]                 │
└──────────────────────────────────────────────────────┘
```

### Search Capabilities
- Full-text search across decision titles and summaries
- Filter by: classification, BJR score range, date range, signatory, seal status
- Sort by: date, BJR score, classification

### API Endpoints
- `GET /api/board-books?q=&class=&bjr_min=&date_from=&date_to=&page=&limit=`
- `GET /api/board-books/export?ids=[]` — bulk ZIP download

### Deliverables
- [ ] `BoardBookGallery` page with search, filter, sort
- [ ] Bulk export (ZIP of PDFs)
- [ ] Quick-view modal (preview without full page navigation)

---

## 8. API & Integration Points

| Integration         | Method              | Endpoint / Hook                              |
|---------------------|---------------------|----------------------------------------------|
| Diligent Boards     | REST API push       | `POST /api/integrations/diligent/sync`       |
| OnBoard             | REST API push       | `POST /api/integrations/onboard/sync`        |
| Google Calendar     | OAuth + CalDAV      | Meeting-linked decisions via calendar event ID|
| Outlook Calendar    | Microsoft Graph API | Same as above                                |
| Email notifications | SMTP / SendGrid     | Triggered on state transitions               |
| Slack               | Slack Webhook/Bot   | Decision status updates, approval requests   |
| D&O Insurance       | Outbound webhook    | `POST {insurer_url}` with BJR score payload  |
| SSO                 | SAML 2.0 / OIDC     | Okta, Azure AD, Google Workspace             |

### Webhook Payload (D&O Insurance)
```json
{
  "decision_id": "uuid",
  "bjr_composite_score": 8875,
  "classification": "Strategic",
  "seal_hash": "7a3f...c821",
  "sealed_at": "2026-04-14T20:47:00Z",
  "verification_url": "https://verify.decision.forum/7a3f...c821"
}
```

### Deliverables
- [ ] Integration adapter framework (`backend/src/integrations/`)
- [ ] Diligent + OnBoard board portal sync
- [ ] Calendar linking (decision tied to meeting)
- [ ] Webhook configuration UI for D&O insurance endpoints
- [ ] Slack bot for approval notifications

---

## 9. Implementation Phases

### Phase 1 — Core GC Experience (Weeks 1-4)
**Goal:** A GC can create a decision and get a Board Book.
- `DecisionWizard` (5-step creation flow)
- `BoardBookTemplate` + PDF generation (client + server)
- Simplified `GCDashboardPage`
- Role-based routing (GC vs admin views)
- **Ships:** MVP usable for demos and early design partners

### Phase 2 — Deliberation & Approval (Weeks 5-8)
**Goal:** AI deliberation is watchable. Approval flow works end-to-end.
- `DeliberationSummary` component + plain-language synthesis
- `ConvergenceMeter` + `ModelPositionCard`
- WebSocket live deliberation streaming
- `ApprovalBar` + 0dentity signing integration
- `QuorumTracker` real-time display
- **Ships:** Full decision lifecycle from creation through approval

### Phase 3 — Seal, Archive, Polish (Weeks 9-12)
**Goal:** Evidence anchoring works. Archive is browsable. Mobile-ready.
- `SealButton` + DAG anchoring pipeline
- Public verification page (`/verify/{hash}`)
- `BoardBookGallery` with search/filter/export
- Mobile responsive pass on all new components
- Branded PDF template with logo, fonts, page numbers
- **Ships:** Complete product for Counsel tier ($500/mo)

### Phase 4 — Integrations & Enterprise (Weeks 13-16)
**Goal:** Board tier and Enterprise ready. Integrates with existing workflows.
- Diligent / OnBoard sync
- Calendar integration (Google + Outlook)
- Slack bot + email notifications
- D&O insurance webhook
- SSO (SAML/OIDC)
- Bulk export
- **Ships:** Board tier ($2,000/mo) and Enterprise ($24,000/yr) features

### Dependencies
- Phase 2 depends on Phase 1 (wizard creates the decision that deliberation operates on)
- Phase 3 depends on Phase 2 (seal happens after approval)
- Phase 4 is independent of Phase 3 (integrations can start in parallel with Week 9)

---

## 10. Technical Architecture

### Frontend Stack
- **Framework:** React 18+ with TypeScript
- **State:** Zustand for global state (decisions, user, deliberation status). React Query for server cache.
- **PDF:** `@react-pdf/renderer` (client preview) + Puppeteer (server final render)
- **WebSocket:** Native WebSocket or Socket.IO for live deliberation
- **Styling:** Tailwind CSS + shadcn/ui components for consistent, professional look
- **Routing:** React Router with role-based guards

### API Surface (Rust Backend)

New endpoints required (all under `/api/v2/`):

```
POST   /decisions                          → Create (wizard payload)
GET    /decisions/{id}                     → Detail (includes deliberation summary)
GET    /decisions/{id}/deliberation/stream → WebSocket live updates
GET    /decisions/{id}/deliberation/status → Poll status
POST   /decisions/{id}/approve             → Sign + approve
POST   /decisions/{id}/reject              → Oppose
POST   /decisions/{id}/remand              → Send back
GET    /decisions/{id}/quorum              → Quorum status
POST   /decisions/{id}/seal                → Trigger DAG anchoring
POST   /decisions/{id}/board-book          → Generate PDF
GET    /decisions/{id}/board-book.pdf      → Download PDF
GET    /board-books                        → Gallery listing
GET    /board-books/export                 → Bulk ZIP
GET    /verify/{hash}                      → Public verification (no auth)
POST   /integrations/{provider}/sync       → Board portal sync
```

### Rust Type Mapping

| Frontend Concept        | Rust Type                          | File                       |
|-------------------------|------------------------------------|----------------------------|
| Decision (full)         | `DecisionObject`                   | `decision_object.rs`       |
| Classification card     | `DecisionClass` enum               | `decision_object.rs`       |
| Approval action         | `VoteChoice` enum                  | `decision_object.rs`       |
| Participant             | `ActorKind` enum                   | `decision_object.rs`       |
| BJR score table         | `FiduciaryPackage`                 | `fiduciary_package.rs`     |
| Evidence hash           | `EvidenceBundle` (BLAKE3 digest)   | `fiduciary_package.rs`     |
| Quorum display          | `QuorumRequirement` + `QuorumState`| `quorum.rs`                |
| Constitutional check    | `ConstitutionCorpus`               | `constitution.rs`          |
| Authority validation    | `AuthorityMatrix`                  | `authority_matrix.rs`      |
| Human gate enforcement  | `HumanGate`                        | `human_gate.rs`            |
| Contestation window     | `ContestationRecord`               | `contestation.rs`          |

### State Management

```
Zustand stores:
├── useDecisionStore     — active decision, wizard state, CRUD
├── useDeliberationStore — live deliberation stream, convergence, model positions
├── useAuthStore         — user, role, 0dentity session
└── useBoardBookStore    — gallery filters, selected items, export queue
```

### PDF Generation Pipeline

1. Client clicks "Generate Board Book"
2. Frontend sends `POST /api/v2/decisions/{id}/board-book`
3. Backend assembles data: `DecisionObject` + `FiduciaryPackage` + deliberation record + approval chain
4. Puppeteer renders HTML template → PDF with branded header/footer, page numbers, QR code
5. PDF stored in object storage (S3/R2), URL returned
6. Frontend shows download link + preview

### Deliverables
- [ ] API v2 route module (`backend/src/routes/v2/`)
- [ ] Zustand stores for decision, deliberation, auth, board-book
- [ ] WebSocket handler for deliberation streaming
- [ ] Puppeteer PDF service (containerized, separate from main API)
- [ ] React Query hooks for all API endpoints
- [ ] E2E test: wizard → deliberation → approve → seal → download Board Book PDF

---

## Summary

This plan converts decision.forum from an engineering console into a product a General Counsel picks up in 30 seconds. The Board Book becomes the hero artifact — the thing they came for, the thing they take to the board meeting, the thing they pull up when a shareholder sues. Every other feature (AI deliberation, BJR scoring, DAG anchoring) is infrastructure that makes the Board Book defensible. The interface hides that infrastructure until someone needs it.

Four phases. Sixteen weeks. Counsel tier ships at Week 12. Enterprise at Week 16.
