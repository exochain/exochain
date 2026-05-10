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

# decision.forum — Executive Intelligence Control System: UX Concept

## Core Metaphor: The Situation Room

decision.forum is an **executive governance situation room** — a real-time intelligence
control system where boards, C-suites, and professionals monitor, triage, and act on
organizational decisions with evidence-grade audit trails.

The metaphor shifts the mental model from "admin dashboard" to "command center":
- You are the **commander** viewing your governance landscape
- Decisions are **missions** with objectives, teams, phases, and outcomes
- Evidence is **intelligence** that supports or challenges positions
- Audit trails are the **chain of custody** that makes governance defensible

---

## Five Executive Workflows

### 1. MONITOR (Ambient Awareness)
**"What's happening in my governance landscape?"**
- Ambient status indicators: pending actions, overdue items, governance health pulse
- No interaction required — pure peripheral awareness
- Maps to: Situation Room sidebar (desktop), bottom status bar (mobile)

### 2. TRIAGE (Priority Sorting)
**"What needs my attention right now?"**
- Priority queue sorted by composite score: urgency × impact × role-relevance
- Four-element cards: title, urgency badge, deadline, action button
- Maps to: Priority Triage Queue (mobile-first), filtered Command View (desktop)

### 3. DRILL-DOWN (Evidence Examination)
**"Show me the full picture for this decision."**
- Three-layer progressive disclosure:
  - Layer 1: Command View (portfolio of decisions)
  - Layer 2: Decision Dossier (full context, timeline, evidence, stakeholders)
  - Layer 3: Evidence Examination (individual documents, provenance, annotations)
- Maps to: Master-detail split (desktop), sequential drill (tablet/mobile)

### 4. ACT (Decision Commitment)
**"I'm ready to vote, delegate, or escalate."**
- Minimal-friction action: 3 primary options (Approve, Reject, Defer/Escalate)
- Confidence capture: optional rationale and sentiment
- Constitutional constraint warnings before commitment
- Maps to: Inline actions (desktop), swipe-to-act (mobile), bottom sheet (tablet)

### 5. AUDIT (Retrospective Review)
**"Prove this decision was made correctly."**
- Narrative timeline of all events in chronological order
- Hash-chain integrity verification (tamper-evident)
- Delegation chain visualization
- Maps to: Timeline view (desktop), activity feed (mobile)

---

## Information Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  SITUATION ROOM (/)                                             │
│  ┌──────────┐  ┌──────────────────────────────────────────────┐ │
│  │ AMBIENT   │  │ COMMAND VIEW                                │ │
│  │ STATUS    │  │                                              │ │
│  │           │  │  ┌─────────────────────────────────────────┐ │ │
│  │ • Pending │  │  │ Decision Brief Cards                    │ │ │
│  │ • Overdue │  │  │ (filterable by status, class, urgency)  │ │ │
│  │ • Health  │  │  │                                          │ │ │
│  │ • Chain ✓ │  │  │  [Title] [Status] [Class] [Deadline]    │ │ │
│  │           │  │  │  [Evidence Count] [Vote Progress]        │ │ │
│  │           │  │  │  [Primary Action Button]                 │ │ │
│  │           │  │  └─────────────────────────────────────────┘ │ │
│  │           │  │                                              │ │
│  └──────────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  DECISION DOSSIER (/decisions/:id)                              │
│                                                                  │
│  ┌─ OODA Lifecycle Rail ─────────────────────────────────────┐  │
│  │ [Observe] → [Orient] → [Decide] → [Act]                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─ Intelligence Brief ──────┐  ┌─ Evidence & Cross-Checks ─┐  │
│  │ Title + Status             │  │ Evidence items (linked)    │  │
│  │ Author + Delegation Chain  │  │ Cross-check matrix         │  │
│  │ Constitutional Constraints │  │ Confidence meter           │  │
│  │ Risk Assessment            │  │ Stakeholder positions      │  │
│  └───────────────────────────┘  └────────────────────────────┘  │
│                                                                  │
│  ┌─ Narrative Timeline ──────────────────────────────────────┐  │
│  │ Created → Evidence → Deliberation → Votes → Result        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─ Actions ─────────────────────────────────────────────────┐  │
│  │ [Advance] [Vote: Approve/Reject/Abstain] [Delegate]       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  AUTHORITY MAP (/delegations)                                    │
│  ┌─ Delegation Graph ────────────────────────────────────────┐  │
│  │ Visual tree: root → delegates → sub-delegates             │  │
│  │ Color-coded by scope (financial, strategic, operational)   │  │
│  │ Click to expand delegation details + constraints           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  AUDIT LEDGER (/audit)                                           │
│  ┌─ Chain Status ─────┐  ┌─ Event Feed ─────────────────────┐  │
│  │ Chain Length: 24    │  │ Filterable by event type, actor   │  │
│  │ Integrity: ✓ Valid  │  │ Hash-linked entries with timing   │  │
│  │ Head Hash: a1b2...  │  │ Expandable detail per entry       │  │
│  └────────────────────┘  └───────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  CONSTITUTION (/constitution)                                    │
│  ┌─ Framework Overview ──────────────────────────────────────┐  │
│  │ Version, hash, human-gate classes                          │  │
│  │ Active constraints with enforcement level indicators       │  │
│  │ Delegation depth limits                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Entity → View Mapping

| Entity | Primary View | Secondary Views |
|--------|-------------|-----------------|
| Decision | Command View card → Decision Dossier | Audit Ledger (events), Authority Map (delegation) |
| Vote | Decision Dossier (vote panel) | Audit Ledger (VoteCast events) |
| Challenge | Decision Dossier (challenge panel) | Command View (contested badge) |
| Evidence | Decision Dossier (evidence panel) | Audit Ledger (evidence events) |
| Delegation | Authority Map (graph node) | Decision Dossier (delegation chain) |
| Audit Entry | Audit Ledger (feed item) | Decision Dossier (timeline event) |
| Constitution | Constitution page | Decision Dossier (constraint warnings) |
| Constraint | Constitution page (constraint list) | Create Decision (real-time warnings) |

---

## The 5-Minute Board Call Prep

An executive opens decision.forum 5 minutes before a board call:

1. **Glance** at Ambient Status: 2 pending votes, 1 contested decision, chain integrity ✓
2. **Triage**: Tap "Pending" filter → see the 2 decisions needing votes, sorted by deadline
3. **Brief**: Open the most urgent → read the Intelligence Brief (title, context, evidence count, stakeholder positions)
4. **Act**: Tap "Approve" with rationale "Aligned with Q4 strategy" → vote recorded with hash
5. **Verify**: Pull up Audit Ledger → see vote recorded with timestamp and chain link

Total interaction: ~3 minutes. The executive is informed, has acted, and has a defensible record.
