# ExoChain Decision Forum Engine — Full Integration Plan

**Project:** #14 — ExoChain Decision Forum Integration
**Status:** Active
**Phases:** 10
**Integration Points:** 47

---

## Phase 1: Foundation (BLOCKING — everything depends on this)
**Executive:** Onyx (CTO)
**Specialists:** Alloy (backend), Query (database), Mortar (schema)

### Tasks:
1. **Build ExoChain WASM module** — Compile exochain-wasm crate, copy .wasm + JS glue to app/lib/exochain/
2. **Create ExoChain service layer** — app/services/exochain.js wrapping WASM exports (45 functions)
3. **Database schema migration** — Add tables: decision_objects, votes, quorum_policies, authority_delegations, challenge_records, independence_attestations, accountability_actions, conflict_disclosures, emergency_actions
4. **Core type definitions** — Decision classes (Routine/Operational/Strategic/Constitutional), vote types, actor kinds, quorum specs
5. **Seed constitutional invariants** — Migrate existing 9 invariants from hardcoded to ExoChain constitutional corpus format
6. **API routes scaffold** — /api/exochain/* endpoints for decisions, votes, challenges, authority

---

## Phase 2: Board Governance
**Executive:** Sable (COO)
**Specialists:** Alloy (backend), Hook (integrations)

### Tasks:
7. **Decision Object lifecycle** — 14-state BCTS model (Created → Deliberation → Voting → Approved/Rejected/Void)
8. **Quorum voting system** — Per-class policies (Routine: 1/51%, Operational: 3/51%, Strategic: 5/67%, Constitutional: 7/75%)
9. **Board deliberation UI** — Frontend page for board members to review, discuss, and vote on decisions
10. **Promotion/demotion votes** — Strategic quorum for specialist→executive promotions
11. **Hiring/firing votes** — Board quorum for personnel decisions (Crest proposes → Board votes)
12. **Policy change votes** — Constitutional class for rule changes
13. **Budget approval votes** — Operational quorum with Tithe's financial review

---

## Phase 3: Authority & Identity
**Executive:** Onyx (CTO)
**Specialists:** Lock (auth), Alloy (backend)

### Tasks:
14. **Delegation Authority Matrix** — Real-time actor→authority mappings with scope, expiry, sub-delegation
15. **Authority chain verification** — Ed25519 signature verification on every state transition
16. **AI vs Human distinction** — SignerType enum, human gate enforcement for Strategic/Constitutional decisions
17. **Delegation expiry management** — Max 12-month, notifications at 90/60/30/14/7 days
18. **Tool/API key authorization** — Migrate member_tools to use delegation matrix with scope enforcement
19. **Spawn permission authority** — Authority chain check before terminal spawn

---

## Phase 4: Task Flow Through Chain of Command
**Executive:** Sable (COO)
**Specialists:** Alloy (backend), Crank (workers), Hook (integrations)

### Tasks:
20. **Task → Decision Object creation** — Every new task creates a Routine/Operational Decision Object
21. **Board review gate** — New tasks enter Board queue, Board delegates to Executive
22. **Executive delegation tracking** — Track Executive→Specialist assignment as authority delegation
23. **Escalation as Challenge** — Specialist files structured escalation with evidence (6 challenge grounds)
24. **Escalation workflow** — 7-stage adjudication: specialist → senior specialist → executive → board
25. **Task reassignment authorization** — Authority chain verification on reassignment
26. **Priority override authorization** — Only authorized actors (by delegation scope) can change priority

---

## Phase 5: Competition & Leaderboard
**Executive:** Loom (CAIO)
**Specialists:** Neural (ML), Briar (research), Alloy (backend)

### Tasks:
27. **Peer review crosscheck** — Plural intelligence: require ≥2 independent reviewers per review
28. **Independence attestation** — 3 mandatory fields (no_common_control, no_coordination, identity_verified)
29. **Sybil detection engine** — 6 sub-threat taxonomy, coordination detection, suspicious agreement flags
30. **Provider diversity enforcement** — Require ≥3 distinct assessors for Leader badge decisions
31. **Contest peer review** — Challenge system with 6 grounds (Bias, ProcedureViolation, FactualDispute, etc.)
32. **Dissent preservation** — Minority views as first-class objects in leaderboard decisions

---

## Phase 6: Improvement Pipeline
**Executive:** Onyx (CTO)
**Specialists:** Crank (workers), Alloy (backend)

### Tasks:
33. **Improvement approval Decision Objects** — Routine quorum for improvement execution
34. **Keep/discard as governed decision** — Decision Object with measurable evidence attached
35. **Chamber authority delegation** — Who can add to chamber, governed by delegation matrix
36. **Reversal linkage** — Failed improvements create reversal Decision Objects with immutable linkage

---

## Phase 7: Quality & Review Gates
**Executive:** Sable (COO)
**Specialists:** Plumb (test strategy), Sweep (QA), Alloy (backend)

### Tasks:
37. **Multi-reviewer task completion** — Deliberation with structured voting from ≥2 reviewers
38. **Code review quorum** — Crosscheck requiring independent reviewers
39. **Quality gate constitutional constraints** — Machine-evaluable constraint expressions for "done"
40. **Revision cycle Decision Objects** — Approve→deliver or reject→back-to-progress as formal decisions

---

## Phase 8: Emergency & Operations
**Executive:** Sable (COO)
**Specialists:** Vigil (SRE), Beacon (monitoring), Alloy (backend)

### Tasks:
41. **Emergency Action Protocol** — Auto-created RATIFICATION_REQUIRED Decision Objects
42. **Token exhaustion governance** — Emergency protocol with ratification for local mode
43. **Pipeline runaway detection** — Per-quarter threshold (>3 emergencies triggers governance review)
44. **Watchdog kill ratification** — Process kills require post-hoc ratification within N hours

---

## Phase 9: Audit & Accountability
**Executive:** Onyx (CTO)
**Specialists:** Alloy (backend), Query (database)

### Tasks:
45. **Upgrade governance_receipts** — Full hash-chained DAG with Blake3 + Ed25519
46. **Upgrade provenance_chain** — Cryptographic provenance with DID binding
47. **Upgrade validateAgainstInvariants()** — CGR Kernel with combinator algebra
48. **Accountability Decision Objects** — Censure, Suspension, Revocation, Recall subtypes
49. **Conflict disclosure enforcement** — Mandatory signed disclosure with recusal
50. **Succession planning** — Minimum-2-successors enforcement per role

---

## Phase 10: Frontend Integration
**Executive:** Quarry (CPO)
**Specialists:** Frame (frontend), Fret (UI), Render (DOM), Chart (dashboards)

### Tasks:
51. **Board Governance page** — Vote interface, deliberation view, decision history
52. **Decision Object status in task cards** — Show governance state on tasks
53. **Escalation UI** — Structured escalation filing with evidence attachment
54. **Authority delegation management** — View/grant/revoke delegations
55. **Accountability dashboard** — Censure/suspension/revocation tracking
56. **Constitutional invariant viewer** — Live invariant status with violation alerts
57. **Audit trail explorer** — Hash-chain verification UI with provenance viewer

---

## Execution Order

Phase 1 (Foundation) BLOCKS everything — must complete first.
Then Phases 2-9 can execute in parallel across different executives/specialists.
Phase 10 (Frontend) runs alongside Phases 2-9, building UI as backend features land.
