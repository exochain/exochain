// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import './index.css';

// ══════════════════════════════════════════════════════════════
// DATA: Syntaxis Node Registry (23 nodes, 8 categories)
// ══════════════════════════════════════════════════════════════
const NODE_REGISTRY = {
  'Identity & Access': [
    { id: 'identity-verify', name: 'Identity Verify', color: '#3b82f6', invariants: ['ProvenanceVerifiable', 'AuthorityChainValid'], inputs: ['did', 'proof'], outputs: ['verified_identity'] },
    { id: 'authority-check', name: 'Authority Check', color: '#3b82f6', invariants: ['AuthorityChainValid', 'SeparationOfPowers', 'NoSelfGrant'], inputs: ['actor_did', 'permission', 'delegation_chain'], outputs: ['authority_proof'] },
    { id: 'authority-delegate', name: 'Authority Delegate', color: '#3b82f6', invariants: ['AuthorityChainValid', 'NoSelfGrant', 'SeparationOfPowers'], inputs: ['grantor_did', 'grantee_did', 'permissions', 'constraints'], outputs: ['delegation_token'] },
  ],
  'Consent': [
    { id: 'consent-request', name: 'Consent Request', color: '#10b981', invariants: ['ConsentRequired'], inputs: ['principal_did', 'scope', 'duration'], outputs: ['consent_token'] },
    { id: 'consent-verify', name: 'Consent Verify', color: '#10b981', invariants: ['ConsentRequired'], inputs: ['consent_token', 'operation'], outputs: ['consent_verified'] },
    { id: 'consent-revoke', name: 'Consent Revoke', color: '#10b981', invariants: ['ConsentRequired', 'HumanOverride'], inputs: ['consent_token', 'revocation_reason'], outputs: ['revocation_receipt'] },
  ],
  'Governance': [
    { id: 'governance-propose', name: 'Governance Propose', color: '#8b5cf6', invariants: ['SeparationOfPowers', 'QuorumLegitimate', 'ProvenanceVerifiable'], inputs: ['proposer_did', 'proposal_content', 'quorum_requirement'], outputs: ['proposal_id', 'deliberation_state'] },
    { id: 'governance-vote', name: 'Governance Vote', color: '#8b5cf6', invariants: ['QuorumLegitimate', 'ProvenanceVerifiable'], inputs: ['voter_did', 'proposal_id', 'vote_value'], outputs: ['vote_receipt'] },
    { id: 'governance-resolve', name: 'Governance Resolve', color: '#8b5cf6', invariants: ['QuorumLegitimate', 'SeparationOfPowers'], inputs: ['proposal_id'], outputs: ['resolution', 'enacted'] },
  ],
  'Kernel': [
    { id: 'kernel-adjudicate', name: 'Kernel Adjudicate', color: '#ef4444', invariants: ['KernelImmutability', 'SeparationOfPowers', 'ProvenanceVerifiable'], inputs: ['action_request', 'adjudication_context'], outputs: ['verdict'] },
    { id: 'invariant-check', name: 'Invariant Check', color: '#ef4444', invariants: ['KernelImmutability'], inputs: ['invariant_id', 'context'], outputs: ['invariant_result'] },
  ],
  'Proof & Ledger': [
    { id: 'proof-generate', name: 'Proof Generate', color: '#06b6d4', invariants: ['ProvenanceVerifiable'], inputs: ['claim', 'evidence'], outputs: ['proof'] },
    { id: 'proof-verify', name: 'Proof Verify', color: '#06b6d4', invariants: ['ProvenanceVerifiable'], inputs: ['proof', 'claim'], outputs: ['verification_result'] },
    { id: 'dag-append', name: 'DAG Append', color: '#06b6d4', invariants: ['ProvenanceVerifiable'], inputs: ['event', 'parent_hashes'], outputs: ['event_hash', 'dag_state'] },
  ],
  'Escalation': [
    { id: 'escalation-trigger', name: 'Escalation Trigger', color: '#f59e0b', invariants: ['HumanOverride', 'ProvenanceVerifiable'], inputs: ['violation', 'severity', 'context'], outputs: ['escalation_id', 'notification_sent'] },
    { id: 'human-override', name: 'Human Override', color: '#f59e0b', invariants: ['HumanOverride'], inputs: ['escalation_id', 'human_decision', 'justification'], outputs: ['override_result'] },
  ],
  'Multi-tenancy & AI': [
    { id: 'tenant-isolate', name: 'Tenant Isolate', color: '#ec4899', invariants: ['SeparationOfPowers', 'AuthorityChainValid'], inputs: ['tenant_id', 'operation', 'actor_did'], outputs: ['isolation_verified'] },
    { id: 'mcp-enforce', name: 'MCP Enforce', color: '#ec4899', invariants: ['KernelImmutability', 'ConsentRequired', 'HumanOverride'], inputs: ['mcp_context', 'ai_action', 'rules'], outputs: ['enforcement_result'] },
  ],
  'Flow Control': [
    { id: 'combinator-sequence', name: 'Sequence', color: '#64748b', invariants: [], inputs: ['children', 'initial_input'], outputs: ['final_output'] },
    { id: 'combinator-parallel', name: 'Parallel', color: '#64748b', invariants: [], inputs: ['children', 'shared_input'], outputs: ['merged_output'] },
    { id: 'combinator-choice', name: 'Choice', color: '#64748b', invariants: [], inputs: ['children', 'input'], outputs: ['first_success'] },
    { id: 'combinator-guard', name: 'Guard', color: '#64748b', invariants: [], inputs: ['inner_combinator', 'predicate', 'input'], outputs: ['guarded_output'] },
    { id: 'combinator-transform', name: 'Transform', color: '#64748b', invariants: [], inputs: ['inner_combinator', 'transform_fn', 'input'], outputs: ['transformed_output'] },
  ],
};

const ALL_NODES = Object.values(NODE_REGISTRY).flat();

// ── ExoForge Feedback Dispatch ──
// Posts structured feedback to the gateway-api for the self-improvement cycle.
// Falls back silently if the gateway is unreachable (local dev without backend).
const GATEWAY_URL = window.location.hostname === 'localhost' ? 'http://localhost:3000' : '';
async function dispatchFeedback(widget, page, type, message, context = {}) {
  try {
    const res = await fetch(`${GATEWAY_URL}/api/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ widget, page, type, message, context }),
    });
    if (res.ok) return await res.json();
  } catch (e) {
    // Gateway unreachable — feedback stored locally only
    console.debug('[ExoForge] Gateway unreachable, feedback not dispatched:', e.message);
  }
  return null;
}

const BCTS_STATES = ['Draft', 'Submitted', 'IdentityResolved', 'ConsentValidated', 'Deliberated', 'Verified', 'Governed', 'Approved', 'Executed', 'Recorded', 'Closed', 'Denied', 'Escalated', 'Remediated'];
const TERMINAL_STATES = ['Closed', 'Denied'];

const WORKFLOW_TEMPLATES = [
  { name: 'Board Resolution', desc: 'Full board decision lifecycle with quorum and fiduciary checks', nodes: ['identity-verify', 'authority-check', 'consent-verify', 'governance-propose', 'governance-vote', 'governance-resolve', 'proof-generate', 'dag-append'] },
  { name: 'Class Action Response', desc: 'Multi-party dispute resolution with evidence and adjudication', nodes: ['identity-verify', 'consent-request', 'kernel-adjudicate', 'proof-generate', 'proof-verify', 'escalation-trigger', 'human-override', 'dag-append'] },
  { name: 'Consent-Gated Action', desc: 'Verify identity, check consent, execute with kernel adjudication', nodes: ['identity-verify', 'consent-verify', 'kernel-adjudicate'] },
  { name: 'Emergency Escalation', desc: 'Trigger escalation with human override and ratification', nodes: ['escalation-trigger', 'human-override', 'governance-propose', 'governance-vote', 'governance-resolve'] },
  { name: 'Data Portability Exit', desc: 'Governed data export with consent revocation and proof chain', nodes: ['governance-propose', 'governance-vote', 'governance-resolve', 'consent-revoke', 'proof-generate', 'dag-append', 'human-override'] },
  { name: 'Conflict-of-Interest Check', desc: 'Pre-vote conflict screening with disclosure or recusal', nodes: ['identity-verify', 'governance-vote', 'combinator-guard', 'combinator-choice', 'human-override', 'dag-append'] },
  { name: 'SSO Federation', desc: 'Identity federation with consent-gated role mapping', nodes: ['identity-verify', 'consent-request', 'authority-delegate', 'invariant-check', 'tenant-isolate', 'mcp-enforce'] },
  { name: 'Fiduciary TCO/ROI', desc: 'Calculate TCO/ROI with fiduciary-grade provenance', nodes: ['identity-verify', 'consent-request', 'authority-check', 'combinator-transform', 'proof-generate', 'dag-append', 'human-override'] },
];

const CONSTITUTIONAL_INVARIANTS = [
  { name: 'DemocraticLegitimacy', desc: 'All governance actions require democratic mandate through proper voting and quorum' },
  { name: 'DelegationGovernance', desc: 'Authority delegation must follow chain-of-custody with no self-grant' },
  { name: 'DualControl', desc: 'Critical operations require two independent actors for approval' },
  { name: 'HumanOversight', desc: 'AI and automated actions must have human escalation path' },
  { name: 'TransparencyAccountability', desc: 'All governance actions are recorded with full provenance trail' },
  { name: 'ConflictAdjudication', desc: 'Conflicts of interest are detected and adjudicated by the kernel' },
  { name: 'TechnologicalHumility', desc: 'Technology failures trigger graceful degradation, not silent corruption' },
  { name: 'ExistentialSafeguard', desc: 'Constitutional amendments require supermajority and cooling period' },
];

// ══════════════════════════════════════════════════════════════
// API Helpers
// ══════════════════════════════════════════════════════════════
const API = '/api';
async function api(path, opts) {
  try {
    const res = await fetch(`${API}${path}`, { headers: { 'Content-Type': 'application/json' }, ...opts });
    return await res.json();
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════
// LAYOUT PERSISTENCE
// ══════════════════════════════════════════════════════════════
const STORAGE_KEY = 'exochain-widget-layouts';

function loadLayouts() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved ? JSON.parse(saved) : {};
  } catch { return {}; }
}

function saveLayouts(layouts) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(layouts)); } catch {}
}

// ══════════════════════════════════════════════════════════════
// DEFAULT LAYOUTS PER PAGE
// ══════════════════════════════════════════════════════════════
const DEFAULT_LAYOUTS = {
  dashboard: [
    { id: 'stats', type: 'stats-row', col: 1, row: 1, colSpan: 12, rowSpan: 1 },
    { id: 'bcts-machine', type: 'bcts-machine', col: 1, row: 2, colSpan: 6, rowSpan: 2 },
    { id: 'workflow-stages', type: 'workflow-stages', col: 7, row: 2, colSpan: 6, rowSpan: 2 },
    { id: 'governors', type: 'governors-table', col: 1, row: 4, colSpan: 6, rowSpan: 3 },
    { id: 'decisions-table', type: 'decisions-table', col: 7, row: 4, colSpan: 6, rowSpan: 3 },
  ],
  bod: [
    { id: 'bod-stats', type: 'bod-stats', col: 1, row: 1, colSpan: 12, rowSpan: 1 },
    { id: 'bod-create', type: 'bod-create', col: 1, row: 2, colSpan: 12, rowSpan: 1 },
    { id: 'bod-resolutions', type: 'bod-resolutions', col: 1, row: 3, colSpan: 12, rowSpan: 4 },
  ],
  classaction: [
    { id: 'ca-stats', type: 'ca-stats', col: 1, row: 1, colSpan: 12, rowSpan: 1 },
    { id: 'ca-cases', type: 'ca-cases', col: 1, row: 2, colSpan: 7, rowSpan: 3 },
    { id: 'ca-invariants', type: 'ca-invariants', col: 8, row: 2, colSpan: 5, rowSpan: 3 },
    { id: 'ca-evidence', type: 'ca-evidence', col: 1, row: 5, colSpan: 6, rowSpan: 3 },
    { id: 'ca-workflow', type: 'ca-workflow', col: 7, row: 5, colSpan: 6, rowSpan: 3 },
  ],
  builder: [
    { id: 'builder-main', type: 'builder-main', col: 1, row: 1, colSpan: 12, rowSpan: 6 },
  ],
  feedback: [
    { id: 'ai-chat', type: 'ai-chat', col: 1, row: 1, colSpan: 6, rowSpan: 4 },
    { id: 'quick-actions', type: 'quick-actions', col: 7, row: 1, colSpan: 6, rowSpan: 2 },
    { id: 'feedback-pipeline', type: 'feedback-pipeline', col: 7, row: 3, colSpan: 6, rowSpan: 2 },
    { id: 'backlog', type: 'council-backlog', col: 1, row: 5, colSpan: 8, rowSpan: 3 },
    { id: 'archon', type: 'archon-pipeline', col: 9, row: 5, colSpan: 4, rowSpan: 3 },
  ],
  explorer: [
    { id: 'invariants-grid', type: 'invariants-grid', col: 1, row: 1, colSpan: 8, rowSpan: 3 },
    { id: 'crypto-prims', type: 'crypto-primitives', col: 9, row: 1, colSpan: 4, rowSpan: 3 },
    { id: 'mcp-rules', type: 'mcp-rules', col: 1, row: 4, colSpan: 6, rowSpan: 3 },
    { id: 'bcts-lifecycle', type: 'bcts-lifecycle', col: 7, row: 4, colSpan: 6, rowSpan: 3 },
  ],
};

// ══════════════════════════════════════════════════════════════
// WIDGET CATALOG — all available widget types
// ══════════════════════════════════════════════════════════════
const WIDGET_CATALOG = [
  { type: 'stats-row', name: 'Stats Overview', desc: 'Key metrics: nodes, decisions, invariants, MCP rules', defaultSpan: [12, 1], category: 'Dashboard' },
  { type: 'bcts-machine', name: 'BCTS State Machine', desc: '14-state governance lifecycle flow', defaultSpan: [6, 2], category: 'Dashboard' },
  { type: 'workflow-stages', name: 'Workflow Stages', desc: 'Active workflow stage badges', defaultSpan: [6, 2], category: 'Dashboard' },
  { type: 'governors-table', name: 'Governors Table', desc: 'Enrolled governors with PACE status and identity scores', defaultSpan: [6, 3], category: 'Dashboard' },
  { type: 'decisions-table', name: 'Decisions Table', desc: 'Active decisions with status and class', defaultSpan: [6, 3], category: 'Dashboard' },
  { type: 'bod-stats', name: 'BoD Stats', desc: 'Pending, resolved, quorum threshold', defaultSpan: [12, 1], category: 'Board' },
  { type: 'bod-create', name: 'Create Resolution', desc: 'Create new board resolution via WASM', defaultSpan: [12, 1], category: 'Board' },
  { type: 'bod-resolutions', name: 'Board Resolutions', desc: 'Resolution table with BCTS lifecycle drill-down', defaultSpan: [12, 4], category: 'Board' },
  { type: 'ca-stats', name: 'Class Action Stats', desc: 'Active cases, parties, resolution time', defaultSpan: [12, 1], category: 'Class Action' },
  { type: 'ca-cases', name: 'Cases Table', desc: 'Class action cases with severity and status', defaultSpan: [7, 3], category: 'Class Action' },
  { type: 'ca-invariants', name: 'Constitutional Check', desc: 'Invariant adjudication results', defaultSpan: [5, 3], category: 'Class Action' },
  { type: 'ca-evidence', name: 'Evidence Chain', desc: 'WASM-powered hash-chained evidence', defaultSpan: [6, 3], category: 'Class Action' },
  { type: 'ca-workflow', name: 'CA Workflow', desc: 'Class action Syntaxis workflow', defaultSpan: [6, 3], category: 'Class Action' },
  { type: 'builder-main', name: 'Syntaxis Builder', desc: '3-panel visual workflow builder', defaultSpan: [12, 6], category: 'Build' },
  { type: 'ai-chat', name: 'AI Chat', desc: 'Context-sensitive AI assistant', defaultSpan: [6, 4], category: 'AI & Backlog' },
  { type: 'quick-actions', name: 'Quick Actions', desc: 'Pre-built AI prompts', defaultSpan: [6, 2], category: 'AI & Backlog' },
  { type: 'feedback-pipeline', name: 'Feedback Pipeline', desc: 'AI → Council → Archon → Deploy flow', defaultSpan: [6, 2], category: 'AI & Backlog' },
  { type: 'council-backlog', name: 'Council Backlog', desc: 'Governance backlog with voting and triage', defaultSpan: [8, 3], category: 'AI & Backlog' },
  { type: 'archon-pipeline', name: 'Archon Pipeline', desc: 'Remote coding agent integration', defaultSpan: [4, 3], category: 'AI & Backlog' },
  { type: 'invariants-grid', name: 'Invariants Grid', desc: '8 constitutional invariants with details', defaultSpan: [8, 3], category: 'Explorer' },
  { type: 'crypto-primitives', name: 'Crypto Primitives', desc: 'WASM cryptographic operations', defaultSpan: [4, 3], category: 'Explorer' },
  { type: 'mcp-rules', name: 'MCP Rules', desc: 'AI governance MCP rule table', defaultSpan: [6, 3], category: 'Explorer' },
  { type: 'bcts-lifecycle', name: 'BCTS Lifecycle', desc: 'Full 14-state lifecycle detail view', defaultSpan: [6, 3], category: 'Explorer' },
];

// ══════════════════════════════════════════════════════════════
// SHARED COMPONENTS
// ══════════════════════════════════════════════════════════════

function JsonViewer({ data }) {
  return <pre className="json-viewer">{JSON.stringify(data, null, 2)}</pre>;
}

function Badge({ type, children }) {
  return <span className={`badge badge-${type}`}>{children}</span>;
}

// Context-sensitive AI help suggestions per widget type
const AI_HELP_CONTEXT = {
  'stats-row': [
    { icon: '?', text: 'What do these stats mean?', response: 'The stats show: **Syntaxis Nodes** (23 composable governance primitives), **Active Decisions** (live BCTS-tracked items), **Constitutional Invariants** (8 kernel-enforced rules), and **MCP Rules** (AI governance controls). Click any stat card to navigate to its detail view.' },
    { icon: '→', text: 'How to create a new decision', response: 'Navigate to **Board of Directors** via the sidebar, then use the "Create Board Resolution" form. Each decision enters the 14-state BCTS lifecycle and is tracked with constitutional invariant compliance.' },
  ],
  'bcts-machine': [
    { icon: '?', text: 'What is BCTS?', response: 'BCTS (Blockchain Transaction State) is the 14-state lifecycle that every governance action follows. States progress from Draft → Submitted → IdentityResolved → ... → Closed/Denied. Each transition is validated against constitutional invariants by the CGR kernel.' },
    { icon: '⚡', text: 'Which transitions are gated?', response: 'All transitions require at least one invariant check. Key gates:\n- **Submitted→IdentityResolved**: Requires PACE enrollment verification\n- **Deliberated→Verified**: Requires quorum check\n- **Governed→Approved**: Requires authority chain validation\n- **Any→Escalated**: Triggered by invariant violation' },
  ],
  'governors-table': [
    { icon: '?', text: 'What is PACE status?', response: 'PACE (Provable Authentication & Credential Exchange) is the identity enrollment protocol. "Enrolled" means the governor has completed identity proofing with Shamir key ceremony and has an active identity score.' },
    { icon: '→', text: 'How identity scores work', response: 'Identity scores combine factors: **document verification**, **biometric liveness**, **delegation depth**, and **governance participation**. Scores determine voting weight and delegation eligibility. Tier thresholds: Observer (<50), Standard (50-80), Elevated (80+).' },
  ],
  'decisions-table': [
    { icon: '→', text: 'Decision lifecycle explained', response: 'Each decision follows BCTS: Draft → Submitted → through 14 states. Classes include **Constitutional**, **Operational**, **Emergency**, and **Administrative**. Constitutional decisions require supermajority quorum.' },
  ],
  'bod-resolutions': [
    { icon: '?', text: 'How quorum is calculated', response: 'Quorum requires >50% of eligible voters to participate, with at least 2 independent board members. The WASM engine computes `wasm_check_quorum()` using the constitutional spec for each decision class.' },
    { icon: '⚡', text: 'What happens on denial?', response: 'Denied decisions enter the Denied terminal state. A contestation period (GOV-008) allows the proposer to challenge with new evidence. Challenges trigger a new deliberation cycle with the Challenge sub-state.' },
  ],
  'ca-cases': [
    { icon: '?', text: 'Case status meanings', response: '**Discovery**: Evidence collection phase, parties being identified\n**Adjudication**: Kernel is evaluating case against invariants\n**Resolution**: Settlement or ruling being formalized\n\nEach phase enforces ConflictAdjudication and TransparencyAccountability invariants.' },
  ],
  'ca-evidence': [
    { icon: '⚡', text: 'How evidence is verified', response: 'Each evidence item is: 1) Hashed with Blake3 via WASM, 2) Chain-linked to the previous hash, 3) Signed with the custodian\'s Ed25519 key, 4) Appended to the immutable DAG. Tampering breaks the hash chain and triggers escalation.' },
  ],
  'builder-main': [
    { icon: '?', text: 'How to build a workflow', response: '1. Click nodes from the left palette to add them\n2. Or select a template from the buttons above\n3. Click a node on the canvas to see its properties\n4. Choose composition type: Sequence, Parallel, Choice, or Guarded\n5. The collected invariants show which constitutional rules your workflow enforces' },
    { icon: '→', text: 'Template recommendations', response: 'Start with **Board Resolution** for full-lifecycle governance, or **Consent-Gated Action** for simple access control. **Emergency Escalation** is best for incident response flows.' },
  ],
  'council-backlog': [
    { icon: '?', text: 'How items reach the backlog', response: 'Items enter via 3 paths:\n1. **AI Suggestion** — The AI assistant proposes improvements\n2. **User Feedback** — Direct submission from team members\n3. **Council Review** — Council members propose items\n\nAll items require council votes before entering the Archon implementation pipeline.' },
  ],
  'archon-pipeline': [
    { icon: '?', text: 'What is Archon?', response: 'Archon is the remote coding agent that autonomously implements approved backlog items. It uses a DAG workflow: parse PRD → generate code → validate against constitutional invariants → create PR. All outputs pass through a governance gate before deployment.' },
  ],
  'invariants-grid': [
    { icon: '⚡', text: 'Which invariants are most critical?', response: '**ExistentialSafeguard** is paramount — it prevents constitutional amendments without supermajority + cooling period. **HumanOversight** is critical for AI governance — no automated action can bypass human escalation paths.' },
  ],
};

function AIHelpMenu({ widgetType }) {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [responses, setResponses] = useState([]);
  const ref = useRef(null);

  const suggestions = AI_HELP_CONTEXT[widgetType] || [];
  if (suggestions.length === 0) return null;

  const handleSuggestion = (s) => {
    setResponses(prev => [...prev, { q: s.text, a: s.response }]);
    dispatchFeedback(widgetType, 'current', 'help-click', s.text, { suggestion: true });
  };

  const handleAsk = () => {
    if (!question.trim()) return;
    // Simple keyword matching for custom questions
    const lower = question.toLowerCase();
    let response = 'I can help with questions about this widget. Try clicking one of the suggested questions above, or ask about specific governance concepts.';
    if (lower.includes('invariant')) response = 'Constitutional invariants are the 8 immutable rules enforced by the ExoChain kernel at every BCTS state transition. They ensure democratic legitimacy, authority chain integrity, human oversight, and more.';
    else if (lower.includes('bcts') || lower.includes('state')) response = 'The BCTS state machine has 14 states. Every governance action progresses through this lifecycle, with invariant checks at each transition.';
    else if (lower.includes('wasm')) response = 'The WASM engine (637KB, 45 functions) is compiled from 28K lines of Rust. It powers all cryptographic operations, combinator algebra, governance logic, and identity verification in the browser.';
    else if (lower.includes('node') || lower.includes('syntaxis')) response = 'There are 23 Syntaxis node types across 8 categories. Each node represents a composable governance primitive that enforces specific constitutional invariants.';
    // Dispatch to ExoForge for the self-improvement cycle
    dispatchFeedback(widgetType, 'current', 'question', question, { matched_topic: lower.includes('invariant') ? 'invariant' : lower.includes('bcts') ? 'bcts' : lower.includes('wasm') ? 'wasm' : 'general' });
    setResponses(prev => [...prev, { q: question, a: response }]);
    setQuestion('');
  };

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div className={`ai-help-trigger ${open ? 'open' : ''}`} onClick={() => setOpen(!open)} title="AI Help">?</div>
      {open && (
        <div className="ai-help-popover">
          <div className="ai-help-popover-header">
            <span>AI Help</span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'none', fontWeight: 400, letterSpacing: 0 }}>Context-aware</span>
          </div>
          <div className="ai-help-popover-body">
            {responses.map((r, i) => (
              <div key={i}>
                <div style={{ fontSize: 11, fontWeight: 500, color: 'var(--accent-blue)', marginBottom: 4 }}>{r.q}</div>
                <div className="ai-help-response">{r.a}</div>
              </div>
            ))}
            {suggestions.map((s, i) => (
              <div key={i} className="ai-help-suggestion" onClick={() => handleSuggestion(s)}>
                <div className="ahs-icon">{s.icon}</div>
                <span>{s.text}</span>
              </div>
            ))}
          </div>
          <div className="ai-help-input">
            <input value={question} onChange={e => setQuestion(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleAsk()} placeholder="Ask anything..." />
            <button className="btn btn-primary" onClick={handleAsk}>Ask</button>
          </div>
        </div>
      )}
    </div>
  );
}

function Drawer({ open, onClose, title, children }) {
  if (!open) return null;
  return (<>
    <div className="drawer-overlay" onClick={onClose} />
    <div className="drawer">
      <div className="drawer-header">
        <h3>{title}</h3>
        <span className="drawer-close" onClick={onClose}>✕</span>
      </div>
      {children}
    </div>
  </>);
}

// ══════════════════════════════════════════════════════════════
// WIDGET GRID — Drag & Drop Engine
// ══════════════════════════════════════════════════════════════

function WidgetGrid({ layout, setLayout, renderWidget, editing, pageId }) {
  const [dragIdx, setDragIdx] = useState(null);
  const [dragOverIdx, setDragOverIdx] = useState(null);
  const [resizing, setResizing] = useState(null);
  const gridRef = useRef(null);

  const handleDragStart = useCallback((e, idx) => {
    if (!editing) return;
    setDragIdx(idx);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', idx.toString());
  }, [editing]);

  const handleDragOver = useCallback((e, idx) => {
    if (!editing || dragIdx === null || dragIdx === idx) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOverIdx(idx);
  }, [editing, dragIdx]);

  const handleDrop = useCallback((e, targetIdx) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === targetIdx) return;
    setLayout(prev => {
      const next = [...prev];
      const dragged = next[dragIdx];
      const target = next[targetIdx];
      // Swap grid positions
      const { col: dc, row: dr, colSpan: dcs, rowSpan: drs } = dragged;
      next[dragIdx] = { ...dragged, col: target.col, row: target.row };
      next[targetIdx] = { ...target, col: dc, row: dr };
      return next;
    });
    setDragIdx(null);
    setDragOverIdx(null);
  }, [dragIdx, setLayout]);

  const handleDragEnd = useCallback(() => {
    setDragIdx(null);
    setDragOverIdx(null);
  }, []);

  const handleResizeStart = useCallback((e, idx) => {
    e.preventDefault();
    e.stopPropagation();
    if (!editing) return;
    const startX = e.clientX;
    const startY = e.clientY;
    const widget = layout[idx];
    const startColSpan = widget.colSpan;
    const startRowSpan = widget.rowSpan;
    const gridEl = gridRef.current;
    if (!gridEl) return;
    const gridRect = gridEl.getBoundingClientRect();
    const colWidth = gridRect.width / 12;
    const rowHeight = 80;

    const onMouseMove = (me) => {
      const dx = me.clientX - startX;
      const dy = me.clientY - startY;
      const newColSpan = Math.max(1, Math.min(12 - widget.col + 1, Math.round(startColSpan + dx / colWidth)));
      const newRowSpan = Math.max(1, Math.round(startRowSpan + dy / rowHeight));
      setLayout(prev => {
        const next = [...prev];
        next[idx] = { ...next[idx], colSpan: newColSpan, rowSpan: newRowSpan };
        return next;
      });
    };
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
      setResizing(null);
    };
    setResizing(idx);
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  }, [editing, layout, setLayout]);

  const removeWidget = useCallback((idx) => {
    setLayout(prev => prev.filter((_, i) => i !== idx));
  }, [setLayout]);

  return (
    <div ref={gridRef} className={`widget-grid ${editing ? 'editing' : ''}`}>
      {layout.map((w, idx) => (
        <div
          key={w.id}
          className={`widget ${dragIdx === idx ? 'dragging' : ''} ${dragOverIdx === idx ? 'drag-over' : ''}`}
          style={{
            gridColumn: `${w.col} / span ${w.colSpan}`,
            gridRow: `${w.row} / span ${w.rowSpan}`,
            minHeight: w.rowSpan * 80,
          }}
          draggable={editing}
          onDragStart={(e) => handleDragStart(e, idx)}
          onDragOver={(e) => handleDragOver(e, idx)}
          onDrop={(e) => handleDrop(e, idx)}
          onDragEnd={handleDragEnd}
        >
          {editing && <div className="widget-handle">⠿</div>}
          {editing && <div className="widget-remove" onClick={() => removeWidget(idx)}>✕</div>}
          {editing && <div className="widget-resize" onMouseDown={(e) => handleResizeStart(e, idx)} />}
          {renderWidget(w)}
        </div>
      ))}
    </div>
  );
}

function WidgetCatalog({ open, onClose, onAdd, currentTypes }) {
  if (!open) return null;
  const categories = [...new Set(WIDGET_CATALOG.map(w => w.category))];
  return (<>
    <div className="widget-catalog-overlay" onClick={onClose} />
    <div className="widget-catalog">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3>Add Widget</h3>
        <span className="drawer-close" onClick={onClose}>✕</span>
      </div>
      {categories.map(cat => (
        <div key={cat}>
          <div className="nav-section">{cat}</div>
          {WIDGET_CATALOG.filter(w => w.category === cat).map(w => {
            const exists = currentTypes.includes(w.type);
            return (
              <div key={w.type} className="widget-catalog-item" style={exists ? { opacity: 0.4 } : {}} onClick={() => !exists && onAdd(w)}>
                <div className="wci-name">{w.name} {exists && <Badge type="blue">Added</Badge>}</div>
                <div className="wci-desc">{w.desc}</div>
                <div className="wci-size">{w.defaultSpan[0]} col × {w.defaultSpan[1]} row</div>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  </>);
}

// ══════════════════════════════════════════════════════════════
// WIDGET RENDERERS — each type gets its own render function
// ══════════════════════════════════════════════════════════════

// ── Dashboard Widgets ─────────────────────────────────────

function StatsRowWidget({ data, setPage }) {
  const { decisions = [], systemInfo } = data;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, padding: 20 }}>
      <div className="stat-card" onClick={() => setPage('builder')}>
        <div className="stat-label">Syntaxis Nodes</div>
        <div className="stat-value">{ALL_NODES.length}</div>
        <div style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>23 node types, 8 categories</div>
      </div>
      <div className="stat-card" onClick={() => setPage('bod')}>
        <div className="stat-label">Active Decisions</div>
        <div className="stat-value">{decisions.length || '—'}</div>
        <div style={{ fontSize: 11, color: 'var(--accent-green)' }}>BCTS 14-state lifecycle</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Constitutional Invariants</div>
        <div className="stat-value">{systemInfo?.constitutional_invariants?.length || 8}</div>
        <div style={{ fontSize: 11, color: 'var(--accent-purple)' }}>CGR kernel enforced</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">MCP Rules</div>
        <div className="stat-value">{systemInfo?.mcp_rules?.length || 6}</div>
        <div style={{ fontSize: 11, color: 'var(--accent-amber)' }}>AI governance controls</div>
      </div>
    </div>
  );
}

function BCTSMachineWidget() {
  const [activeState, setActiveState] = useState(null);
  return (<>
    <div className="widget-header"><span className="widget-title">BCTS State Machine</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><Badge type="cyan">14 States</Badge><AIHelpMenu widgetType="bcts-machine" /></div></div>
    <div className="widget-body">
      <div className="bcts-flow">
        {BCTS_STATES.map((s, i) => (<span key={s}>
          <span className={`bcts-state ${s === activeState ? 'active' : ''} ${TERMINAL_STATES.includes(s) ? (s === 'Denied' ? 'denied' : 'terminal') : ''}`} onClick={() => setActiveState(activeState === s ? null : s)}>{s}</span>
          {i < BCTS_STATES.length - 1 && <span className="bcts-arrow"> → </span>}
        </span>))}
      </div>
      {activeState && (
        <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{activeState}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            State #{BCTS_STATES.indexOf(activeState) + 1} — {TERMINAL_STATES.includes(activeState) ? 'Terminal state' : `Next: ${BCTS_STATES[BCTS_STATES.indexOf(activeState) + 1] || 'N/A'}`}
          </div>
        </div>
      )}
    </div>
  </>);
}

function WorkflowStagesWidget({ data }) {
  const { systemInfo } = data;
  return (<>
    <div className="widget-header"><span className="widget-title">Workflow Stages</span><Badge type="blue">{systemInfo?.workflow_stages?.length || 11} stages</Badge></div>
    <div className="widget-body">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {(systemInfo?.workflow_stages || ['Ingestion', 'Identity', 'Consent', 'Authorization', 'Governance', 'Adjudication', 'Execution', 'Recording', 'Notification', 'Audit', 'Archival']).map(s => <Badge key={s} type="purple">{s}</Badge>)}
      </div>
    </div>
  </>);
}

function GovernorsTableWidget({ data }) {
  const { users = [], scores = [] } = data;
  const [selectedUser, setSelectedUser] = useState(null);
  return (<>
    <div className="widget-header"><span className="widget-title">Governors</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{users.length} enrolled</span><AIHelpMenu widgetType="governors-table" /></div></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>Name</th><th>DID</th><th>PACE</th><th>Score</th></tr></thead>
        <tbody>
          {users.map(u => {
            const score = scores.find(s => s.did === u.did);
            return (
              <tr key={u.did} onClick={() => setSelectedUser(u)}>
                <td style={{ fontWeight: 500 }}>{u.display_name}</td>
                <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{u.did}</td>
                <td><Badge type={u.pace_status === 'Enrolled' ? 'green' : 'amber'}>{u.pace_status}</Badge></td>
                <td>{score ? <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{score.score}</span> : '—'}</td>
              </tr>
            );
          })}
          {users.length === 0 && <tr><td colSpan={4} style={{ color: 'var(--text-muted)', textAlign: 'center' }}>Connect to API to see live data</td></tr>}
        </tbody>
      </table>
    </div>
    <Drawer open={!!selectedUser} onClose={() => setSelectedUser(null)} title={selectedUser?.display_name || ''}>
      {selectedUser && <>
        <div className="prop-section"><div className="prop-label">DID</div><div className="prop-value" style={{ fontFamily: 'JetBrains Mono, monospace' }}>{selectedUser.did}</div></div>
        <div className="prop-section"><div className="prop-label">Email</div><div className="prop-value">{selectedUser.email}</div></div>
        <div className="prop-section"><div className="prop-label">Roles</div><div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>{(typeof selectedUser.roles === 'string' ? JSON.parse(selectedUser.roles) : selectedUser.roles || []).map(r => <Badge key={r} type="blue">{r}</Badge>)}</div></div>
        <div className="prop-section"><div className="prop-label">PACE Status</div><Badge type="green">{selectedUser.pace_status}</Badge></div>
        <div className="prop-section"><div className="prop-label">Identity Score</div>{(() => { const s = scores.find(x => x.did === selectedUser.did); return s ? <><div className="stat-value">{s.score}</div><Badge type="cyan">{s.tier}</Badge><div style={{ marginTop: 8 }}><JsonViewer data={s.factors} /></div></> : '—'; })()}</div>
        <div className="prop-section"><div className="prop-label">Raw Data</div><JsonViewer data={selectedUser} /></div>
      </>}
    </Drawer>
  </>);
}

function DecisionsTableWidget({ data, setPage }) {
  const { decisions = [] } = data;
  return (<>
    <div className="widget-header"><span className="widget-title">Active Decisions</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><AIHelpMenu widgetType="decisions-table" /><button className="btn btn-primary btn-sm" onClick={() => setPage('bod')}>View All</button></div></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>Title</th><th>Status</th><th>Class</th></tr></thead>
        <tbody>
          {decisions.map(d => (
            <tr key={d.id_hash}>
              <td style={{ fontWeight: 500 }}>{d.title}</td>
              <td><Badge type={d.status === 'Approved' ? 'green' : d.status === 'Denied' ? 'red' : 'blue'}>{d.status}</Badge></td>
              <td><Badge type="purple">{d.decision_class}</Badge></td>
            </tr>
          ))}
          {decisions.length === 0 && <tr><td colSpan={3} style={{ color: 'var(--text-muted)', textAlign: 'center' }}>Connect to PostgreSQL to see live data</td></tr>}
        </tbody>
      </table>
    </div>
  </>);
}

// ── Board of Directors Widgets ────────────────────────────

function BoDStatsWidget({ data }) {
  const { decisions = [] } = data;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, padding: 20 }}>
      <div className="stat-card"><div className="stat-label">Pending Decisions</div><div className="stat-value">{decisions.filter(d => !TERMINAL_STATES.includes(d.status)).length}</div></div>
      <div className="stat-card"><div className="stat-label">Resolved</div><div className="stat-value" style={{ color: 'var(--accent-green)' }}>{decisions.filter(d => d.status === 'Closed' || d.status === 'Approved').length}</div></div>
      <div className="stat-card"><div className="stat-label">Quorum Threshold</div><div className="stat-value">51%</div><div style={{ fontSize: 11, color: 'var(--text-muted)' }}>2 independent required</div></div>
    </div>
  );
}

function BoDCreateWidget({ data, setData }) {
  const [newTitle, setNewTitle] = useState('');
  const [creating, setCreating] = useState(false);
  const createDecision = async () => {
    if (!newTitle) return;
    setCreating(true);
    const result = await api('/decisions', { method: 'POST', body: JSON.stringify({ title: newTitle, decision_class: 'Operational', author_did: 'did:exo:alice' }) });
    if (result?.decision) {
      setData(prev => ({ ...prev, decisions: [{ id_hash: result.decision.id, title: newTitle, status: 'Draft', decision_class: 'Operational', author: 'did:exo:alice', created_at_ms: Date.now() }, ...(prev.decisions || [])] }));
      setNewTitle('');
    }
    setCreating(false);
  };
  return (<>
    <div className="widget-header"><span className="widget-title">Create Board Resolution</span></div>
    <div className="widget-body">
      <div style={{ display: 'flex', gap: 12 }}>
        <input placeholder="Resolution title..." value={newTitle} onChange={e => setNewTitle(e.target.value)} onKeyDown={e => e.key === 'Enter' && createDecision()} />
        <button className="btn btn-primary" onClick={createDecision} disabled={creating}>{creating ? 'Creating...' : 'Create via WASM'}</button>
      </div>
    </div>
  </>);
}

function BoDResolutionsWidget({ data }) {
  const { decisions = [] } = data;
  const [selected, setSelected] = useState(null);
  return (<>
    <div className="widget-header"><span className="widget-title">Board Resolutions</span><AIHelpMenu widgetType="bod-resolutions" /></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>Resolution</th><th>Status</th><th>Class</th><th>Author</th><th>Created</th></tr></thead>
        <tbody>
          {decisions.map(d => (
            <tr key={d.id_hash} onClick={() => setSelected(d)}>
              <td style={{ fontWeight: 500 }}>{d.title}</td>
              <td><Badge type={d.status === 'Approved' || d.status === 'Closed' ? 'green' : d.status === 'Denied' ? 'red' : 'blue'}>{d.status}</Badge></td>
              <td><Badge type="purple">{d.decision_class}</Badge></td>
              <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{d.author}</td>
              <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{new Date(d.created_at_ms).toLocaleDateString()}</td>
            </tr>
          ))}
          {decisions.length === 0 && <tr><td colSpan={5} style={{ color: 'var(--text-muted)', textAlign: 'center' }}>No resolutions yet</td></tr>}
        </tbody>
      </table>
    </div>
    <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected?.title || ''}>
      {selected && <>
        <div className="prop-section"><div className="prop-label">Decision ID</div><div className="prop-value" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{selected.id_hash}</div></div>
        <div className="prop-section"><div className="prop-label">Status</div><Badge type="blue">{selected.status}</Badge></div>
        <div className="prop-section"><div className="prop-label">BCTS Lifecycle</div>
          <div className="bcts-flow" style={{ marginTop: 8 }}>
            {BCTS_STATES.map((s, i) => (<span key={s}>
              <span className={`bcts-state ${s === selected.status ? 'active' : ''} ${TERMINAL_STATES.includes(s) ? (s === 'Denied' ? 'denied' : 'terminal') : ''}`}>{s}</span>
              {i < BCTS_STATES.length - 1 && <span className="bcts-arrow"> → </span>}
            </span>))}
          </div>
        </div>
        <div className="prop-section"><div className="prop-label">Raw Decision Object</div><JsonViewer data={selected} /></div>
      </>}
    </Drawer>
  </>);
}

// ── Class Action Widgets ──────────────────────────────────

const CA_CASES = [
  { id: 'CA-2026-001', title: 'Data Processing Consent Violation', status: 'Discovery', parties: 142, severity: 'High', filed: '2026-03-01' },
  { id: 'CA-2026-002', title: 'Algorithmic Bias in Credit Scoring', status: 'Adjudication', parties: 89, severity: 'Critical', filed: '2026-02-15' },
  { id: 'CA-2026-003', title: 'Unauthorized Data Sharing (GDPR)', status: 'Resolution', parties: 312, severity: 'High', filed: '2026-01-20' },
];

function CAStatsWidget() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, padding: 20 }}>
      <div className="stat-card"><div className="stat-label">Active Cases</div><div className="stat-value">{CA_CASES.length}</div></div>
      <div className="stat-card"><div className="stat-label">Total Parties</div><div className="stat-value">{CA_CASES.reduce((a, c) => a + c.parties, 0)}</div></div>
      <div className="stat-card"><div className="stat-label">Avg Resolution</div><div className="stat-value">47d</div></div>
    </div>
  );
}

function CACasesWidget() {
  return (<>
    <div className="widget-header"><span className="widget-title">Class Action Cases</span><AIHelpMenu widgetType="ca-cases" /></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>Case ID</th><th>Title</th><th>Status</th><th>Parties</th><th>Severity</th></tr></thead>
        <tbody>
          {CA_CASES.map(c => (
            <tr key={c.id}>
              <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>{c.id}</td>
              <td style={{ fontWeight: 500 }}>{c.title}</td>
              <td><Badge type={c.status === 'Resolution' ? 'green' : c.status === 'Adjudication' ? 'amber' : 'blue'}>{c.status}</Badge></td>
              <td>{c.parties}</td>
              <td><Badge type={c.severity === 'Critical' ? 'red' : 'amber'}>{c.severity}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </>);
}

function CAInvariantsWidget() {
  return (<>
    <div className="widget-header"><span className="widget-title">Constitutional Adjudication</span></div>
    <div className="widget-body">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        {CONSTITUTIONAL_INVARIANTS.map((inv, i) => (
          <div key={inv.name} style={{ padding: 10, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, fontWeight: 500 }}>{inv.name}</span>
              <Badge type={i < 6 ? 'green' : 'amber'}>{i < 6 ? 'Satisfied' : 'Review'}</Badge>
            </div>
          </div>
        ))}
      </div>
    </div>
  </>);
}

function CAEvidenceWidget() {
  const evidence = ['Consent Policy Document v2.1', 'Data Processing Audit Log (Jan-Mar)', 'Affected User Dataset (anonymized)', 'Expert Witness: Prof. Chen Declaration'];
  return (<>
    <div className="widget-header"><span className="widget-title">Evidence Chain</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><Badge type="cyan">WASM</Badge><AIHelpMenu widgetType="ca-evidence" /></div></div>
    <div className="widget-body">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {evidence.map((e, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 10, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'rgba(6,182,212,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--accent-cyan)', flexShrink: 0 }}>#{i+1}</div>
            <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: 12, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e}</div><div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{('0123456789abcdef').repeat(4).slice(i * 8, i * 8 + 16)}...</div></div>
            <Badge type="green">Verified</Badge>
          </div>
        ))}
      </div>
    </div>
  </>);
}

function CAWorkflowWidget() {
  const nodes = ['identity-verify', 'consent-request', 'kernel-adjudicate', 'proof-generate', 'proof-verify', 'escalation-trigger', 'human-override', 'dag-append'];
  return (<>
    <div className="widget-header"><span className="widget-title">CA Syntaxis Workflow</span></div>
    <div className="widget-body">
      {nodes.map((nodeId, i) => {
        const node = ALL_NODES.find(n => n.id === nodeId);
        return (<div key={i}>
          {i > 0 && <div className="canvas-connector" />}
          <div className="canvas-node">
            <div className="canvas-node-header">
              <span className="canvas-node-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: '50%', background: node?.color || '#64748b' }} />{node?.name || nodeId}</span>
              <span className="canvas-node-type">{nodeId}</span>
            </div>
            {node?.invariants?.length > 0 && <div className="canvas-node-invariants">{node.invariants.map(inv => <Badge key={inv} type="purple">{inv}</Badge>)}</div>}
          </div>
        </div>);
      })}
    </div>
  </>);
}

// ── Builder Widget ────────────────────────────────────────

function BuilderMainWidget() {
  const [workflowNodes, setWorkflowNodes] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [workflowName, setWorkflowName] = useState('new-workflow');
  const [composition, setComposition] = useState('sequence');
  const [showJson, setShowJson] = useState(false);
  const [search, setSearch] = useState('');

  const addNode = (node) => {
    setWorkflowNodes(prev => [...prev, { ...node, stepId: `step_${prev.length + 1}`, config: {} }]);
  };
  const removeNode = (idx) => {
    setWorkflowNodes(prev => prev.filter((_, i) => i !== idx));
    if (selectedNode === idx) setSelectedNode(null);
  };
  const loadTemplate = (template) => {
    setWorkflowName(template.name.toLowerCase().replace(/\s+/g, '-'));
    setWorkflowNodes(template.nodes.map((nodeId, i) => {
      const node = ALL_NODES.find(n => n.id === nodeId);
      return { ...node, stepId: `step_${i + 1}`, config: {} };
    }));
  };

  const workflowJson = {
    name: workflowName,
    composition,
    steps: workflowNodes.map(n => ({ node: n.id, id: n.stepId, config: n.config })),
    invariants: [...new Set(workflowNodes.flatMap(n => n.invariants || []))],
  };

  const filteredRegistry = useMemo(() => {
    if (!search) return NODE_REGISTRY;
    const q = search.toLowerCase();
    const result = {};
    for (const [cat, nodes] of Object.entries(NODE_REGISTRY)) {
      const filtered = nodes.filter(n => n.name.toLowerCase().includes(q) || n.id.includes(q));
      if (filtered.length) result[cat] = filtered;
    }
    return result;
  }, [search]);

  return (<>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px 0' }}>
      <div><div className="widget-title">Syntaxis Visual Builder</div><div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Compose governance workflows from 23 node types</div></div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => setShowJson(!showJson)}>{showJson ? 'Hide' : 'Show'} JSON</button>
        <button className="btn btn-primary btn-sm">Generate Rust</button>
      </div>
    </div>
    <div style={{ padding: '8px 20px', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
      {WORKFLOW_TEMPLATES.map(t => (
        <button key={t.name} className="btn btn-secondary btn-sm" onClick={() => loadTemplate(t)} title={t.desc}>{t.name}</button>
      ))}
    </div>
    {showJson && <div style={{ padding: '0 20px 8px' }}><JsonViewer data={workflowJson} /></div>}
    <div className="builder-layout" style={{ margin: '0 20px 20px', height: 'calc(100% - 130px)' }}>
      <div className="node-palette">
        <input placeholder="Search nodes..." value={search} onChange={e => setSearch(e.target.value)} style={{ padding: '6px 10px', fontSize: 12, marginBottom: 8 }} />
        {Object.entries(filteredRegistry).map(([category, nodes]) => (
          <div key={category}>
            <div className="node-palette-title">{category}</div>
            {nodes.map(node => (
              <div key={node.id} className="palette-node" onClick={() => addNode(node)}>
                <span className="node-dot" style={{ background: node.color }} />
                {node.name}
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="canvas">
        {workflowNodes.length === 0 ? (
          <div className="canvas-empty">Click nodes or select a template to build your workflow</div>
        ) : (
          <div>
            <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
              <input value={workflowName} onChange={e => setWorkflowName(e.target.value)} style={{ flex: 1, fontSize: 15, fontWeight: 600, background: 'transparent', border: '1px solid transparent', padding: '4px 8px' }} />
              <select value={composition} onChange={e => setComposition(e.target.value)} style={{ width: 'auto', padding: '4px 12px' }}>
                <option value="sequence">Sequence</option>
                <option value="parallel">Parallel</option>
                <option value="choice">Choice</option>
                <option value="guarded_sequence">Guarded Sequence</option>
              </select>
            </div>
            {workflowNodes.map((node, i) => (
              <div key={i}>
                {i > 0 && <div className="canvas-connector" />}
                <div className={`canvas-node ${selectedNode === i ? 'selected' : ''}`} onClick={() => setSelectedNode(i)}>
                  <div className="canvas-node-header">
                    <span className="canvas-node-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: node.color }} />
                      {node.name}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="canvas-node-type">{node.stepId}</span>
                      <span className="canvas-node-remove" onClick={(e) => { e.stopPropagation(); removeNode(i); }}>✕</span>
                    </div>
                  </div>
                  {node.invariants?.length > 0 && <div className="canvas-node-invariants">{node.invariants.map(inv => <Badge key={inv} type="purple">{inv}</Badge>)}</div>}
                </div>
              </div>
            ))}
            <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)', border: '1px dashed var(--border)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Collected Invariants ({[...new Set(workflowNodes.flatMap(n => n.invariants || []))].length})</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {[...new Set(workflowNodes.flatMap(n => n.invariants || []))].map(inv => <Badge key={inv} type="cyan">{inv}</Badge>)}
              </div>
            </div>
          </div>
        )}
      </div>
      <div className="properties-panel">
        {selectedNode !== null && workflowNodes[selectedNode] ? (() => {
          const node = workflowNodes[selectedNode];
          return <>
            <h4 style={{ marginBottom: 16 }}>{node.name}</h4>
            <div className="prop-section"><div className="prop-label">Node Type</div><div className="prop-value">{node.id}</div></div>
            <div className="prop-section"><div className="prop-label">Step ID</div><div className="prop-value">{node.stepId}</div></div>
            <div className="prop-section"><div className="prop-label">Inputs</div><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{node.inputs?.map(inp => <Badge key={inp} type="blue">{inp}</Badge>)}</div></div>
            <div className="prop-section"><div className="prop-label">Outputs</div><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{node.outputs?.map(out => <Badge key={out} type="green">{out}</Badge>)}</div></div>
            <div className="prop-section"><div className="prop-label">Invariants</div><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{node.invariants?.map(inv => <Badge key={inv} type="purple">{inv}</Badge>)}</div></div>
            <div className="prop-section"><div className="prop-label">Definition</div><JsonViewer data={node} /></div>
          </>;
        })() : (
          <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 16 }}>Select a node to view its properties, inputs, outputs, and invariants.</div>
        )}
      </div>
    </div>
  </>);
}

// ── AI & Feedback Widgets ─────────────────────────────────

function AIChatWidget({ data, setData }) {
  const [messages, setMessages] = useState([
    { role: 'ai', text: 'Welcome to ExoChain AI Assistant. I can help you design Syntaxis workflows, evaluate governance decisions, check constitutional compliance, or suggest improvements. What would you like to work on?', context: null },
  ]);
  const [input, setInput] = useState('');
  const [thinking, setThinking] = useState(false);
  const msgsRef = useRef(null);

  useEffect(() => {
    if (msgsRef.current) msgsRef.current.scrollTop = msgsRef.current.scrollHeight;
  }, [messages]);

  const generateResponse = useCallback((userMsg) => {
    const lower = userMsg.toLowerCase();
    // Context-sensitive responses with intelligent elicitation
    if (lower.includes('workflow') || lower.includes('design')) {
      return {
        text: `Based on your requirements, I recommend a **Consent-Gated Governance** workflow:\n\n1. \`identity-verify\` → Authenticate the actor\n2. \`consent-verify\` → Check active bailment\n3. \`governance-propose\` → Submit for deliberation\n4. \`governance-vote\` → Collect votes with quorum\n5. \`governance-resolve\` → Resolve based on threshold\n6. \`dag-append\` → Record to immutable ledger\n\nThis enforces 5 of the 8 constitutional invariants.\n\n**Follow-up questions:**\n- What quorum percentage should be required?\n- Should this include an escalation path for rejected proposals?\n- Do you need dual-control for the final resolution step?`,
        action: null,
      };
    }
    if (lower.includes('improve') || lower.includes('suggest')) {
      return {
        text: `After analyzing the system state, I identified these high-impact improvements:\n\n1. **Real-time BCTS state visualization** — show live transitions as they happen\n   - Impact: High · Effort: Medium · Invariants: TransparencyAccountability\n\n2. **Delegation depth indicator** — visualize authority chain depth on governor cards\n   - Impact: Medium · Effort: Low · Invariants: DelegationGovernance\n\n3. **Consent expiry warnings** — proactive alerts before bailment consent expires\n   - Impact: High · Effort: Medium · Invariants: ConsentRequired\n\nShall I add these to the council backlog for review? I can also generate Archon workflow definitions for any of these.`,
        action: 'add-suggestions',
      };
    }
    if (lower.includes('invariant') || lower.includes('constitutional')) {
      return {
        text: `The ExoChain constitution defines **8 immutable invariants** enforced by the CGR kernel:\n\n${CONSTITUTIONAL_INVARIANTS.map((inv, i) => `${i+1}. **${inv.name}** — ${inv.desc}`).join('\n')}\n\nThese are checked at every BCTS state transition. A violation triggers mandatory escalation.\n\n**Which invariant would you like to explore further?**`,
        action: null,
      };
    }
    if (lower.includes('bcts') || lower.includes('state') || lower.includes('lifecycle')) {
      return {
        text: `The **BCTS (Blockchain Transaction State)** machine has 14 states:\n\n${BCTS_STATES.map((s, i) => `${i+1}. **${s}** ${TERMINAL_STATES.includes(s) ? '(terminal)' : ''}`).join('\n')}\n\nTransitions are governed by the constitutional invariants — each transition requires passing all applicable invariant checks.\n\n**Questions to consider:**\n- Are there states where you need additional approval gates?\n- Should escalated items have a separate resolution pathway?`,
        action: null,
      };
    }
    if (lower.includes('node') || lower.includes('explain')) {
      const nodeMatch = ALL_NODES.find(n => lower.includes(n.id) || lower.includes(n.name.toLowerCase()));
      if (nodeMatch) {
        return {
          text: `**${nodeMatch.name}** (\`${nodeMatch.id}\`)\n\n**Category:** ${Object.entries(NODE_REGISTRY).find(([_, nodes]) => nodes.some(n => n.id === nodeMatch.id))?.[0] || 'Unknown'}\n**Inputs:** ${nodeMatch.inputs.join(', ')}\n**Outputs:** ${nodeMatch.outputs.join(', ')}\n**Invariants:** ${nodeMatch.invariants.length ? nodeMatch.invariants.join(', ') : 'None (flow control)'}\n\nThis node enforces ${nodeMatch.invariants.length} constitutional invariant${nodeMatch.invariants.length !== 1 ? 's' : ''} at execution time.`,
          action: null,
        };
      }
      return {
        text: `There are **${ALL_NODES.length} Syntaxis node types** across ${Object.keys(NODE_REGISTRY).length} categories:\n\n${Object.entries(NODE_REGISTRY).map(([cat, nodes]) => `**${cat}:** ${nodes.map(n => n.name).join(', ')}`).join('\n')}\n\nWhich node would you like me to explain in detail?`,
        action: null,
      };
    }
    if (lower.includes('archon') || lower.includes('agent') || lower.includes('automat')) {
      return {
        text: `**Archon Integration** connects the council backlog to autonomous implementation:\n\n1. **PRD Assessment** — Council reviews requirement against constitution\n2. **Archon Execution** — DAG workflow: plan → implement → validate → PR\n3. **Governance Gate** — Kernel adjudicates output against invariants\n4. **Deployment** — Approved changes auto-deploy\n\nThe Archon pipeline uses \`.archon/workflows/\` YAML definitions and Claude Agent SDK for execution.\n\n**Would you like to:**\n- Create a custom Archon workflow?\n- Review pending pipeline items?\n- Configure governance gates for the pipeline?`,
        action: null,
      };
    }
    // Default with intelligent follow-up
    return {
      text: `I can help with:\n\n- **"design a workflow for X"** — I'll compose Syntaxis nodes\n- **"suggest improvements"** — I'll analyze and propose changes\n- **"explain [node name]"** — Deep dive into any node type\n- **"check invariants"** — Review constitutional compliance\n- **"BCTS lifecycle"** — Explore state machine transitions\n- **"archon pipeline"** — Configure autonomous implementation\n\nAll suggestions flow through the council backlog for governance-conditioned approval before reaching Archon.`,
      action: null,
    };
  }, []);

  const sendMessage = useCallback(() => {
    if (!input.trim()) return;
    const userMsg = input.trim();
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setInput('');
    setThinking(true);

    setTimeout(() => {
      const { text, action } = generateResponse(userMsg);
      setMessages(prev => [...prev, { role: 'ai', text }]);
      setThinking(false);

      // Dispatch to ExoForge self-improvement cycle
      dispatchFeedback('ai-chat', 'ai-backlog', action === 'add-suggestions' ? 'suggestion' : 'question', userMsg, { ai_response_action: action });

      if (action === 'add-suggestions') {
        setData(prev => ({
          ...prev,
          backlog: [
            { id: `BL-${String((prev.backlog?.length || 0) + 1).padStart(3, '0')}`, title: 'Real-time BCTS state visualization', priority: 'High', status: 'Proposed', source: 'AI Suggestion', votes: 0, impact: 'High', effort: 'Medium', invariants: ['TransparencyAccountability'] },
            { id: `BL-${String((prev.backlog?.length || 0) + 2).padStart(3, '0')}`, title: 'Delegation depth indicator', priority: 'Medium', status: 'Proposed', source: 'AI Suggestion', votes: 0, impact: 'Medium', effort: 'Low', invariants: ['DelegationGovernance'] },
            { id: `BL-${String((prev.backlog?.length || 0) + 3).padStart(3, '0')}`, title: 'Consent expiry warnings', priority: 'High', status: 'Proposed', source: 'AI Suggestion', votes: 0, impact: 'High', effort: 'Medium', invariants: ['ConsentRequired'] },
            ...(prev.backlog || []),
          ],
        }));
      }
    }, 600 + Math.random() * 400);
  }, [input, generateResponse, setData]);

  return (<>
    <div className="widget-header"><span className="widget-title">ExoChain AI Assistant</span><Badge type="green">Online</Badge></div>
    <div className="widget-body" style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
      <div ref={msgsRef} style={{ flex: 1, overflowY: 'auto', marginBottom: 12, maxHeight: 350 }}>
        {messages.map((m, i) => <div key={i} className={`feedback-msg ${m.role}`} style={{ whiteSpace: 'pre-wrap' }}>{m.text}</div>)}
        {thinking && <div className="feedback-msg ai" style={{ color: 'var(--accent-blue)' }}>Analyzing...</div>}
      </div>
      <div className="feedback-input">
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && sendMessage()} placeholder="Ask about workflows, nodes, invariants..." />
        <button className="btn btn-primary" onClick={sendMessage}>Send</button>
      </div>
    </div>
  </>);
}

function QuickActionsWidget({ setInput }) {
  const prompts = [
    'Design a workflow for consent-gated data access',
    'How can we improve the governance UI?',
    'Explain the BCTS state machine',
    'Suggest new Syntaxis node types',
    'Check constitutional invariants',
    'Configure Archon pipeline',
  ];
  return (<>
    <div className="widget-header"><span className="widget-title">Quick Actions</span></div>
    <div className="widget-body">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        {prompts.map(q => (
          <button key={q} className="btn btn-secondary" style={{ justifyContent: 'flex-start', textAlign: 'left', fontSize: 11, padding: '8px 12px' }} onClick={() => setInput && setInput(q)}>{q}</button>
        ))}
      </div>
    </div>
  </>);
}

function FeedbackPipelineWidget() {
  const stages = [
    { label: 'AI Chat', badge: 'green', desc: 'Issue elicited' },
    { label: 'Triage', badge: 'cyan', desc: 'Priority & impact' },
    { label: 'Council', badge: 'amber', desc: 'Review & vote' },
    { label: 'Backlog', badge: 'blue', desc: 'Accepted' },
    { label: 'Archon', badge: 'purple', desc: 'Autonomous impl' },
    { label: 'Deploy', badge: 'green', desc: 'Governance gate' },
  ];
  return (<>
    <div className="widget-header"><span className="widget-title">Feedback Pipeline</span></div>
    <div className="widget-body">
      <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
        {stages.map((s, i) => (<span key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ textAlign: 'center' }}>
            <Badge type={s.badge}>{s.label}</Badge>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>{s.desc}</div>
          </div>
          {i < stages.length - 1 && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>→</span>}
        </span>))}
      </div>
    </div>
  </>);
}

function CouncilBacklogWidget({ data }) {
  const { backlog: backlogData = [] } = data;
  const defaultBacklog = [
    { id: 'BL-001', title: 'Add real-time quorum visualization', priority: 'High', status: 'Proposed', source: 'AI Suggestion', votes: 3, impact: 'High', effort: 'Medium', invariants: ['TransparencyAccountability'] },
    { id: 'BL-002', title: 'Implement delegation chain drill-down', priority: 'Medium', status: 'Accepted', source: 'User Feedback', votes: 5, impact: 'Medium', effort: 'Medium', invariants: ['DelegationGovernance'] },
    { id: 'BL-003', title: 'Add PACE enrollment wizard', priority: 'High', status: 'In Progress', source: 'Council Review', votes: 7, impact: 'High', effort: 'High', invariants: ['DemocraticLegitimacy'] },
    { id: 'BL-004', title: 'Shamir key ceremony UI', priority: 'Low', status: 'Proposed', source: 'AI Suggestion', votes: 1, impact: 'Low', effort: 'High', invariants: [] },
    { id: 'BL-005', title: 'Consent bailment management dashboard', priority: 'Medium', status: 'Proposed', source: 'User Feedback', votes: 2, impact: 'Medium', effort: 'Medium', invariants: ['ConsentRequired'] },
  ];
  const items = backlogData.length > 0 ? backlogData : defaultBacklog;
  return (<>
    <div className="widget-header"><span className="widget-title">Council Backlog</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{items.length} items</span><AIHelpMenu widgetType="council-backlog" /></div></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Priority</th><th>Status</th><th>Source</th><th>Votes</th></tr></thead>
        <tbody>
          {items.map(item => (
            <tr key={item.id}>
              <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{item.id}</td>
              <td style={{ fontWeight: 500 }}>{item.title}</td>
              <td><Badge type={item.priority === 'High' ? 'red' : item.priority === 'Medium' ? 'amber' : 'blue'}>{item.priority}</Badge></td>
              <td><Badge type={item.status === 'In Progress' ? 'green' : item.status === 'Accepted' ? 'blue' : 'amber'}>{item.status}</Badge></td>
              <td><Badge type={item.source === 'AI Suggestion' ? 'purple' : item.source === 'Council Review' ? 'cyan' : 'blue'}>{item.source}</Badge></td>
              <td style={{ fontWeight: 600 }}>{item.votes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </>);
}

function ArchonPipelineWidget() {
  return (<>
    <div className="widget-header"><span className="widget-title">Archon Pipeline</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><Badge type="purple">Agent</Badge><AIHelpMenu widgetType="archon-pipeline" /></div></div>
    <div className="widget-body">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[
          { step: '1', label: 'PRD Assessment', desc: 'Council reviews PRD against constitution', icon: '1' },
          { step: '2', label: 'Archon Execution', desc: 'DAG: plan → implement → validate → PR', icon: '2' },
          { step: '3', label: 'Governance Gate', desc: 'Kernel adjudicates against invariants', icon: '3' },
        ].map(s => (
          <div key={s.step} style={{ padding: 12, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'rgba(139,92,246,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: 'var(--accent-purple)', flexShrink: 0 }}>{s.icon}</div>
              <div><div style={{ fontSize: 13, fontWeight: 600 }}>{s.label}</div><div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{s.desc}</div></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </>);
}

// ── Explorer Widgets ──────────────────────────────────────

function InvariantsGridWidget() {
  const [expanded, setExpanded] = useState(null);
  return (<>
    <div className="widget-header"><span className="widget-title">Constitutional Invariants</span><div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><Badge type="purple">8 Rules</Badge><AIHelpMenu widgetType="invariants-grid" /></div></div>
    <div className="widget-body">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        {CONSTITUTIONAL_INVARIANTS.map((inv, i) => (
          <div key={inv.name} style={{ padding: 12, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', cursor: 'pointer', transition: 'all 0.15s' }} onClick={() => setExpanded(expanded === i ? null : i)}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: `rgba(139,92,246,${0.1 + i * 0.02})`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, color: 'var(--accent-purple)', flexShrink: 0, fontSize: 13 }}>{i + 1}</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{inv.name}</div>
                {expanded === i && <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>{inv.desc}</div>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </>);
}

function CryptoPrimitivesWidget() {
  const prims = [
    { name: 'Blake3 Hashing', desc: 'Content-addressable hashing for governance objects' },
    { name: 'Ed25519 Signatures', desc: 'EdDSA digital signatures for identity auth' },
    { name: 'Shamir Secret Sharing', desc: 'Threshold splitting for PACE key recovery' },
    { name: 'Merkle Trees', desc: 'Hash trees for efficient dataset verification' },
    { name: 'CBOR Serialization', desc: 'Canonical deterministic serialization' },
    { name: 'HLC Timestamps', desc: 'Hybrid Logical Clocks for causal ordering' },
  ];
  return (<>
    <div className="widget-header"><span className="widget-title">Crypto Primitives</span><Badge type="cyan">WASM</Badge></div>
    <div className="widget-body">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {prims.map(c => (
          <div key={c.name} style={{ padding: 10, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 2 }}>{c.name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.desc}</div>
          </div>
        ))}
      </div>
    </div>
  </>);
}

function MCPRulesWidget({ data }) {
  const { systemInfo } = data;
  return (<>
    <div className="widget-header"><span className="widget-title">MCP Rules</span><Badge type="amber">AI Governance</Badge></div>
    <div className="widget-body" style={{ padding: '0 0 16px' }}>
      <table>
        <thead><tr><th>Rule</th><th>Description</th></tr></thead>
        <tbody>
          {(systemInfo?.mcp_rules || [
            { rule: 'ConsentGate', description: 'All data access requires active consent token' },
            { rule: 'HumanLoop', description: 'AI actions above threshold require human approval' },
            { rule: 'AuditTrail', description: 'All AI operations are recorded to immutable log' },
            { rule: 'ScopeLimit', description: 'AI actions bounded to declared scope in MCP context' },
            { rule: 'Explainability', description: 'AI decisions must produce human-readable rationale' },
            { rule: 'KillSwitch', description: 'Human override can halt any AI operation immediately' },
          ]).map((r, i) => (
            <tr key={i}><td><Badge type="amber">{r.rule}</Badge></td><td style={{ fontSize: 12 }}>{r.description}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  </>);
}

function BCTSLifecycleWidget() {
  return (<>
    <div className="widget-header"><span className="widget-title">BCTS 14-State Lifecycle</span></div>
    <div className="widget-body">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {BCTS_STATES.map((state, i) => (
          <div key={state} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 10, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <div style={{ width: 28, textAlign: 'center', fontWeight: 700, color: 'var(--text-muted)', fontSize: 12 }}>{i + 1}</div>
            <span style={{ fontWeight: 600, fontSize: 13, flex: 1 }}>{state}</span>
            <Badge type={TERMINAL_STATES.includes(state) ? (state === 'Denied' ? 'red' : 'green') : 'blue'}>
              {TERMINAL_STATES.includes(state) ? 'Terminal' : 'Active'}
            </Badge>
          </div>
        ))}
      </div>
    </div>
  </>);
}

// ══════════════════════════════════════════════════════════════
// PAGES — thin wrappers around WidgetGrid
// ══════════════════════════════════════════════════════════════

function WidgetPage({ pageId, title, desc, data, setData, setPage, editing, setEditing }) {
  const allLayouts = loadLayouts();
  const [layout, setLayout] = useState(() => allLayouts[pageId] || DEFAULT_LAYOUTS[pageId] || []);
  const [catalogOpen, setCatalogOpen] = useState(false);

  // Persist layout changes
  useEffect(() => {
    const all = loadLayouts();
    all[pageId] = layout;
    saveLayouts(all);
  }, [layout, pageId]);

  const addWidget = useCallback((catalogItem) => {
    const maxRow = layout.reduce((max, w) => Math.max(max, w.row + w.rowSpan), 1);
    setLayout(prev => [...prev, {
      id: `${catalogItem.type}-${Date.now()}`,
      type: catalogItem.type,
      col: 1,
      row: maxRow,
      colSpan: catalogItem.defaultSpan[0],
      rowSpan: catalogItem.defaultSpan[1],
    }]);
    setCatalogOpen(false);
  }, [layout]);

  const resetLayout = useCallback(() => {
    setLayout(DEFAULT_LAYOUTS[pageId] || []);
  }, [pageId]);

  const renderWidget = useCallback((w) => {
    switch (w.type) {
      // Dashboard
      case 'stats-row': return <StatsRowWidget data={data} setPage={setPage} />;
      case 'bcts-machine': return <BCTSMachineWidget />;
      case 'workflow-stages': return <WorkflowStagesWidget data={data} />;
      case 'governors-table': return <GovernorsTableWidget data={data} />;
      case 'decisions-table': return <DecisionsTableWidget data={data} setPage={setPage} />;
      // BoD
      case 'bod-stats': return <BoDStatsWidget data={data} />;
      case 'bod-create': return <BoDCreateWidget data={data} setData={setData} />;
      case 'bod-resolutions': return <BoDResolutionsWidget data={data} />;
      // Class Action
      case 'ca-stats': return <CAStatsWidget />;
      case 'ca-cases': return <CACasesWidget />;
      case 'ca-invariants': return <CAInvariantsWidget />;
      case 'ca-evidence': return <CAEvidenceWidget />;
      case 'ca-workflow': return <CAWorkflowWidget />;
      // Builder
      case 'builder-main': return <BuilderMainWidget />;
      // AI & Feedback
      case 'ai-chat': return <AIChatWidget data={data} setData={setData} />;
      case 'quick-actions': return <QuickActionsWidget />;
      case 'feedback-pipeline': return <FeedbackPipelineWidget />;
      case 'council-backlog': return <CouncilBacklogWidget data={data} />;
      case 'archon-pipeline': return <ArchonPipelineWidget />;
      // Explorer
      case 'invariants-grid': return <InvariantsGridWidget />;
      case 'crypto-primitives': return <CryptoPrimitivesWidget />;
      case 'mcp-rules': return <MCPRulesWidget data={data} />;
      case 'bcts-lifecycle': return <BCTSLifecycleWidget />;
      default: return <div className="widget-body" style={{ color: 'var(--text-muted)' }}>Unknown widget: {w.type}</div>;
    }
  }, [data, setData, setPage]);

  return (<>
    <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div>
        <div className="page-title">{title}</div>
        <div className="page-desc">{desc}</div>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {editing && <button className="btn btn-secondary btn-sm" onClick={() => setCatalogOpen(true)}>+ Add Widget</button>}
        {editing && <button className="btn btn-secondary btn-sm" onClick={resetLayout}>Reset Layout</button>}
        <button className={`btn ${editing ? 'btn-primary' : 'btn-secondary'} btn-sm`} onClick={() => setEditing(!editing)}>
          {editing ? 'Done' : 'Customize'}
        </button>
      </div>
    </div>
    <WidgetGrid layout={layout} setLayout={setLayout} renderWidget={renderWidget} editing={editing} pageId={pageId} />
    <WidgetCatalog open={catalogOpen} onClose={() => setCatalogOpen(false)} onAdd={addWidget} currentTypes={layout.map(w => w.type)} />
  </>);
}

// ══════════════════════════════════════════════════════════════
// MAIN APP
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage] = useState('dashboard');
  const [editing, setEditing] = useState(false);
  const [data, setData] = useState({
    systemInfo: null,
    users: [],
    decisions: [],
    scores: [],
    backlog: [],
  });

  useEffect(() => {
    Promise.all([
      api('/system'),
      api('/users'),
      api('/decisions'),
      api('/identity/scores'),
    ]).then(([sys, users, decisions, scores]) => {
      setData(prev => ({
        ...prev,
        systemInfo: sys && !sys.error ? sys : prev.systemInfo,
        users: Array.isArray(users) ? users : prev.users,
        decisions: Array.isArray(decisions) ? decisions : prev.decisions,
        scores: Array.isArray(scores) ? scores : prev.scores,
      }));
    });
  }, []);

  const PAGE_CONFIG = {
    dashboard: { title: 'ExoChain Governance Dashboard', desc: 'Real-time governance state powered by 28K LOC Rust engine compiled to WebAssembly' },
    bod: { title: 'Board of Directors', desc: 'Constitutional governance decisions with BCTS lifecycle, quorum validation, and fiduciary-grade audit' },
    classaction: { title: 'Class Action Manager', desc: 'Multi-party dispute resolution with constitutional adjudication, evidence chain, and governed remediation' },
    builder: { title: 'Syntaxis Visual Builder', desc: 'Compose governance workflows from 23 constitutional node types' },
    feedback: { title: 'AI Assistant & Council Backlog', desc: 'AI-powered feedback collection that populates the governance backlog for council-driven self-improvement via Archon' },
    explorer: { title: 'System Explorer', desc: 'Drill down into the ExoChain governance engine internals — constitutional invariants, MCP rules, BCTS states' },
  };

  const config = PAGE_CONFIG[page] || PAGE_CONFIG.dashboard;

  const nav = [
    { section: 'Platform' },
    { id: 'dashboard', icon: '◈', label: 'Dashboard' },
    { id: 'explorer', icon: '⚙', label: 'System Explorer' },
    { section: 'Use Cases' },
    { id: 'bod', icon: '🏛', label: 'Board of Directors' },
    { id: 'classaction', icon: '⚖', label: 'Class Action' },
    { section: 'Build' },
    { id: 'builder', icon: '⬡', label: 'Syntaxis Builder' },
    { id: 'feedback', icon: '💬', label: 'AI + Backlog' },
  ];

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="sidebar-logo">ExoChain</div>
        <div className="sidebar-sub">Governance Engine</div>
        {nav.map((item, i) =>
          item.section ? <div key={i} className="nav-section">{item.section}</div> :
          <div key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} onClick={() => { setPage(item.id); setEditing(false); }}>
            <span>{item.icon}</span> {item.label}
          </div>
        )}
        <div className="sidebar-footer">
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            <div>WASM: 637KB · 45 functions</div>
            <div>Rust: 28K LOC · 14 crates</div>
            <div style={{ marginTop: 4, color: data.systemInfo ? 'var(--accent-green)' : 'var(--accent-amber)' }}>
              {data.systemInfo ? '● API Connected' : '○ API Offline'}
            </div>
          </div>
        </div>
      </nav>
      <main className="main">
        <WidgetPage
          key={page}
          pageId={page}
          title={config.title}
          desc={config.desc}
          data={data}
          setData={setData}
          setPage={setPage}
          editing={editing}
          setEditing={setEditing}
        />
      </main>
    </div>
  );
}
