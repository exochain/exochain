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

# PANEL 5 — OPERATIONS REVIEW

**Discipline:** DevOps, Enterprise Adoption, UX Operations, Self-Development Systems, Syntaxis Workflow Architecture
**PRD Version:** decision.forum v1.1.0
**Review Date:** 2026-03-18
**Reviewer:** Operations Panel, EXOCHAIN Council

---

## ENTERPRISE REQUIREMENTS (ENT-001 through ENT-008)

### ENT-001 — Embedded TCO/ROI Calculator with Fiduciary-Reportable Metrics
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-legal::fiduciary` (DutyType, ComplianceResult, check_duty_compliance), `decision-forum::fiduciary_package` (FiduciaryDefensePackage::generate), `exo-governance::audit` (hash-chained audit trails)
**Syntaxis Workflow:**
```
identity_resolve -> consent_request -> authority_check -> transform[calculate_tco] ->
transform[calculate_roi] -> proof_generate[fiduciary_evidence] -> dag_append[report] ->
human_override[export_approval]
```
The user enters cost parameters at the `transform[calculate_tco]` node. The system computes ROI against governance costs tracked in `exo-legal::fiduciary`. The `proof_generate` node creates a verifiable fiduciary evidence package. The user sees each calculation step, can override assumptions, and receives a DAG-anchored receipt.
**Gaps:**
- No TCO model exists in the crate layer. `exo-legal::fiduciary` tracks duty compliance (Care, Loyalty, GoodFaith, Disclosure, Confidentiality) but not financial cost modeling.
- `FiduciaryDefensePackage::generate` produces a summary string but not structured financial metrics suitable for board reports.
- No integration point for external ERP data feeds.
**Optimized Requirement:**
> ENT-001-OPS: The platform SHALL provide a TCO/ROI calculation engine as a `transform` node type within Syntaxis, accepting cost parameters (license, integration, training, governance overhead) and producing fiduciary-reportable output anchored to `exo-dag` with `exo-proofs::snark` verification. Output SHALL be exportable as structured JSON conforming to XBRL or equivalent financial reporting schema. The calculation model SHALL be a Decision Object governed under GOV-013.
**Test Specification:**
- test_tco_calculation_deterministic: Given identical inputs, TCO transform produces identical outputs across runs, verified by proof_verify node.
- test_roi_fiduciary_evidence_dag_anchored: ROI output is appended to DAG with merkle proof; FiduciaryDefensePackage includes financial metrics.
- test_tco_export_xbrl_schema: Export conforms to financial reporting schema parseable by standard tools.

---

### ENT-002 — Segment-Specific Pricing Tiers
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-tenant::tenant` (TenantConfig with max_storage_bytes, max_users), `exo-authority::permission` (PermissionSet for feature gating)
**Syntaxis Workflow:**
```
identity_resolve -> tenant_isolate -> authority_check[tier_permissions] ->
guard[feature_gate] -> transform[apply_tier_config]
```
Tenant configuration drives which features are available. The `guard` node evaluates the tenant's tier against the requested capability. Users see their tier and what it unlocks at the `guard` node.
**Gaps:**
- `TenantConfig` only tracks `max_storage_bytes` and `max_users`. No pricing tier, feature flag set, or billing integration.
- No segment classification (startup, mid-market, enterprise, public sector) in the tenant model.
**Optimized Requirement:**
> ENT-002-OPS: Tenant configuration SHALL include a `tier` field (Startup|Growth|Enterprise|PublicSector) with associated PermissionSet defining feature access. Tier changes SHALL be governed as Decision Objects. Syntaxis workflows SHALL include `guard[tier_gate]` nodes that show users which features their tier enables and what upgrading unlocks.
**Test Specification:**
- test_tier_feature_gating: Startup tier cannot access Enterprise-only features; guard node returns deny with upgrade path.
- test_tier_change_decision_object: Tier upgrade creates a Decision Object with authority chain verification.
- test_tenant_isolation_across_tiers: Tier boundaries enforce data isolation via `tenant_isolate`.

---

### ENT-003 — 30-Day Pilot with Breakeven ROI Demonstration
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-tenant::tenant` (TenantRegistry::create with lifecycle), `exo-governance::audit` (pilot activity tracking), `decision-forum::decision_object` (DecisionObject for pilot evaluation)
**Syntaxis Workflow:**
```
tenant_isolate[create_pilot] -> sequence[
  consent_request[pilot_terms] ->
  transform[baseline_metrics] ->
  parallel[
    transform[track_governance_events],
    transform[track_time_savings],
    transform[track_risk_reduction]
  ] ->
  transform[compute_breakeven] ->
  proof_generate[roi_evidence] ->
  governance_propose[continue_or_exit] ->
  governance_vote ->
  governance_resolve
]
```
Users see real-time ROI accumulation during the pilot. At day 30, the `governance_propose` node presents the breakeven analysis and the organization votes on continuation.
**Gaps:**
- No pilot lifecycle management (auto-provisioning, time-bounded tenants, auto-teardown).
- No baseline metrics capture or comparison engine.
- TenantStatus has Active/Suspended/Archived but no Trial/Pilot state.
**Optimized Requirement:**
> ENT-003-OPS: The platform SHALL support a `Pilot` tenant status with configurable duration (default 30 days) and automatic transition to `governance_propose[continue_or_exit]` at expiry. Baseline governance metrics SHALL be captured at pilot start. ROI demonstration SHALL compare pilot metrics against baseline with DAG-anchored evidence. Pilot exit SHALL follow ENT-008 exit path.
**Test Specification:**
- test_pilot_auto_expiry: Pilot tenant transitions to governance review at 30-day mark.
- test_pilot_breakeven_calculation: ROI computation against baseline produces verifiable evidence.
- test_pilot_exit_data_export: Pilot termination exports all data per ENT-008.

---

### ENT-004 — Rapid Integration with Enterprise SSO and ERP
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-identity::did` (DID resolution), `exo-gateway::auth` (authentication middleware), `exo-api::schema` (API schema)
**Syntaxis Workflow:**
```
identity_resolve[sso_federation] -> consent_request[data_sharing_scope] ->
authority_delegate[map_sso_roles] -> invariant_check[authority_chain_valid] ->
tenant_isolate[erp_connector] -> mcp_enforce[api_boundaries]
```
The user's SSO identity maps to an EXOCHAIN DID at `identity_resolve`. Role mappings from AD/LDAP become authority delegations. ERP connectors operate within MCP-enforced boundaries.
**Gaps:**
- `exo-identity::did` provides DID primitives but no SAML/OIDC federation bridge.
- `exo-gateway::auth` exists but SSO adapter specifics are not in current source.
- No ERP connector framework (SAP, Oracle, Workday integration patterns).
**Optimized Requirement:**
> ENT-004-OPS: The platform SHALL provide SAML 2.0 and OIDC identity federation that maps enterprise directory roles to EXOCHAIN authority chains within 4 hours of configuration start. ERP integration SHALL operate through `mcp_enforce` boundaries with consent-gated data flows. Integration time SHALL be measurable and reportable as a pilot metric for ENT-003.
**Test Specification:**
- test_sso_to_did_mapping: OIDC token resolves to DID with authority chain in <2s.
- test_sso_role_to_authority_delegation: AD group membership produces valid authority delegation chain.
- test_erp_mcp_enforcement: ERP data flow blocked when consent is revoked.

---

### ENT-005 — SOC 2 Type II + ISO 27001 Certifications
**Operations Assessment:** Achievable (infrastructure-dependent)
**Exochain Coverage:** `exo-dag::dag` (append-only audit trail), `exo-governance::audit` (hash-chained audit), `exo-gatekeeper::tee` (TEE attestation), `exo-proofs::verifier` (proof verification), `exo-legal::evidence` (litigation-grade evidence), `exo-legal::records` (records management)
**Syntaxis Workflow:**
```
invariant_check[all_eight] -> proof_generate[compliance_evidence] ->
dag_append[audit_record] -> proof_verify[tamper_check] ->
transform[soc2_control_mapping] -> human_override[auditor_access]
```
The entire EXOCHAIN invariant enforcement engine produces the evidence trail that SOC 2 auditors need. Every kernel adjudication is a control execution. The `human_override` node gives auditors read access.
**Gaps:**
- No explicit SOC 2 control-to-invariant mapping documentation.
- TEE attestation (`exo-gatekeeper::tee`) has types defined (TeeAttestation, TeePlatform, TeePolicy) but deployment infrastructure is environment-dependent.
- ISO 27001 Annex A control mapping not codified.
- Certification is an organizational process, not a software feature alone.
**Optimized Requirement:**
> ENT-005-OPS: The platform SHALL maintain a machine-readable mapping from SOC 2 Type II controls and ISO 27001 Annex A controls to EXOCHAIN constitutional invariants and audit trail entries. Every kernel adjudication SHALL produce evidence sufficient to satisfy the mapped control. The mapping itself SHALL be a Decision Object under GOV-013. Infrastructure deployment SHALL include TEE attestation for key management operations.
**Test Specification:**
- test_soc2_control_mapping_complete: Every SOC 2 control maps to at least one invariant check with DAG evidence.
- test_audit_trail_immutability: Attempt to modify DAG audit entry fails; tamper detection fires.
- test_tee_attestation_key_ops: Key generation and signing operations produce TEE attestation records.

---

### ENT-006 — Adoption Tracking and Utilization Monitoring
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-governance::audit` (activity tracking), `exo-gateway::notifications` (NotificationService with delivery tracking), `exo-escalation::feedback` (feedback loops), `exo-tenant::tenant` (per-tenant metrics)
**Syntaxis Workflow:**
```
tenant_isolate -> parallel[
  transform[active_user_count],
  transform[decision_throughput],
  transform[governance_participation_rate],
  transform[notification_engagement]
] -> transform[adoption_score] -> guard[renewal_threshold] ->
choice[
  healthy: dag_append[adoption_report],
  at_risk: escalation_trigger[csm_alert] -> human_override[intervention]
]
```
Users see adoption dashboards generated from the same audit trail that proves governance. The `guard` node evaluates against M8 (>80% active users). At-risk tenants trigger CSM escalation.
**Gaps:**
- No adoption scoring model defined.
- `exo-governance::audit` provides hash-chained records but no analytics/aggregation layer.
- No CSM integration or account health alerting.
**Optimized Requirement:**
> ENT-006-OPS: The platform SHALL compute per-tenant adoption metrics (active users, decision throughput, participation rate, notification engagement) from DAG audit data. Adoption score SHALL be computed weekly and exposed via `exo-api`. Scores below configurable thresholds SHALL trigger `escalation_trigger` with CSM notification. Metrics SHALL be visible to tenant admins through Syntaxis dashboard workflows.
**Test Specification:**
- test_adoption_score_computation: Metrics correctly aggregate from audit trail entries.
- test_at_risk_escalation: Adoption score below threshold triggers escalation case.
- test_adoption_visible_to_tenant_admin: Tenant admin authority chain grants adoption metric read access.

---

### ENT-007 — Switching Cost Analysis and Retention Strategy
**Operations Assessment:** Aspirational
**Exochain Coverage:** `exo-dag::dag` (data export), `exo-legal::records` (records management), `exo-consent::policy` (consent-gated data)
**Syntaxis Workflow:**
```
identity_resolve -> authority_check[admin] -> transform[switching_cost_model] ->
parallel[
  transform[data_export_estimate],
  transform[retraining_cost],
  transform[governance_gap_risk]
] -> transform[retention_value_prop] -> dag_append[analysis]
```
**Gaps:**
- Switching cost analysis is fundamentally a sales/CS function, not a platform feature. The platform can provide data export tools and governance continuity metrics, but the cost model is customer-specific.
- No competitive comparison framework in crate layer.
**Optimized Requirement:**
> ENT-007-OPS: The platform SHALL provide governance continuity metrics showing accumulated governance evidence (decision count, proof count, authority chain depth) and estimated cost to rebuild equivalent governance posture. Data portability SHALL be a first-class feature per ENT-008. Switching cost analysis SHALL be available as a Syntaxis template workflow, not hardcoded.
**Test Specification:**
- test_governance_continuity_metrics: Platform computes accumulated governance evidence counts.
- test_data_portability_export: Full tenant data exportable in open format within SLA.
- test_switching_cost_template: Syntaxis template instantiable with custom parameters.

---

### ENT-008 — Failure Mode Mitigation and Pilot Exit Path
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-tenant::tenant` (TenantRegistry::delete, update_status), `exo-dag::dag` (data export), `exo-consent::policy` (consent revocation), `exo-legal::records` (records retention)
**Syntaxis Workflow:**
```
governance_propose[exit_decision] -> governance_vote -> governance_resolve ->
sequence[
  consent_revoke[all_active] ->
  transform[export_all_data] ->
  proof_generate[export_completeness] ->
  dag_append[exit_record] ->
  tenant_isolate[archive] ->
  human_override[confirm_deletion]
]
```
Users control the entire exit process through a governed workflow. Every step produces a receipt. The `human_override` at the end ensures a human confirms final deletion.
**Gaps:**
- No bulk data export API.
- `TenantRegistry::delete` is immediate; no staged archival-then-delete pipeline.
- No data retention policy enforcement post-exit.
**Optimized Requirement:**
> ENT-008-OPS: Pilot exit SHALL be a governed workflow producing verifiable evidence of data export completeness. Export SHALL include all Decision Objects, authority chains, proofs, and audit trails in an open format (JSON-LD or equivalent). Tenant deletion SHALL require `human_override` confirmation and SHALL be irreversible only after a configurable cooling-off period. Exit receipts SHALL be DAG-anchored and available to the departing tenant for 90 days post-exit.
**Test Specification:**
- test_exit_data_completeness: Export contains all Decision Objects, proofs, and audit entries.
- test_exit_cooling_period: Deletion blocked within cooling-off period; reactivation possible.
- test_exit_receipt_accessible: Exit receipt verifiable by departing tenant for 90 days.
- test_exit_consent_revocation: All active consents revoked as part of exit workflow.

---

## UX REQUIREMENTS (UX-001 through UX-010)

### UX-001 — Progressive Disclosure Based on User Role
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-authority::permission` (PermissionSet), `exo-authority::chain` (AuthorityChain with role-based links), `exo-gatekeeper::kernel` (AdjudicationContext.actor_roles with GovernmentBranch)
**Syntaxis Workflow:**
```
identity_resolve -> authority_check[role_permissions] ->
choice[
  observer: transform[minimal_view],
  contributor: transform[standard_view],
  governor: transform[full_view],
  steward: transform[admin_view]
] -> guard[never_hide_constitutional_warnings]
```
Syntaxis itself IS the progressive disclosure mechanism. Each role sees the workflow nodes relevant to their authority. The `guard` ensures constitutional warnings (UX-003) are never hidden regardless of role.
**Gaps:**
- Role-to-view-complexity mapping not defined in current crates. Authority crates model permissions, not UI complexity tiers.
- No UI rendering layer in the crate system (expected -- this is frontend).
**Optimized Requirement:**
> UX-001-OPS: Syntaxis workflow visualization SHALL render only the nodes for which the current user's PermissionSet grants access, with collapsed/expandable nodes for adjacent context. Constitutional constraint warnings (UX-003) SHALL be visible at all disclosure levels. Each Syntaxis node SHALL declare its minimum role requirement as metadata.
**Test Specification:**
- test_observer_sees_minimal_nodes: Observer PermissionSet renders only read-only status nodes.
- test_governor_sees_voting_nodes: Governor PermissionSet renders governance_vote, governance_propose.
- test_constitutional_warnings_all_roles: UX-003 warnings render for all four role tiers.

---

### UX-002 — Tamper-Evident Badges with Plain-English Explainers
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-proofs::verifier` (unified proof verifier), `exo-dag::mmr` (Merkle Mountain Range), `exo-dag::smt` (Sparse Merkle Tree), `exo-gatekeeper::invariants` (InvariantViolation with description and evidence)
**Syntaxis Workflow:**
```
proof_verify[check_dag_integrity] ->
choice[
  verified: transform[green_badge + explainer],
  tampered: escalation_trigger[integrity_alert] -> transform[red_badge + explainer]
]
```
The badge is the proof_verify result rendered visually. The explainer maps InvariantViolation.description to plain English. Users click the badge to see the full Syntaxis verification workflow.
**Gaps:**
- InvariantViolation descriptions are technical (e.g., "Authority chain is broken -- delegation gap"). Need a plain-English mapping layer.
- No badge rendering specification (this is expected as frontend concern).
**Optimized Requirement:**
> UX-002-OPS: Every Decision Object SHALL display a tamper-evidence badge driven by `proof_verify` against the DAG. Badge state SHALL be one of: Verified (green), Unverified (amber), Tampered (red). Each badge SHALL include a plain-English explainer generated from InvariantViolation.description through a localization/simplification transform. Clicking the badge SHALL open the Syntaxis verification workflow showing the proof chain.
**Test Specification:**
- test_verified_badge_green: Clean proof_verify produces Verified state.
- test_tampered_badge_red: Modified DAG entry produces Tampered state with explainer.
- test_explainer_plain_english: Technical invariant descriptions map to <8th-grade reading level text.

---

### UX-003 — Real-Time Constitutional Constraint Warnings
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-gatekeeper::kernel` (Kernel::adjudicate returns Verdict with violations), `exo-gatekeeper::invariants` (all 8 ConstitutionalInvariant types with InvariantViolation), `exo-gatekeeper::mcp` (McpViolation for AI actions)
**Syntaxis Workflow:**
```
[any_user_action] -> kernel_adjudicate ->
choice[
  permitted: [continue_workflow],
  denied: invariant_check[show_violations] -> transform[constraint_warning_card],
  escalated: escalation_trigger -> human_override
]
```
Every action passes through `kernel_adjudicate`. Violations produce real-time warnings with the specific invariant (SeparationOfPowers, ConsentRequired, NoSelfGrant, HumanOverride, KernelImmutability, AuthorityChainValid, QuorumLegitimate, ProvenanceVerifiable) and evidence. The user sees which constitutional principle they would violate BEFORE the action is blocked.
**Gaps:**
- Real-time means pre-action validation, which requires a "dry run" adjudication path. Current `Kernel::adjudicate` is synchronous and blocking -- suitable for pre-validation.
- Warning cards need UI rendering (frontend concern).
**Optimized Requirement:**
> UX-003-OPS: Every user action that requires kernel adjudication SHALL be pre-validated with a dry-run adjudication call. Constitutional violations SHALL be rendered as warning cards BEFORE the action is submitted, showing which of the 8 invariants would be violated with plain-English explanation. Warnings SHALL be non-dismissible for P0 invariants (SeparationOfPowers, ConsentRequired, KernelImmutability). Warnings SHALL include the Syntaxis node where the violation occurs.
**Test Specification:**
- test_prevalidation_latency: Dry-run adjudication completes in <100ms P95.
- test_all_eight_invariants_warned: Each invariant type produces a distinct warning card.
- test_p0_warnings_non_dismissible: SeparationOfPowers, ConsentRequired, KernelImmutability warnings cannot be dismissed without resolving the violation.

---

### UX-004 — AI Recommendation Cards with Human Review + zkML Confidence
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-proofs::zkml` (ModelCommitment, InferenceProof, prove_inference, verify_inference), `exo-gatekeeper::mcp` (McpRule enforcement including Mcp005Distinguishable), `decision-forum::decision_object` (HumanReviewStatus, AdvancedReasoningPolicy with BayesianAssessment)
**Syntaxis Workflow:**
```
mcp_enforce[ai_boundaries] -> transform[ai_recommendation] ->
proof_generate[zkml_inference_proof] -> transform[confidence_card] ->
human_override[accept_reject_modify] -> consent_verify[ai_output_consent] ->
dag_append[decision_with_ai_provenance]
```
The AI produces a recommendation within MCP boundaries. zkML proves the inference was computed by a committed model. The user sees the confidence (BayesianAssessment: prior, posterior, confidence_interval, sensitivity_instability, teacher_student_disagreement). The `human_override` node ensures a human reviews before the recommendation becomes a decision input.
**Gaps:**
- `exo-proofs::zkml` is a hash-based simulation, not a real ZK circuit over ML inference. The comment in the code says "In a real ZKML system, this would involve running the model in a ZK circuit." This is the most significant technical gap in the entire PRD.
- BayesianAssessment exists in decision-forum but is not integrated with zkml proof flow.
**Optimized Requirement:**
> UX-004-OPS: AI recommendations SHALL be displayed as cards showing: model identity (ModelCommitment hash), confidence metrics (from BayesianAssessment), zkML verification status, and MCP compliance status. Human review SHALL be mandatory (human_override node) for all decision classes above Routine. The zkML proof SHALL verify model-input-output binding; the CURRENT implementation uses hash-based binding which is sufficient for model provenance but SHALL be upgraded to circuit-based ZK proofs when computationally feasible. The card SHALL clearly state the proof strength level.
**Test Specification:**
- test_ai_card_shows_confidence: BayesianAssessment fields rendered in card.
- test_zkml_proof_verifiable: InferenceProof produced and verified for recommendation.
- test_human_review_mandatory_above_routine: Strategic/Constitutional decisions require human_override completion.
- test_mcp_005_distinguishable: AI output card is visually distinct from human output.

---

### UX-005 — Tiered Notification System with Fatigue Controls
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-gateway::notifications` (NotificationService with max_per_hour, NotificationPriority: Low/Medium/High/Critical, NotificationChannel: InApp/Email/Sms/Webhook/Slack, fatigue control with Critical bypass)
**Syntaxis Workflow:**
```
[governance_event] -> transform[classify_priority] ->
guard[fatigue_check] ->
choice[
  under_limit: parallel[deliver_channels],
  over_limit_non_critical: transform[batch_digest],
  critical_bypass: parallel[deliver_all_channels_immediately]
]
```
The fatigue control is already implemented: `NotificationService::send` blocks non-Critical notifications when `max_per_hour` is exceeded but always delivers Critical. Users configure their thresholds and channel preferences.
**Gaps:**
- No per-user channel preference configuration.
- No digest/batch notification mode -- fatigue control simply blocks.
- No notification preference governance (who can set Critical classification).
**Optimized Requirement:**
> UX-005-OPS: Notifications SHALL be classified into four priority tiers (Low, Medium, High, Critical) with per-user channel preferences and fatigue limits. Non-Critical notifications exceeding fatigue thresholds SHALL be batched into digest notifications rather than silently dropped. Critical notifications SHALL always bypass fatigue controls (ALREADY IMPLEMENTED). Notification classification rules SHALL be governed as tenant-level Decision Objects.
**Test Specification:**
- test_fatigue_blocks_low_priority: Already passing in `exo-gateway::notifications::tests::test_fatigue_control`.
- test_critical_bypasses_fatigue: Already passing.
- test_digest_batching: Blocked notifications aggregated into periodic digest.
- test_channel_preference_respected: User SMS-only preference prevents email delivery.

---

### UX-006 — Mobile-First Intake and Approval Workflows
**Operations Assessment:** Achievable (frontend-dependent)
**Exochain Coverage:** `exo-api::schema` (API schema), `exo-gateway::rest` + `exo-gateway::graphql` (API surface), `exo-governance::deliberation` (async deliberation)
**Syntaxis Workflow:**
```
identity_resolve[mobile_auth] -> consent_verify ->
choice[
  intake: governance_propose[mobile_form] -> dag_append,
  approve: governance_vote[swipe_approve_reject] -> dag_append,
  review: transform[decision_summary_card]
]
```
Syntaxis workflows render as mobile-optimized card sequences. Each node becomes a swipeable card. The core approval workflow (vote approve/reject) fits in a single mobile interaction.
**Gaps:**
- Entirely a frontend/rendering concern. API surface exists via exo-gateway. No mobile SDK or responsive rendering framework in crate layer.
- Offline/sync not addressed (async deliberation helps but is not offline-first).
**Optimized Requirement:**
> UX-006-OPS: Syntaxis workflows SHALL be renderable as sequential mobile cards with a maximum of 3 inputs per card. Approval workflows SHALL require a maximum of 2 taps to complete (identity verification + approve/reject). Mobile rendering SHALL be derived from the same Syntaxis workflow definition used for desktop, not maintained separately. API latency for mobile approval SHALL be <500ms P95.
**Test Specification:**
- test_approval_api_latency: Vote submission completes in <500ms P95.
- test_mobile_card_input_limit: No Syntaxis node renders more than 3 inputs on mobile viewport.
- test_same_workflow_definition: Mobile and desktop render from identical Syntaxis graph.

---

### UX-007 — Accessibility WCAG 2.2 AA + Neurodiversity
**Operations Assessment:** Achievable (frontend-dependent)
**Exochain Coverage:** `exo-gateway::rest` (semantic API responses), `exo-api::types` (structured data types)
**Syntaxis Workflow:**
```
identity_resolve -> transform[accessibility_preferences] ->
guard[wcag_compliance_check] -> [render_workflow_with_preferences]
```
Syntaxis node metadata includes ARIA labels, focus order, and alternative text descriptions. The workflow graph has a linear reading order for screen readers.
**Gaps:**
- Entirely frontend. No accessibility metadata in current crate types.
- Neurodiversity accommodations (reduced motion, focus mode, reading aids) require frontend implementation.
**Optimized Requirement:**
> UX-007-OPS: All Syntaxis nodes SHALL include accessibility metadata (ARIA label, role description, focus order hint) as part of their type definition. The API SHALL return this metadata with workflow responses. WCAG 2.2 AA compliance SHALL be validated by automated testing in CI. Neurodiversity accommodations (reduced motion, high contrast, focus mode, plain language) SHALL be user-configurable and persisted in user preferences.
**Test Specification:**
- test_syntaxis_nodes_have_aria_metadata: All 23 node types include ARIA label and role.
- test_wcag_automated_audit: CI pipeline runs axe-core against rendered workflows with 0 violations.
- test_screen_reader_linear_order: Workflow graph has deterministic linear reading order.

---

### UX-008 — Async-First Collaboration with Live Meeting Sync
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-governance::deliberation` (deliberation processes), `exo-core::hlc` (HybridLogicalClock for causal ordering), `decision-forum::decision_object` (sync_version, expected_sync_version for OT/CRDT)
**Syntaxis Workflow:**
```
governance_propose -> parallel[
  sequence[deliberation_async],
  sequence[deliberation_sync_meeting]
] -> transform[merge_deliberation] ->
governance_vote -> governance_resolve -> dag_append
```
The `parallel` node allows async and sync deliberation to proceed concurrently. HybridLogicalClock ensures causal ordering of contributions. The DecisionObject's `sync_version` / `expected_sync_version` enables conflict-free merging.
**Gaps:**
- No real-time sync protocol (WebSocket, SSE) in current gateway implementation.
- `exo-gateway::livesafe` exists but details not reviewed.
- Meeting integration (calendar sync, video embed) is external dependency.
**Optimized Requirement:**
> UX-008-OPS: Deliberation SHALL support both async (comment threads with HLC ordering) and sync (real-time session with participant presence) modes. Contributions from both modes SHALL merge into a single Decision Object timeline using HLC causal ordering. Meeting sync SHALL capture decisions made in meetings as governance_propose events with provenance.
**Test Specification:**
- test_hlc_causal_ordering: Async contributions from different timezones merge in causal order.
- test_sync_version_conflict_resolution: Concurrent edits resolve via sync_version check.
- test_meeting_capture_provenance: Meeting-originated proposals include meeting provenance metadata.

---

### UX-009 — Conflict Disclosure and Recusal Workflow
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-governance::conflict` (ConflictDeclaration, check_conflicts, must_recuse, ConflictSeverity: Advisory/Material/Disqualifying), `exo-legal::conflict_disclosure` (conflict disclosure records), `decision-forum::decision_object` (ConflictDisclosure, conflicts_disclosed)
**Syntaxis Workflow:**
```
identity_resolve -> governance_vote[begin] ->
guard[conflict_check] ->
choice[
  no_conflict: governance_vote[cast],
  advisory: transform[disclose_advisory] -> governance_vote[cast_with_disclosure],
  material: transform[disclose_material] -> human_override[recusal_decision],
  disqualifying: consent_revoke[recuse] -> transform[recusal_receipt] -> dag_append
]
```
Before any vote, `check_conflicts` runs against the voter's ConflictDeclarations and the decision's affected_dids. Disqualifying conflicts (financial, ownership) auto-recuse. Material conflicts (personal, family) require human review. Advisory conflicts are disclosed but allow participation. Every disclosure and recusal is DAG-anchored.
**Gaps:**
- No pre-populated conflict declaration registry. Users must self-declare.
- `must_recuse` uses string matching ("financial", "ownership", "personal", "family") which is fragile.
- No mechanism to detect undisclosed conflicts.
**Optimized Requirement:**
> UX-009-OPS: All governance participants SHALL maintain a ConflictDeclaration registry updated before each governance cycle. The `guard[conflict_check]` node SHALL run automatically before any governance_vote. Disqualifying conflicts SHALL auto-recuse with DAG-anchored receipt. Material conflicts SHALL require explicit human_override decision to proceed or recuse. Conflict severity classification SHALL use structured categories (not string matching) defined as a governed taxonomy.
**Test Specification:**
- test_disqualifying_auto_recuse: Financial conflict triggers automatic recusal. Already passing in `exo-governance::conflict::tests::financial_disqualifying`.
- test_material_requires_human_override: Personal relationship conflict requires explicit human decision.
- test_advisory_allows_participation: Acquaintance conflict allows vote with disclosure. Already passing.
- test_recusal_receipt_dag_anchored: Recusal produces DAG entry with proof.

---

### UX-010 — Decision Lifecycle Visibility and Status Tracking
**Operations Assessment:** Achievable
**Exochain Coverage:** `decision-forum::decision_object` (Status: Draft/Pending/Approved/Rejected/Contested/Void, DecisionClass: Routine/Operational/Strategic/Constitutional, audit_log with AuditEventType), `exo-escalation::kanban` (kanban board)
**Syntaxis Workflow:**
```
transform[decision_timeline] -> parallel[
  transform[status_badge: Draft|Pending|Approved|Rejected|Contested|Void],
  transform[audit_trail_view],
  transform[participant_activity],
  transform[deadline_tracker]
] -> guard[stale_decision_alert]
```
The Decision Object's status field and audit_log provide complete lifecycle tracking. The Syntaxis workflow renders this as a visual timeline with status transitions, participant activity, and upcoming deadlines. The `guard` alerts on decisions exceeding M9 (24h routine target).
**Gaps:**
- No deadline tracking or SLA management in current Decision Object.
- `exo-escalation::kanban` exists but integration with decision lifecycle not detailed.
**Optimized Requirement:**
> UX-010-OPS: Every Decision Object SHALL display a visual lifecycle timeline showing all status transitions with timestamps, actors, and reasons from the audit_log. The timeline SHALL include projected deadlines based on DecisionClass (Routine: 24h, Operational: 72h, Strategic: 7d, Constitutional: 30d). Decisions exceeding their class deadline SHALL trigger `escalation_trigger`. The kanban board SHALL provide cross-decision lifecycle visibility for governors.
**Test Specification:**
- test_lifecycle_timeline_complete: All AuditEventType transitions rendered in order.
- test_deadline_escalation: Routine decision exceeding 24h triggers escalation.
- test_kanban_cross_decision: Multiple decisions visible in kanban with correct statuses.

---

## SUCCESS METRICS (M1-M12)

### M1 — Authority Verification Coverage 100%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-gatekeeper::invariants::AuthorityChainValid` (enforced on every `Kernel::adjudicate` call), `exo-authority::chain` (AuthorityChain validation)
**Syntaxis Workflow:** `authority_check -> invariant_check[AuthorityChainValid]` on every action path.
**Gaps:** Coverage means every action is verified, not just governance actions. Need to ensure non-governance API calls also pass through authority verification.
**Optimized Requirement:** Every API call through `exo-gateway` SHALL pass through `authority_check` with coverage measured as (verified_requests / total_requests). Target: 100%.
**Test Specification:**
- test_no_unverified_api_path: Fuzzing of all API endpoints confirms authority_check on every path.
- test_authority_coverage_counter: Metrics endpoint reports verified/total ratio.

### M2 — Revocation Enforcement Latency P95 <60s
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-consent::gatekeeper` (ConsentGate), `exo-consent::policy` (PolicyEngine), `exo-authority::cache` (ChainCache -- must be invalidated on revocation)
**Syntaxis Workflow:** `consent_revoke -> [propagate_to_all_caches] -> invariant_check[verify_revocation]`
**Gaps:** `ChainCache` invalidation propagation latency not benchmarked. Multi-node deployments need cache coherence protocol.
**Optimized Requirement:** Consent revocation SHALL invalidate all cached authority chains within 60s P95 measured from revocation timestamp to enforcement across all nodes.
**Test Specification:**
- test_revocation_propagation_latency: Consent revoke reaches all cache nodes within 60s P95.
- test_revoked_consent_blocks_action: Action attempted after revocation but before cache expiry is blocked.

### M3 — Fiduciary Evidence Completeness >=99%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-legal::fiduciary` (check_duty_compliance), `exo-legal::evidence` (evidence collection), `decision-forum::fiduciary_package` (FiduciaryDefensePackage)
**Syntaxis Workflow:** `proof_generate[fiduciary_evidence] -> proof_verify[completeness_check]`
**Gaps:** Completeness definition needed. What constitutes a complete fiduciary evidence package?
**Optimized Requirement:** Every sealed Decision Object SHALL have a FiduciaryDefensePackage containing: authority chain, all votes with provenance, conflict disclosures, deliberation record, and Merkle proof. Completeness = (packages_with_all_fields / total_sealed_decisions). Target: >=99%.
**Test Specification:**
- test_fiduciary_package_completeness: Sealed Decision Object produces package with all required fields.
- test_incomplete_package_blocks_seal: Decision cannot seal without complete fiduciary evidence.

### M4 — AI Provenance Compliance 100%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-gatekeeper::mcp` (all 6 McpRules enforced), `exo-proofs::zkml` (InferenceProof), `exo-gatekeeper::invariants::ProvenanceVerifiable`
**Syntaxis Workflow:** `mcp_enforce[all_rules] -> proof_generate[provenance]`
**Gaps:** None significant. MCP enforcement is architecturally complete with 6 rules.
**Optimized Requirement:** Every AI action SHALL pass MCP enforcement producing a provenance record. Compliance = (ai_actions_with_full_provenance / total_ai_actions). Target: 100%.
**Test Specification:**
- test_ai_action_without_provenance_blocked: MCP003 blocks unprovenienced AI actions. Already passing.
- test_ai_provenance_compliance_counter: Metrics track compliance ratio.

### M5 — Quorum/Recusal Integrity Incidents 0/quarter
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-governance::quorum` (compute_quorum with independence-aware counting), `exo-governance::conflict` (check_conflicts, must_recuse)
**Syntaxis Workflow:** `governance_vote -> guard[quorum_check] -> guard[conflict_check] -> governance_resolve`
**Gaps:** Integrity incident detection requires monitoring, not just enforcement. Need anomaly detection for quorum manipulation.
**Optimized Requirement:** Every governance_resolve SHALL verify quorum via `compute_quorum` with independence attestation. Recusal compliance SHALL be verified by `check_conflicts` before every vote. Integrity incidents defined as: quorum resolved without meeting policy, or vote cast with undisclosed Disqualifying conflict.
**Test Specification:**
- test_quorum_without_independence_fails: Already passing in exo-governance tests.
- test_undisclosed_conflict_detection: Post-hoc audit detects conflict that should have triggered recusal.

### M6 — Tamper-Evident Verification Success 100%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-dag::mmr` (Merkle Mountain Range), `exo-dag::smt` (Sparse Merkle Tree), `exo-proofs::verifier` (proof verification), `exo-gatekeeper::kernel::verify_kernel_integrity`
**Syntaxis Workflow:** `proof_verify[dag_integrity] -> proof_verify[kernel_integrity]`
**Gaps:** "Success" means every verification attempt returns a correct result. Need to ensure verification is computationally feasible at scale.
**Optimized Requirement:** Every DAG entry SHALL be verifiable via Merkle proof. Verification SHALL complete in <100ms P95. Verification correctness = (correct_verify_results / total_verify_calls). Target: 100%.
**Test Specification:**
- test_merkle_proof_round_trip: Append to DAG, generate proof, verify proof succeeds.
- test_tampered_entry_detected: Modified DAG entry fails verification.
- test_kernel_integrity_verified: `verify_kernel_integrity` confirms constitution hash. Already passing.

### M7 — Emergency Governance Discipline >=98%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-governance::emergency` (EmergencyAction with ratification lifecycle, EmergencyFrequencyTracker)
**Syntaxis Workflow:** `escalation_trigger[emergency] -> human_override[invoke_emergency] -> governance_propose[ratification] -> governance_vote[ratify_within_deadline] -> governance_resolve`
**Gaps:** Discipline = emergency actions ratified within deadline. `EmergencyFrequencyTracker` tracks frequency but not ratification compliance rate.
**Optimized Requirement:** Emergency actions SHALL auto-create ratification Decision Objects (ALREADY IMPLEMENTED via `ratification_decision_id`). Discipline = (emergency_actions_ratified_before_deadline / total_emergency_actions). Target: >=98%. Emergency frequency exceeding 3/quarter SHALL trigger governance review (ALREADY IMPLEMENTED via threshold).
**Test Specification:**
- test_emergency_ratification_lifecycle: Create, ratify within deadline. Already passing.
- test_emergency_expiry: Unratified emergency expires correctly. Already passing.
- test_frequency_threshold_review: >3 per quarter triggers review. Already passing.

### M8 — Active User Adoption >80% at Renewal
**Operations Assessment:** Achievable (requires analytics layer)
**Exochain Coverage:** `exo-governance::audit` (activity tracking), `exo-tenant::tenant` (per-tenant user counts)
**Gaps:** No active user definition or measurement in current crates. Need to define "active" (logged in? voted? participated in deliberation?).
**Optimized Requirement:** Active user = user who performed at least one governance action (vote, propose, review, comment) in the 30 days preceding renewal date. Measured per-tenant via audit trail aggregation.
**Test Specification:**
- test_active_user_definition: User with governance action in 30d classified as active.
- test_adoption_metric_computation: Correct ratio computed from audit trail.

### M9 — Time-to-Decision (routine) <=24h
**Operations Assessment:** Achievable
**Exochain Coverage:** `decision-forum::decision_object` (created_at, status transitions in audit_log), `exo-escalation::kanban` (tracking)
**Gaps:** No SLA enforcement or deadline tracking in Decision Object.
**Optimized Requirement:** Routine decisions SHALL include a 24h deadline computed from created_at. Decisions exceeding deadline SHALL trigger escalation_trigger. Time-to-decision = (resolved_at - created_at) measured from audit_log.
**Test Specification:**
- test_routine_deadline_computation: 24h deadline correctly computed.
- test_deadline_escalation_trigger: Exceeded deadline fires escalation.

### M10 — Proof Verification Uptime 99.9%
**Operations Assessment:** Achievable (infrastructure-dependent)
**Exochain Coverage:** `exo-proofs::verifier`, `exo-dag::proof`
**Gaps:** Uptime is an infrastructure metric, not a code metric. Requires deployment architecture (load balancing, failover, health checks).
**Optimized Requirement:** The proof verification service SHALL be deployed with N+1 redundancy and health check endpoints. Uptime = (successful_health_checks / total_health_checks) measured every 30s.
**Test Specification:**
- test_verification_health_check: Health endpoint returns 200 with verification capability.
- test_verification_under_load: 1000 concurrent verifications complete without failure.

### M11 — TLA+ Invariant Verification Coverage 100%
**Operations Assessment:** Aspirational
**Exochain Coverage:** `exo-gatekeeper::invariants` (8 constitutional invariants), `exo-core::invariants`
**Gaps:** No TLA+ specifications exist in the codebase. The 8 invariants are implemented in Rust but not formally specified in TLA+. Writing and model-checking TLA+ specs is significant engineering effort.
**Optimized Requirement:** Each of the 8 constitutional invariants SHALL have a corresponding TLA+ specification. The Rust implementation SHALL be proven consistent with the TLA+ spec via property-based testing. Coverage = (invariants_with_tla_spec / total_invariants). Target: 100%.
**Test Specification:**
- test_tla_spec_exists_per_invariant: Each invariant has a .tla file.
- test_rust_tla_consistency: Property-based tests demonstrate Rust behavior matches TLA+ state transitions.

### M12 — Self-Modification Compliance 100%
**Operations Assessment:** Achievable
**Exochain Coverage:** `exo-gatekeeper::invariants::KernelImmutability` (blocks kernel modification), `decision-forum::decision_object` (platform changes as Decision Objects)
**Syntaxis Workflow:** `governance_propose[platform_change] -> invariant_check[kernel_immutability] -> governance_vote -> governance_resolve -> dag_append`
**Gaps:** Need to define scope of "self-modification". Kernel is immutable. But platform evolution (new features, configuration changes) must be governed.
**Optimized Requirement:** Every platform configuration change, feature flag toggle, and crate version upgrade SHALL be submitted as a Decision Object. Compliance = (governed_changes / total_changes). Target: 100%. Kernel modifications SHALL remain impossible (ALREADY ENFORCED).
**Test Specification:**
- test_kernel_modification_blocked: Already passing in exo-gatekeeper tests.
- test_config_change_requires_decision_object: Configuration change without Decision Object is rejected.

---

## GOV-013 — Recursive Self-Governance

### GOV-013 — All Platform Evolution Governed as Decision Objects
**Operations Assessment:** Achievable
**Exochain Coverage:** `decision-forum::decision_object` (DecisionObject with full lifecycle), `exo-gatekeeper::invariants::KernelImmutability` (kernel immutability), `exo-governance::*` (complete governance primitives), `exo-dag::dag` (append-only evidence)
**Syntaxis Workflow:**
```
governance_propose[platform_change] ->
invariant_check[all_eight] ->
parallel[
  sequence[deliberation],
  sequence[conflict_check -> recusal_workflow]
] ->
governance_vote[quorum_with_independence] ->
governance_resolve ->
proof_generate[change_evidence] ->
dag_append[immutable_record] ->
transform[governance_simulator_update]
```
The platform governs its own evolution using the same governance mechanisms it provides to users. The Governance Simulator is a read-only Syntaxis workflow viewer that lets stakeholders model "what if we changed this rule" without affecting the live system.
**Gaps:**
- Governance Simulator not implemented. Needs a sandboxed Syntaxis execution environment.
- Self-modification compliance tracking not instrumented.
- No mechanism to detect ungoverned changes (e.g., direct database modifications bypassing the governance layer).
**Optimized Requirement:**
> GOV-013-OPS: ALL platform changes (code deploys, configuration updates, schema migrations, feature flags, governance rule changes) SHALL be submitted as Decision Objects and resolved through the standard governance workflow. The Governance Simulator SHALL be a sandboxed Syntaxis execution environment where proposed rule changes can be tested against historical Decision Objects before live deployment. Ungoverned changes SHALL be detectable via DAG integrity checks comparing deployed state against governed change records.
**Test Specification:**
- test_code_deploy_requires_decision_object: CI/CD pipeline rejects deploy without approved Decision Object.
- test_governance_simulator_sandboxed: Simulator changes do not affect live Decision Objects.
- test_ungoverned_change_detection: Manual database modification detected by DAG integrity audit.
- test_self_modification_compliance_metric: Compliance counter tracks governed/total changes.

---

## OPERATIONS PANEL VERDICT

### Production-Ready (Ship Today)

These requirements have direct crate support with passing tests:

1. **UX-003** (Constitutional Constraint Warnings): `Kernel::adjudicate` with all 8 invariants is fully implemented and tested. 37+ tests in `exo-gatekeeper::invariants` and `exo-gatekeeper::kernel`.
2. **UX-005** (Tiered Notifications with Fatigue): `NotificationService` with 4-tier priority, 5 channels, and fatigue control with Critical bypass is implemented and tested.
3. **UX-009** (Conflict Disclosure and Recusal): `check_conflicts` and `must_recuse` with Advisory/Material/Disqualifying severity is implemented and tested.
4. **M1** (Authority Verification): `AuthorityChainValid` invariant enforced on every adjudication.
5. **M4** (AI Provenance): All 6 MCP rules implemented and tested. Full enforcement pipeline.
6. **M5** (Quorum/Recusal Integrity): Independence-aware quorum with "theater, not legitimacy" enforcement.
7. **M6** (Tamper-Evidence): Kernel integrity verification, Merkle structures in exo-dag.
8. **M7** (Emergency Discipline): EmergencyAction with ratification lifecycle and frequency tracking.
9. **M12** (Self-Modification Compliance): KernelImmutability invariant blocks kernel modification.

### Needs Infrastructure (Ship in 30-60 Days)

These require integration work, deployment infrastructure, or frontend development:

1. **ENT-003** (30-Day Pilot): Needs Pilot tenant status, baseline metrics capture, auto-expiry workflow.
2. **ENT-004** (SSO/ERP Integration): Needs SAML/OIDC federation bridge and ERP connector framework.
3. **ENT-005** (SOC 2 / ISO 27001): Needs control-to-invariant mapping documentation and TEE deployment.
4. **ENT-006** (Adoption Tracking): Needs analytics aggregation layer over audit trail.
5. **ENT-008** (Pilot Exit Path): Needs bulk data export API and staged archival pipeline.
6. **UX-001** (Progressive Disclosure): Needs role-to-view-complexity mapping in Syntaxis node metadata.
7. **UX-002** (Tamper-Evident Badges): Needs plain-English explainer mapping for InvariantViolation descriptions.
8. **UX-006** (Mobile Workflows): Needs mobile rendering of Syntaxis workflows (frontend).
9. **UX-007** (Accessibility): Needs ARIA metadata in Syntaxis node types and automated WCAG testing.
10. **UX-008** (Async Collaboration): Needs real-time sync protocol (WebSocket/SSE) in gateway.
11. **UX-010** (Decision Lifecycle): Needs deadline tracking and kanban integration.
12. **M2** (Revocation Latency): Needs cache coherence protocol for multi-node deployments.
13. **M8** (Active User Adoption): Needs active user definition and audit trail aggregation.
14. **M9** (Time-to-Decision): Needs SLA enforcement and deadline tracking in Decision Objects.
15. **M10** (Proof Verification Uptime): Needs N+1 deployment architecture with health checks.

### Aspirational (60-90+ Days)

These require significant new engineering or are partially outside platform scope:

1. **ENT-001** (TCO/ROI Calculator): Needs financial modeling engine not present in any crate. Can be built as Syntaxis transform, but the model itself requires domain expertise.
2. **ENT-002** (Segment-Specific Pricing): Needs tier model, billing integration. Partially outside platform scope.
3. **ENT-007** (Switching Cost Analysis): Primarily a sales/CS function. Platform provides data portability, not competitive analysis.
4. **UX-004** (zkML Confidence): The zkML implementation is hash-based simulation, not circuit-based ZK proofs. Upgrading to real zkML is a multi-quarter research effort. Hash-based provenance is sufficient for V1 but must be clearly communicated.
5. **M3** (Fiduciary Evidence Completeness >=99%): Achievable but requires defining completeness criteria and instrumenting every seal path.
6. **M11** (TLA+ Coverage 100%): No TLA+ specs exist. Writing formal specifications for 8 invariants is significant effort.
7. **GOV-013** (Governance Simulator): Sandboxed Syntaxis execution environment is new infrastructure.

---

## COMPLETE SYNTAXIS WORKFLOW MAP: DECISION.FORUM LIFECYCLE

The following maps the entire decision.forum lifecycle through the 23 Syntaxis node types, showing how users interact with the system at each stage.

```
PHASE 1: IDENTITY AND ACCESS
=============================
identity_resolve ──> consent_request ──> consent_verify ──> authority_check
     |                    |                    |                    |
     |  User provides     | System requests    | User confirms      | System verifies
     |  DID or SSO        | data sharing       | consent terms      | authority chain
     |  credentials       | scope              |                    | from root to user

PHASE 2: DECISION INTAKE
=========================
authority_check ──> tenant_isolate ──> governance_propose ──> dag_append
     |                    |                    |                    |
     |  Verified user     | Actions scoped     | User submits       | Proposal anchored
     |  enters their      | to their tenant    | proposal with      | to immutable DAG
     |  tenant context    | boundary           | evidence           | with merkle proof

PHASE 3: CONSTITUTIONAL VALIDATION
====================================
kernel_adjudicate ──> invariant_check ──> mcp_enforce
     |                      |                    |
     |  Every action        | All 8 invariants   | AI actions checked
     |  passes through      | verified:          | against 6 MCP rules:
     |  immutable kernel    | SeparationOfPowers | BCTS scope, no self-
     |                      | ConsentRequired    | escalation, provenance
     |                      | NoSelfGrant        | no identity forge,
     |                      | HumanOverride      | distinguishable,
     |                      | KernelImmutability | consent boundaries
     |                      | AuthorityChainValid|
     |                      | QuorumLegitimate   |
     |                      | ProvenanceVerifiable|

PHASE 4: DELIBERATION
======================
governance_propose ──> parallel[async, sync] ──> sequence[deliberation_rounds]
     |                         |                          |
     |  Proposal visible       | Async comments and       | Structured deliberation
     |  to all authorized      | sync meeting notes       | with HLC ordering
     |  participants           | merge via HLC            |

PHASE 5: CONFLICT AND RECUSAL
==============================
guard[conflict_check] ──> choice[severity] ──> consent_revoke[recuse]
     |                         |                       |
     |  Before any vote,       | Advisory: disclose     | Disqualifying: auto-
     |  check_conflicts        | Material: human review | recuse with DAG receipt
     |  runs automatically     | Disqualifying: recuse  |

PHASE 6: VOTING AND QUORUM
============================
governance_vote ──> guard[quorum_policy] ──> governance_resolve
     |                    |                       |
     |  Participants cast | Independence-aware     | Decision resolved when
     |  votes with        | quorum computed.       | quorum met or deadline
     |  provenance        | "Theater, not          | exceeded. Status becomes
     |  signatures        | legitimacy" check      | Approved/Rejected/Contested

PHASE 7: AI ADVISORY (when applicable)
========================================
mcp_enforce ──> transform[ai_recommendation] ──> proof_generate[zkml]
     |                    |                            |
     |  AI operates       | AI produces recommendation | zkML proof binds
     |  within MCP        | with BayesianAssessment    | model+input+output
     |  boundaries        | (prior, posterior, CI)     |
                                    |
                          human_override[accept/reject/modify]
                                    |
                          User ALWAYS reviews AI output before
                          it becomes a decision input

PHASE 8: SEALING AND EVIDENCE
==============================
governance_resolve ──> proof_generate[fiduciary] ──> dag_append[sealed]
     |                         |                          |
     |  Decision sealed        | FiduciaryDefensePackage  | Sealed decision with
     |  after TnC enforcement  | generated with full      | merkle root anchored
     |  and threshold checks   | authority chain, votes,  | permanently in DAG
     |                         | conflicts, evidence      |

PHASE 9: EMERGENCY PATH
=========================
escalation_trigger[emergency] ──> human_override[invoke] ──> governance_propose[ratification]
     |                                  |                            |
     |  Emergency condition             | Human invokes emergency    | Auto-created ratification
     |  detected (detection signal      | authority with             | Decision Object with
     |  confidence > threshold)         | justification              | deadline enforcement

PHASE 10: SELF-GOVERNANCE (GOV-013)
=====================================
governance_propose[platform_change] ──> invariant_check[all_eight] ──> governance_vote
     |                                         |                            |
     |  Platform changes submitted             | Constitutional validation   | Governed like any
     |  as Decision Objects                    | of the change itself       | other decision
                    |
          governance_resolve ──> dag_append ──> transform[deploy]
                    |                  |               |
                    | Change approved  | Evidence       | Deployment only after
                    | through normal   | permanently    | governance resolution
                    | governance       | recorded       |

NOTIFICATION OVERLAY (runs in parallel throughout):
====================================================
[any_governance_event] ──> transform[classify_priority] ──> guard[fatigue_check]
     |                            |                               |
     |  Every state change        | Low/Medium/High/Critical      | Fatigue control blocks
     |  generates notification    | classification                | non-Critical when limit
     |  event                     |                               | exceeded; Critical always
     |                            |                               | delivered
```

### Node Type Usage Summary

| Node Type | Usage in Lifecycle | Phase |
|-----------|-------------------|-------|
| identity_resolve | DID/SSO authentication | 1 |
| consent_request | Data sharing scope request | 1 |
| consent_verify | Confirm active consent | 1 |
| consent_revoke | Recusal, exit, revocation | 5, 8 |
| authority_check | Role and permission verification | 1, 2 |
| authority_delegate | SSO role mapping, delegation | 1 |
| kernel_adjudicate | Constitutional validation of every action | 3 |
| invariant_check | 8 constitutional invariants | 3, 10 |
| sequence | Ordered workflow steps | 4, 8 |
| parallel | Async+sync deliberation, multi-channel notify | 4, 11 |
| choice | Conflict severity routing, approval routing | 5, 6 |
| guard | Quorum policy, fatigue control, feature gates | 5, 6, 11 |
| transform | Data transformation, metrics, UI rendering | 2, 6, 7, 8, 11 |
| governance_propose | Submit proposals and platform changes | 2, 9, 10 |
| governance_vote | Cast votes with provenance | 6 |
| governance_resolve | Resolve decisions against quorum | 6, 10 |
| escalation_trigger | Emergency, deadline, integrity alerts | 9 |
| human_override | Emergency invoke, AI review, recusal decision | 5, 7, 9 |
| dag_append | Anchor evidence to immutable DAG | 2, 5, 6, 8, 10 |
| proof_generate | zkML, fiduciary evidence, compliance proofs | 7, 8 |
| proof_verify | Tamper-evidence badges, integrity checks | 8 |
| tenant_isolate | Tenant boundary enforcement | 2 |
| mcp_enforce | AI action boundary enforcement | 3, 7 |

All 23 node types are utilized. No orphan types.

---

## CRITICAL OPERATIONAL RISKS

1. **zkML Gap (UX-004)**: The most significant technical gap. Hash-based simulation is not zero-knowledge. V1 must clearly label proof strength as "model provenance binding" not "zero-knowledge inference proof." Misrepresenting this to enterprises is a trust-destroying error.

2. **TLA+ Gap (M11)**: Claiming 100% TLA+ coverage without any TLA+ specifications is operationally dishonest. Recommend reframing as "formal verification roadmap" with property-based testing as the interim.

3. **Cache Coherence (M2)**: Revocation latency depends entirely on deployment architecture. Single-node is trivial. Multi-node requires a cache invalidation protocol that does not exist in the crate layer.

4. **Governance Simulator (GOV-013)**: Sandboxed execution is a hard problem. Recommend V1 ships with a "preview mode" that shows invariant check results for proposed rule changes without full simulation.

5. **Frontend Dependencies**: UX-001, UX-002, UX-006, UX-007 are all frontend-dependent. The crate layer provides the data but the operations assessment assumes a competent frontend team delivers within the same timeline.

---

*Panel 5 review complete. The exochain crate architecture provides strong constitutional enforcement primitives. The primary operational gaps are in the application layer (analytics, financial modeling, frontend rendering) and infrastructure layer (multi-node cache coherence, TEE deployment, real-time sync). The governance primitives themselves are production-ready.*
