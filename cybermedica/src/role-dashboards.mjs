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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'dashboard_view';
const DASHBOARD_SCHEMA = 'cybermedica.role_dashboard.v1';

const REQUIRED_WIDGETS = Object.freeze({
  auditor: [
    'evidence_traceability',
    'document_version_history',
    'access_logs',
    'chain_of_custody',
    'decision_rationale',
    'issue_history',
    'corrective_actions',
    'staff_training_records',
    'role_delegation_records',
    'inspection_audit_packet',
  ],
  coordinator: [
    'assigned_tasks',
    'training_requirements',
    'protocol_procedures',
    'active_consent_version',
    'deviation_reporting_shortcut',
    'participant_visit_requirements',
    'document_access',
    'upcoming_due_dates',
    'concern_reporting',
  ],
  cro_portfolio_manager: [
    'sites_by_readiness_status',
    'studies_by_startup_status',
    'site_gaps',
    'critical_findings',
    'capa_aging',
    'training_coverage',
    'risk_heatmap',
    'sponsor_exports',
    'monitoring_findings',
    'cross_site_trends',
  ],
  decision_forum: [
    'pending_matters',
    'required_quorum',
    'conflict_disclosures',
    'evidence_bundles',
    'ai_review_summaries',
    'votes',
    'conditions',
    'dissent',
    'decisions',
    'follow_up_actions',
  ],
  principal_investigator: [
    'protocol_readiness',
    'delegation_log',
    'training_completion',
    'consent_form_status',
    'active_deviations',
    'safety_events',
    'participant_protection_tasks',
    'launch_enrollment_gate_status',
    'required_approvals',
    'study_action_items',
  ],
  quality_manager: [
    'control_status',
    'evidence_completeness',
    'evidence_freshness',
    'findings_by_severity',
    'capa_aging',
    'deviation_trends',
    'audit_schedule',
    'risk_register',
    'document_review_queue',
    'training_gap_trends',
  ],
  site_leader: [
    'site_qms_passport_status',
    'critical_gaps',
    'open_risks',
    'open_capas',
    'training_gaps',
    'upcoming_reviews',
    'audit_status',
    'protocol_startup_status',
    'decision_forum_matters',
    'sponsor_cro_requests',
  ],
  sponsor_viewer: [
    'authorized_site_readiness_view',
    'evidence_summary',
    'open_critical_major_gaps',
    'capa_status',
    'training_summary',
    'facility_equipment_status',
    'consent_readiness',
    'deviation_trends',
    'audit_assessment_reports',
    'decision_certificates',
  ],
});

const DASHBOARD_ROLES = new Set(Object.keys(REQUIRED_WIDGETS));
const SOURCE_FAMILIES = new Set([
  'access_logs',
  'audits',
  'capas',
  'chain_of_custody',
  'controls',
  'decisions',
  'delegation',
  'deviations',
  'documents',
  'equipment',
  'evidence',
  'facilities',
  'findings',
  'inspection_packets',
  'notifications',
  'participants',
  'products',
  'protocols',
  'risks',
  'safety_events',
  'sites',
  'training',
]);
const RAW_DASHBOARD_FIELDS = new Set([
  'dashboardbody',
  'dashboardcopy',
  'dashboardtext',
  'freeformdashboard',
  'rawdashboard',
  'rawdashboardtext',
  'rawmetricdata',
  'rawpayload',
  'rawwidget',
  'rawwidgettext',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'widgetbody',
  'widgetcopy',
  'widgettext',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawDashboardContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDashboardContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_DASHBOARD_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw dashboard content field is not allowed at ${path}.${key}`);
    }
    assertNoRawDashboardContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDashboardContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function intersects(left, right) {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
}

function includesAll(left, right) {
  const leftSet = new Set(left);
  return right.every((value) => leftSet.has(value));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'dashboard_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDashboard(input, reasons) {
  const dashboard = input?.dashboard;
  const role = hasText(dashboard?.role) ? dashboard.role : 'unknown';
  const allowedDashboardRoles = sortedTextList(input?.accessPolicy?.allowedDashboardRoles);
  addReason(reasons, !hasText(dashboard?.dashboardRef), 'dashboard_ref_absent');
  addReason(reasons, !DASHBOARD_ROLES.has(role), `dashboard_role_unsupported:${role}`);
  addReason(
    reasons,
    DASHBOARD_ROLES.has(role) && allowedDashboardRoles.length > 0 && !allowedDashboardRoles.includes(role),
    `dashboard_role_not_allowed:${role}`,
  );
  addReason(reasons, hlcTuple(dashboard?.generatedAtHlc) === null, 'dashboard_generated_time_invalid');
  addReason(reasons, !isDigest(dashboard?.sourceIndexHash), 'dashboard_source_index_hash_invalid');
  addReason(reasons, dashboard?.schemaVersion !== DASHBOARD_SCHEMA, 'dashboard_schema_invalid');
  addReason(reasons, dashboard?.metadataOnly !== true, 'dashboard_metadata_boundary_invalid');
  addReason(reasons, dashboard?.rawPayloadExcluded !== true, 'dashboard_payload_boundary_invalid');
  addReason(reasons, dashboard?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, !isDigest(dashboard?.widgetManifestHash), 'widget_manifest_hash_invalid');
  return role;
}

function evaluateAccessPolicy(input, reasons) {
  const policy = input?.accessPolicy;
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const allowedRoleRefs = sortedTextList(policy?.allowedRoleRefs);
  addReason(reasons, !hasText(policy?.policyRef), 'dashboard_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'dashboard_policy_hash_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'dashboard_policy_time_invalid');
  addReason(reasons, sortedTextList(policy?.allowedDashboardRoles).length === 0, 'dashboard_policy_roles_absent');
  addReason(reasons, allowedRoleRefs.length === 0, 'dashboard_policy_role_refs_absent');
  addReason(reasons, sortedTextList(policy?.allowedSiteRefs).length === 0, 'dashboard_policy_site_refs_absent');
  addReason(reasons, sortedTextList(policy?.allowedSensitivityTags).length === 0, 'dashboard_policy_sensitivity_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'dashboard_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.sourcePayloadAccessible !== false, 'dashboard_policy_payload_access_forbidden');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'dashboard_policy_disclosure_required');
  addReason(
    reasons,
    actorRoles.length > 0 && allowedRoleRefs.length > 0 && !intersects(actorRoles, allowedRoleRefs),
    'actor_role_not_allowed_by_policy',
  );
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, input?.dashboard?.generatedAtHlc), 'dashboard_policy_after_generation');
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logId), 'disclosure_log_id_absent');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_log_purpose_absent');
  addReason(reasons, !hasText(log?.recipientClass), 'disclosure_log_recipient_absent');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.accessPolicy?.evaluatedAtHlc), 'disclosure_log_before_policy');
  addReason(reasons, hlcAfter(log?.loggedAtHlc, input?.dashboard?.generatedAtHlc), 'disclosure_log_after_dashboard_generation');
}

function widgetAccessState(input, widget) {
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const policyRoles = sortedTextList(input?.accessPolicy?.allowedRoleRefs);
  const widgetRoles = sortedTextList(widget?.roleVisibility);
  const allowedSites = sortedTextList(input?.accessPolicy?.allowedSiteRefs);
  const widgetSites = sortedTextList(widget?.siteRefs);
  const allowedSensitivityTags = sortedTextList(input?.accessPolicy?.allowedSensitivityTags);
  const widgetSensitivityTags = sortedTextList(widget?.sensitivityTags);

  return {
    roleAllowed: widgetRoles.length > 0 && intersects(actorRoles, widgetRoles) && intersects(policyRoles, widgetRoles),
    siteAllowed: widgetSites.length > 0 && includesAll(allowedSites, widgetSites),
    sensitivityAllowed: widgetSensitivityTags.length > 0 && includesAll(allowedSensitivityTags, widgetSensitivityTags),
  };
}

function widgetIsVisible(input, widget) {
  const access = widgetAccessState(input, widget);
  return access.roleAllowed && access.siteAllowed && access.sensitivityAllowed;
}

function normalizeWidget(input, widget, requiredSet, reasons) {
  const metricKey = hasText(widget?.metricKey) ? widget.metricKey : 'unknown';
  const roleVisibility = sortedTextList(widget?.roleVisibility);
  const sourceFamilies = sortedTextList(widget?.sourceFamilies);
  const sensitivityTags = sortedTextList(widget?.sensitivityTags);
  const siteRefs = sortedTextList(widget?.siteRefs);

  addReason(reasons, !hasText(widget?.widgetRef), `widget_ref_absent:${metricKey}`);
  addReason(reasons, !hasText(widget?.metricKey), 'widget_metric_key_absent');
  addReason(reasons, hasText(widget?.metricKey) && !requiredSet.has(widget.metricKey), `widget_metric_not_required:${metricKey}`);
  addReason(reasons, !isDigest(widget?.evidenceHash), `widget_evidence_hash_invalid:${metricKey}`);
  addReason(reasons, !isDigest(widget?.custodyDigest), `widget_custody_digest_invalid:${metricKey}`);
  addReason(reasons, !isDigest(widget?.sourceIndexHash), `widget_source_index_hash_invalid:${metricKey}`);
  addReason(reasons, hlcTuple(widget?.updatedAtHlc) === null, `widget_updated_time_invalid:${metricKey}`);
  addReason(reasons, hlcAfter(widget?.updatedAtHlc, input?.dashboard?.generatedAtHlc), `widget_updated_after_dashboard:${metricKey}`);
  addReason(reasons, siteRefs.length === 0, `widget_site_refs_absent:${metricKey}`);
  addReason(reasons, roleVisibility.length === 0, `widget_role_visibility_absent:${metricKey}`);
  addReason(reasons, sensitivityTags.length === 0, `widget_sensitivity_tags_absent:${metricKey}`);
  addReason(reasons, sourceFamilies.length === 0, `widget_source_families_absent:${metricKey}`);
  addReason(reasons, !isBasisPoints(widget?.statusBasisPoints), `widget_status_basis_points_invalid:${metricKey}`);
  addReason(reasons, !isNonNegativeSafeInteger(widget?.recordCount), `widget_record_count_invalid:${metricKey}`);
  addReason(reasons, !isNonNegativeSafeInteger(widget?.criticalCount), `widget_critical_count_invalid:${metricKey}`);
  addReason(reasons, !isNonNegativeSafeInteger(widget?.overdueCount), `widget_overdue_count_invalid:${metricKey}`);
  addReason(reasons, widget?.boundary?.metadataOnly !== true, `widget_metadata_boundary_invalid:${metricKey}`);
  addReason(reasons, widget?.boundary?.rawContentExcluded !== true, `widget_raw_content_boundary_invalid:${metricKey}`);
  addReason(reasons, widget?.boundary?.sourcePayloadAnchored !== false, `widget_source_payload_anchor_forbidden:${metricKey}`);

  for (const sourceFamily of sourceFamilies) {
    addReason(reasons, !SOURCE_FAMILIES.has(sourceFamily), `widget_source_family_unsupported:${metricKey}:${sourceFamily}`);
  }

  return {
    metricKey,
    widgetRefHash: hasText(widget?.widgetRef) ? sha256Hex(widget.widgetRef) : null,
    evidenceHash: widget?.evidenceHash ?? null,
    custodyDigest: widget?.custodyDigest ?? null,
    sourceIndexHash: widget?.sourceIndexHash ?? null,
    updatedAtHlc: widget?.updatedAtHlc ?? null,
    siteRefs,
    sensitivityTags,
    sourceFamilies,
    statusBasisPoints: widget?.statusBasisPoints ?? 0,
    recordCount: widget?.recordCount ?? 0,
    criticalCount: widget?.criticalCount ?? 0,
    overdueCount: widget?.overdueCount ?? 0,
  };
}

function evaluateWidgets(input, role, reasons) {
  const requiredWidgetKeys = REQUIRED_WIDGETS[role] ?? [];
  const requiredSet = new Set(requiredWidgetKeys);
  const widgets = Array.isArray(input?.widgets) ? input.widgets : [];
  addReason(reasons, widgets.length === 0, 'dashboard_widgets_absent');

  const visibleByMetric = new Map();
  let suppressedWidgetCount = 0;

  for (const widget of widgets) {
    if (!widgetIsVisible(input, widget)) {
      suppressedWidgetCount += 1;
      continue;
    }

    const normalizedWidget = normalizeWidget(input, widget, requiredSet, reasons);
    if (requiredSet.has(normalizedWidget.metricKey)) {
      addReason(reasons, visibleByMetric.has(normalizedWidget.metricKey), `widget_metric_duplicate:${normalizedWidget.metricKey}`);
      if (!visibleByMetric.has(normalizedWidget.metricKey)) {
        visibleByMetric.set(normalizedWidget.metricKey, normalizedWidget);
      }
    }
  }

  for (const requiredWidgetKey of requiredWidgetKeys) {
    addReason(reasons, !visibleByMetric.has(requiredWidgetKey), `required_widget_missing:${requiredWidgetKey}`);
  }

  return {
    requiredWidgetKeys,
    suppressedWidgetCount,
    visibleWidgets: requiredWidgetKeys.map((metricKey) => visibleByMetric.get(metricKey)).filter(Boolean),
  };
}

function dashboardSummary(visibleWidgets, suppressedWidgetCount) {
  const visibleWidgetCount = visibleWidgets.length;
  const criticalCount = visibleWidgets.reduce((total, widget) => total + widget.criticalCount, 0);
  const overdueCount = visibleWidgets.reduce((total, widget) => total + widget.overdueCount, 0);
  const recordCount = visibleWidgets.reduce((total, widget) => total + widget.recordCount, 0);
  const statusTotal = visibleWidgets.reduce((total, widget) => total + BigInt(widget.statusBasisPoints), 0n);
  const averageStatusBasisPoints =
    visibleWidgetCount === 0 ? 0 : Number(statusTotal / BigInt(visibleWidgetCount));

  return {
    averageStatusBasisPoints,
    criticalCount,
    overdueCount,
    recordCount,
    suppressedWidgetCount,
    visibleWidgetCount,
  };
}

function deniedDashboard(role, requiredWidgetKeys, suppressedWidgetCount, denialReasons) {
  return {
    schema: DASHBOARD_SCHEMA,
    status: 'denied',
    dashboardRole: role,
    requiredWidgetKeys,
    visibleWidgets: [],
    summary: dashboardSummary([], suppressedWidgetCount),
    dashboardHash: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    canShowProductionTrustClaim: false,
    denialReasons: uniqueReasons(denialReasons),
    receipt: null,
  };
}

function buildReceipt(input, role, visibleWidgets, summary, dashboardHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: dashboardHash,
    artifactType: 'role_dashboard_result_set',
    artifactVersion: input.dashboard.dashboardRef,
    classification: 'dashboard_metadata',
    custodyDigest: sha256Hex({
      disclosureLogHash: input.disclosureLog.disclosureLogHash,
      sourceIndexHash: input.dashboard.sourceIndexHash,
      widgetManifestHash: input.dashboard.widgetManifestHash,
    }),
    hlcTimestamp: `${input.dashboard.generatedAtHlc.physicalMs}:${input.dashboard.generatedAtHlc.logical}`,
    schema: 'cybermedica.role_dashboard_receipt.v1',
    sensitivityTags: ['metadata_only', 'qms_dashboard', role],
    sourceSystem: 'cybermedica.role_dashboards',
    tenantId: input.tenantId,
    visibleWidgetCount: summary.visibleWidgetCount,
  });
}

export function evaluateRoleDashboard(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const role = evaluateDashboard(input, reasons);
  evaluateAccessPolicy(input, reasons);
  evaluateDisclosureLog(input, reasons);
  const { requiredWidgetKeys, suppressedWidgetCount, visibleWidgets } = evaluateWidgets(input, role, reasons);

  if (reasons.length > 0) {
    return deniedDashboard(role, requiredWidgetKeys, suppressedWidgetCount, reasons);
  }

  const summary = dashboardSummary(visibleWidgets, suppressedWidgetCount);
  const dashboardHash = sha256Hex({
    dashboardRef: input.dashboard.dashboardRef,
    disclosureLogHash: input.disclosureLog.disclosureLogHash,
    role,
    summary,
    visibleWidgets,
  });
  const receipt = buildReceipt(input, role, visibleWidgets, summary, dashboardHash);

  return {
    schema: DASHBOARD_SCHEMA,
    status: 'ready',
    dashboardRole: role,
    requiredWidgetKeys,
    visibleWidgets,
    summary,
    dashboardHash,
    trustState: 'inactive',
    exochainProductionClaim: false,
    canShowProductionTrustClaim: false,
    denialReasons: [],
    receipt,
  };
}
