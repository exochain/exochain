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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

async function loadRoleDashboards() {
  try {
    return await import('../src/role-dashboards.mjs');
  } catch (error) {
    assert.fail(`CyberMedica role dashboards module must exist and load: ${error.message}`);
  }
}

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

const ROLE_REFS = Object.freeze({
  auditor: ['auditor'],
  coordinator: ['clinical_research_coordinator'],
  cro_portfolio_manager: ['cro_portfolio_manager'],
  decision_forum: ['decision_forum'],
  principal_investigator: ['principal_investigator'],
  quality_manager: ['quality_manager'],
  site_leader: ['site_leader'],
  sponsor_viewer: ['sponsor_viewer'],
});

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
  DIGEST_9,
];

function roleDashboardInput(role = 'quality_manager', overrides = {}) {
  const roleRefs = ROLE_REFS[role];
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: `did:exo:${role.replaceAll('_', '-')}-alpha`,
      kind: 'human',
      roleRefs,
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['dashboard_view', 'read'],
      authorityChainHash: DIGEST_A,
    },
    dashboard: {
      dashboardRef: `dashboard-${role}-site-alpha`,
      role,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 30 },
      sourceIndexHash: DIGEST_B,
      schemaVersion: 'cybermedica.role_dashboard.v1',
      metadataOnly: true,
      rawPayloadExcluded: true,
      productionTrustClaim: false,
      widgetManifestHash: DIGEST_C,
    },
    accessPolicy: {
      policyRef: `dashboard-policy-${role}`,
      policyHash: DIGEST_D,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 2 },
      allowedDashboardRoles: Object.keys(REQUIRED_WIDGETS),
      allowedRoleRefs: roleRefs,
      allowedSiteRefs: ['site-alpha'],
      allowedSensitivityTags: ['metadata_only', 'qms', 'sponsor_confidential_metadata', 'audit_metadata'],
      metadataOnly: true,
      sourcePayloadAccessible: false,
      disclosureLogRequired: true,
    },
    disclosureLog: {
      logId: `dashboard-disclosure-${role}`,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 3 },
      disclosureLogHash: DIGEST_E,
      purpose: 'role_dashboard_view',
      recipientClass: role,
      includesRawContent: false,
    },
    widgets: dashboardWidgets(role),
    ...overrides,
  };
}

function dashboardWidgets(role) {
  return REQUIRED_WIDGETS[role].map((metricKey, index) => widget(metricKey, index, role));
}

function widget(metricKey, index, role = 'quality_manager', overrides = {}) {
  return {
    widgetRef: `${role}-${metricKey}-widget`,
    metricKey,
    evidenceHash: DIGESTS[index % DIGESTS.length],
    custodyDigest: DIGESTS[(index + 1) % DIGESTS.length],
    sourceIndexHash: DIGESTS[(index + 2) % DIGESTS.length],
    updatedAtHlc: { physicalMs: 1795000000000, logical: index + 4 },
    siteRefs: ['site-alpha'],
    roleVisibility: ROLE_REFS[role],
    sensitivityTags: ['metadata_only', 'qms'],
    sourceFamilies: ['controls', 'evidence', 'risks'],
    statusBasisPoints: 10_000 - index * 250,
    recordCount: index + 1,
    criticalCount: index % 3 === 0 ? 1 : 0,
    overdueCount: index % 4 === 0 ? 1 : 0,
    boundary: {
      metadataOnly: true,
      rawContentExcluded: true,
      sourcePayloadAnchored: false,
    },
    ...overrides,
  };
}

test('role dashboards render deterministic inactive metadata-only dashboards for all PRD roles', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();

  for (const [role, requiredWidgets] of Object.entries(REQUIRED_WIDGETS)) {
    const input = roleDashboardInput(role);
    const reversedInput = { ...input, widgets: [...input.widgets].reverse() };
    const resultA = evaluateRoleDashboard(input);
    const resultB = evaluateRoleDashboard(reversedInput);

    assert.equal(resultA.status, 'ready', role);
    assert.deepEqual(resultA.denialReasons, [], role);
    assert.equal(resultA.trustState, 'inactive', role);
    assert.equal(resultA.exochainProductionClaim, false, role);
    assert.equal(resultA.canShowProductionTrustClaim, false, role);
    assert.deepEqual(resultA.requiredWidgetKeys, requiredWidgets, role);
    assert.deepEqual(
      resultA.visibleWidgets.map((visibleWidget) => visibleWidget.metricKey),
      requiredWidgets,
      role,
    );
    assert.deepEqual(resultA.visibleWidgets, resultB.visibleWidgets, role);
    assert.equal(resultA.dashboardHash, resultB.dashboardHash, role);
    assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId, role);
    assert.equal(resultA.receipt.trustState, 'inactive', role);
    assert.equal(resultA.summary.visibleWidgetCount, requiredWidgets.length, role);
    assert.equal(resultA.summary.suppressedWidgetCount, 0, role);
    assert.ok(Number.isSafeInteger(resultA.summary.averageStatusBasisPoints), role);
  }
});

test('role dashboard fails closed for unsafe authority role widget and production trust defects', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const input = roleDashboardInput('quality_manager', {
    actor: { did: 'did:exo:ai-quality-agent', kind: 'ai_agent', roleRefs: ['quality_manager'] },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    dashboard: {
      ...roleDashboardInput('quality_manager').dashboard,
      productionTrustClaim: true,
    },
    accessPolicy: {
      ...roleDashboardInput('quality_manager').accessPolicy,
      allowedDashboardRoles: ['site_leader'],
    },
    widgets: roleDashboardInput('quality_manager').widgets.slice(1).map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            boundary: {
              metadataOnly: false,
              rawContentExcluded: false,
              sourcePayloadAnchored: true,
            },
          }
        : dashboardWidget,
    ),
  });

  const result = evaluateRoleDashboard(input);

  assert.equal(result.status, 'denied');
  assert.equal(result.receipt, null);
  assert.equal(result.summary.visibleWidgetCount, 0);
  assert.ok(result.denialReasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.denialReasons.includes('human_actor_required'));
  assert.ok(result.denialReasons.includes('dashboard_authority_missing'));
  assert.ok(result.denialReasons.includes('dashboard_role_not_allowed:quality_manager'));
  assert.ok(result.denialReasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.denialReasons.includes('required_widget_missing:control_status'));
  assert.ok(result.denialReasons.includes('widget_metadata_boundary_invalid:evidence_completeness'));
  assert.ok(result.denialReasons.includes('widget_raw_content_boundary_invalid:evidence_completeness'));
  assert.ok(result.denialReasons.includes('widget_source_payload_anchor_forbidden:evidence_completeness'));
});

test('role dashboard suppresses inaccessible extra widgets without leaking suppressed widget refs', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const input = roleDashboardInput('sponsor_viewer', {
    widgets: [
      ...roleDashboardInput('sponsor_viewer').widgets,
      widget('internal_quality_only_signal', 12, 'quality_manager', {
        widgetRef: 'restricted-quality-widget-ref',
        roleVisibility: ['quality_manager'],
      }),
      widget('other_site_equipment_gap', 13, 'sponsor_viewer', {
        widgetRef: 'restricted-site-widget-ref',
        siteRefs: ['site-beta'],
      }),
      widget('source_payload_signal', 14, 'sponsor_viewer', {
        widgetRef: 'restricted-sensitivity-widget-ref',
        sensitivityTags: ['metadata_only', 'raw_source_payload'],
      }),
    ],
  });

  const result = evaluateRoleDashboard(input);
  const serialized = JSON.stringify(result);

  assert.equal(result.status, 'ready');
  assert.equal(result.summary.visibleWidgetCount, REQUIRED_WIDGETS.sponsor_viewer.length);
  assert.equal(result.summary.suppressedWidgetCount, 3);
  assert.equal(result.suppressedWidgetRefs, undefined);
  assert.doesNotMatch(serialized, /restricted-quality-widget-ref|restricted-site-widget-ref|restricted-sensitivity-widget-ref/u);
  assert.deepEqual(
    result.visibleWidgets.map((visibleWidget) => visibleWidget.metricKey),
    REQUIRED_WIDGETS.sponsor_viewer,
  );
});

test('role dashboard validates HLC ordering and same-tick dashboard clocks', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const valid = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 20 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 3 },
    },
  });
  const invalid = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 10 },
    },
    accessPolicy: {
      ...roleDashboardInput('site_leader').accessPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 5 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 4 },
    },
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            updatedAtHlc: { physicalMs: 1795000000000, logical: 11 },
          }
        : dashboardWidget,
    ),
  });

  assert.equal(evaluateRoleDashboard(valid).status, 'ready');

  const invalidResult = evaluateRoleDashboard(invalid);
  assert.equal(invalidResult.status, 'denied');
  assert.ok(invalidResult.denialReasons.includes('disclosure_log_before_policy'));
  assert.ok(invalidResult.denialReasons.includes('widget_updated_after_dashboard:site_qms_passport_status'));

  const physicalOrdering = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    accessPolicy: {
      ...roleDashboardInput('site_leader').accessPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000001, logical: 0 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            updatedAtHlc: { physicalMs: 1795000000002, logical: 0 },
          }
        : dashboardWidget,
    ),
  });

  const physicalOrderingResult = evaluateRoleDashboard(physicalOrdering);
  assert.equal(physicalOrderingResult.status, 'denied');
  assert.ok(physicalOrderingResult.denialReasons.includes('disclosure_log_before_policy'));
  assert.ok(physicalOrderingResult.denialReasons.includes('widget_updated_after_dashboard:site_qms_passport_status'));

  const malformedClock = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: -1 },
    },
  });
  const malformedClockResult = evaluateRoleDashboard(malformedClock);
  assert.equal(malformedClockResult.status, 'denied');
  assert.ok(malformedClockResult.denialReasons.includes('dashboard_generated_time_invalid'));
});

test('role dashboard rejects raw dashboard widget and protected content before receipts', async () => {
  const { evaluateRoleDashboard, ProtectedContentError } = await loadRoleDashboards();

  assert.throws(
    () =>
      evaluateRoleDashboard({
        ...roleDashboardInput('auditor'),
        rawDashboardText: 'source document body must not be anchored in a dashboard',
      }),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateRoleDashboard({
        ...roleDashboardInput('coordinator'),
        widgets: [
          ...roleDashboardInput('coordinator').widgets,
          widget('coordinator_raw_note', 1, 'coordinator', {
            rawWidgetText: 'participant Jane Example visit details',
          }),
        ],
      }),
    ProtectedContentError,
  );
});
