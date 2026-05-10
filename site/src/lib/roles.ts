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

// Role/permission matrix for EXOCHAIN extranet and intranet.
// See SPEC.md §5 for the canonical description.

export type ExtranetRole =
  | 'org_admin'
  | 'developer'
  | 'enterprise_user'
  | 'partner'
  | 'validator_operator'
  | 'node_operator'
  | 'auditor'
  | 'researcher'
  | 'credential_issuer'
  | 'custody_verifier'
  | 'agent_operator'
  | 'legal_reviewer'
  | 'support_user';

export type IntranetRole =
  | 'super_admin'
  | 'protocol_maintainer'
  | 'security_admin'
  | 'governance_admin'
  | 'node_ops'
  | 'support'
  | 'legal_compliance'
  | 'product'
  | 'devrel'
  | 'content_admin'
  | 'incident_commander'
  | 'auditor_internal';

export type Role = ExtranetRole | IntranetRole;

export const EXTRANET_ROLES: ExtranetRole[] = [
  'org_admin',
  'developer',
  'enterprise_user',
  'partner',
  'validator_operator',
  'node_operator',
  'auditor',
  'researcher',
  'credential_issuer',
  'custody_verifier',
  'agent_operator',
  'legal_reviewer',
  'support_user'
];

export const INTRANET_ROLES: IntranetRole[] = [
  'super_admin',
  'protocol_maintainer',
  'security_admin',
  'governance_admin',
  'node_ops',
  'support',
  'legal_compliance',
  'product',
  'devrel',
  'content_admin',
  'incident_commander',
  'auditor_internal'
];

export function isExtranetRole(r: string): r is ExtranetRole {
  return (EXTRANET_ROLES as string[]).includes(r);
}

export function isIntranetRole(r: string): r is IntranetRole {
  return (INTRANET_ROLES as string[]).includes(r);
}

export const ROLE_LABEL: Record<Role, string> = {
  org_admin: 'Org Admin',
  developer: 'Developer',
  enterprise_user: 'Enterprise',
  partner: 'Partner',
  validator_operator: 'Validator Op',
  node_operator: 'Node Op',
  auditor: 'Auditor',
  researcher: 'Researcher',
  credential_issuer: 'Issuer',
  custody_verifier: 'Verifier',
  agent_operator: 'Agent Op',
  legal_reviewer: 'Legal',
  support_user: 'Support User',
  super_admin: 'Super Admin',
  protocol_maintainer: 'Protocol',
  security_admin: 'Security',
  governance_admin: 'Governance',
  node_ops: 'Node Ops',
  support: 'Support',
  legal_compliance: 'Legal/Compliance',
  product: 'Product',
  devrel: 'DevRel',
  content_admin: 'Content',
  incident_commander: 'Incident Cmdr',
  auditor_internal: 'Internal Audit'
};

// Capability checks. Conservative by default.
export type Capability =
  | 'avc.issue'
  | 'avc.revoke'
  | 'avc.quarantine'
  | 'pricing.view'
  | 'pricing.edit'
  | 'pricing.future-config'
  | 'governance.view'
  | 'governance.ratify'
  | 'incident.open'
  | 'incident.close'
  | 'content.publish'
  | 'audit.export'
  | 'security.review'
  | 'release.publish'
  | 'flag.write';

const EXTRANET_CAPS: Record<ExtranetRole, Capability[]> = {
  org_admin: ['avc.issue', 'avc.revoke', 'audit.export'],
  developer: ['avc.issue'],
  enterprise_user: [],
  partner: [],
  validator_operator: [],
  node_operator: [],
  auditor: ['audit.export'],
  researcher: [],
  credential_issuer: ['avc.issue'],
  custody_verifier: [],
  agent_operator: ['avc.issue'],
  legal_reviewer: ['audit.export'],
  support_user: []
};

const INTRANET_CAPS: Record<IntranetRole, Capability[]> = {
  super_admin: [
    'avc.issue',
    'avc.revoke',
    'avc.quarantine',
    'pricing.view',
    'pricing.edit',
    'pricing.future-config',
    'governance.view',
    'governance.ratify',
    'incident.open',
    'incident.close',
    'content.publish',
    'audit.export',
    'security.review',
    'release.publish',
    'flag.write'
  ],
  protocol_maintainer: ['release.publish', 'flag.write', 'governance.view'],
  security_admin: [
    'avc.revoke',
    'avc.quarantine',
    'incident.open',
    'incident.close',
    'security.review',
    'audit.export'
  ],
  governance_admin: [
    'pricing.view',
    'pricing.edit',
    'pricing.future-config',
    'governance.view',
    'governance.ratify'
  ],
  node_ops: ['flag.write'],
  support: [],
  legal_compliance: ['audit.export', 'governance.view'],
  product: ['content.publish'],
  devrel: ['content.publish'],
  content_admin: ['content.publish'],
  incident_commander: ['incident.open', 'incident.close'],
  auditor_internal: ['governance.view', 'audit.export']
};

export function can(role: Role, cap: Capability): boolean {
  if (isIntranetRole(role)) return INTRANET_CAPS[role].includes(cap);
  if (isExtranetRole(role)) return EXTRANET_CAPS[role].includes(cap);
  return false;
}
