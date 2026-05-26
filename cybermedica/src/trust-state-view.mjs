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

const TRUST_STATE_COPY = Object.freeze({
  inactive: {
    severity: 'neutral',
    primaryText: 'Exochain production trust is inactive for this CyberMedica action.',
    secondaryText: 'Baseline QMS workflow may proceed only as operational state without an active Exochain production claim.',
  },
  pending: {
    severity: 'attention',
    primaryText: 'Exochain trust evidence is pending verification.',
    secondaryText: 'The action remains disabled for production trust language until all required receipts verify.',
  },
  denied: {
    severity: 'critical',
    primaryText: 'Exochain trust evidence was denied.',
    secondaryText: 'The action cannot proceed as a trusted CyberMedica workflow until the failing evidence is corrected.',
  },
  degraded: {
    severity: 'warning',
    primaryText: 'Exochain trust dependency is degraded or unavailable.',
    secondaryText: 'The adapter fails closed and disables trust-dependent actions until service readiness returns.',
  },
  verified: {
    severity: 'success',
    primaryText: 'Verified Exochain receipt path is available for this CyberMedica action.',
    secondaryText: 'The UI may show the verified production trust claim that maps to this receipt path.',
  },
});

function normalizeBlockedBy(blockedBy) {
  if (!Array.isArray(blockedBy)) {
    return [];
  }
  return blockedBy.filter((item) => typeof item === 'string' && item.length > 0).sort();
}

export function buildTrustStateView(input) {
  const requestedState = typeof input?.state === 'string' ? input.state : 'inactive';
  const status = Object.hasOwn(TRUST_STATE_COPY, requestedState) ? requestedState : 'inactive';
  const copy = TRUST_STATE_COPY[status];
  const canShowProductionTrustClaim = status === 'verified';

  return {
    schema: 'cybermedica.trust_state_view.v1',
    status,
    severity: copy.severity,
    primaryText: copy.primaryText,
    secondaryText: copy.secondaryText,
    blockedBy: normalizeBlockedBy(input?.blockedBy),
    actionsDisabled: !canShowProductionTrustClaim,
    canShowProductionTrustClaim,
  };
}
