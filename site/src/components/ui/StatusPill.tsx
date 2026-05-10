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

import { Pill } from './Pill';

export type Status =
  | 'active'
  | 'expired'
  | 'revoked'
  | 'quarantined'
  | 'inactive'
  | 'healthy'
  | 'degraded'
  | 'syncing'
  | 'offline'
  | 'permitted'
  | 'denied'
  | 'partial'
  | 'open'
  | 'mitigated'
  | 'resolved'
  | 'draft'
  | 'ratified'
  | 'rejected'
  | 'success'
  | 'error';

const map: Record<Status, Parameters<typeof Pill>[0]['tone']> = {
  active: 'verify',
  expired: 'roadmap',
  revoked: 'alert',
  quarantined: 'signal',
  inactive: 'roadmap',
  healthy: 'verify',
  degraded: 'signal',
  syncing: 'custody',
  offline: 'alert',
  permitted: 'verify',
  denied: 'alert',
  partial: 'signal',
  open: 'signal',
  mitigated: 'custody',
  resolved: 'verify',
  draft: 'roadmap',
  ratified: 'verify',
  rejected: 'alert',
  success: 'verify',
  error: 'alert'
};

export function StatusPill({ status }: { status: Status }) {
  return <Pill tone={map[status]}>{status}</Pill>;
}
