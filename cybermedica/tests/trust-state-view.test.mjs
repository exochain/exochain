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

async function loadTrustStateView() {
  try {
    return await import('../src/trust-state-view.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust-state view module must exist and load: ${error.message}`);
  }
}

test('trust-state UI view models expose inactive pending denied degraded and verified states explicitly', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const inactive = buildTrustStateView({ state: 'inactive', blockedBy: ['root_bundle_absent'] });
  assert.equal(inactive.status, 'inactive');
  assert.equal(inactive.actionsDisabled, true);
  assert.equal(inactive.canShowProductionTrustClaim, false);
  assert.doesNotMatch(inactive.primaryText, /root-backed production authority/i);

  const pending = buildTrustStateView({ state: 'pending', blockedBy: ['root_verifier_pending'] });
  assert.equal(pending.status, 'pending');
  assert.equal(pending.actionsDisabled, true);

  const denied = buildTrustStateView({ state: 'denied', blockedBy: ['human_gate_unverified'] });
  assert.equal(denied.status, 'denied');
  assert.equal(denied.actionsDisabled, true);

  const degraded = buildTrustStateView({ state: 'degraded', blockedBy: ['gateway_timeout'] });
  assert.equal(degraded.status, 'degraded');
  assert.equal(degraded.actionsDisabled, true);

  const verified = buildTrustStateView({ state: 'verified', blockedBy: [] });
  assert.equal(verified.status, 'verified');
  assert.equal(verified.actionsDisabled, false);
  assert.equal(verified.canShowProductionTrustClaim, true);
  assert.match(verified.primaryText, /verified/i);
});
