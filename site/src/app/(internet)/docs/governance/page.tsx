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

import { DocPage } from '@/components/content/DocPage';

export const metadata = { title: 'Governance Model' };

export default function Page() {
  return (
    <DocPage title="Governance Model">
      <h2>Constitutional invariants</h2>
      <p>
        Certain protocol invariants — fail-closed validation, scope
        narrowing under delegation, independence of trust and economy,
        absence of floating-point arithmetic — are enforced by a
        constitutional governance kernel and cannot be revised by ordinary
        amendment.
      </p>
      <h2>Proposal lifecycle</h2>
      <ol>
        <li>Draft. Open commentary period.</li>
        <li>Quorum vote among governance signers.</li>
        <li>Ratification with cooldown window before activation.</li>
        <li>Activation gated by feature flag and observable rollout.</li>
      </ol>
      <h2>Pricing changes</h2>
      <p>
        Switching <code>ZeroFeeReason</code> off for declared scopes
        requires a governance amendment with quorum ratification and a
        cooldown. AVC validation is unaffected by pricing changes.
      </p>
    </DocPage>
  );
}
