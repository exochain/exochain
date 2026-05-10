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
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';

export const metadata = { title: 'Settlement' };

export default function Page() {
  return (
    <DocPage title="Settlement (zero-priced launch policy)" unstable>
      <ZeroPriceBanner />
      <h2>Quotes</h2>
      <p>
        A quote is generated against a trust receipt. Under the current
        launch policy every quote returns <code>amount = 0</code> with a{' '}
        <code>ZeroFeeReason</code>. The quote includes an{' '}
        <code>expires_at</code>; expired quotes must be regenerated.
      </p>
      <h2>ZeroFeeReason</h2>
      <ul>
        <li><code>launch_policy_zero</code> — the default during alpha.</li>
        <li><code>governance_subsidy</code> — issued under specific governance amendments.</li>
        <li><code>humanitarian_carve_out</code> — declared scopes (see governance).</li>
      </ul>
      <h2>Settlement receipts</h2>
      <p>
        Committing a quote yields a settlement receipt. The receipt
        references the quote, the trust receipt, and the fee reason, and is
        signed and chained to its predecessor.
      </p>
      <h2>Future pricing</h2>
      <p>
        Future governance amendments may enable nonzero pricing for declared
        scopes. The economy crate ships the full mechanism today; it is
        suppressed by policy. Pricing changes route through the
        constitutional governance kernel.
      </p>
    </DocPage>
  );
}
