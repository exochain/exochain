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

export const metadata = { title: 'FAQ' };

const QA: { q: string; a: string }[] = [
  {
    q: 'Is EXOCHAIN a cryptocurrency?',
    a: 'No. EXOCHAIN is a custody-native blockchain. The economic layer ships the transaction mechanism, but the launch policy resolves every active price to zero. There is no token sale and no investment offering.'
  },
  {
    q: 'Does EXOCHAIN claim AI has consciousness?',
    a: 'No. The word "volition" in AVC is operational and delegated. It refers to the authorized intent a principal hands to a subject; it is not a claim about machine sentience.'
  },
  {
    q: 'Can AVC validation be slowed by network congestion or pricing changes?',
    a: 'No. Validation is independent of the economy and runs deterministically against the AVC, the parent chain, and the policy in effect.'
  },
  {
    q: 'What happens to receipts after I revoke an AVC?',
    a: 'They remain. Receipts issued before revocation continue to be valid evidence of the authorization that existed at execution time. Future actions under the revoked AVC fail-closed.'
  },
  {
    q: 'Is the network production-ready?',
    a: 'No. EXOCHAIN is in alpha. Validator membership, attestation, and pricing policy are all subject to change. See the Trust Center for current capabilities and the public roadmap.'
  }
];

export default function Page() {
  return (
    <DocPage title="FAQ">
      <div className="space-y-6">
        {QA.map((x) => (
          <div key={x.q}>
            <h3>{x.q}</h3>
            <p>{x.a}</p>
          </div>
        ))}
      </div>
    </DocPage>
  );
}
