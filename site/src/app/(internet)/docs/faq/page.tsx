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

import Link from 'next/link';
import { DocPage } from '@/components/content/DocPage';
import { loadPublicStatus } from '@/lib/public-status';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'FAQ',
  description: 'FAQ. EXOCHAIN is the trust fabric for autonomous commerce.',
  path: '/docs/faq',
});

const QA: { q: string; a: string }[] = [
  {
    q: 'Is EXOCHAIN a cryptocurrency?',
    a: 'No. EXOCHAIN is a custody-native blockchain. The internal ledger ships a transaction mechanism whose launch policy resolves every active price to zero. That policy does not set a third-party x402 payment amount or the price of commercial licensing. There is no token sale and no investment offering.'
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
  }
];

export default function Page() {
  const publicStatus = loadPublicStatus();
  return (
    <DocPage title="FAQ">
      <div className="space-y-6">
        {QA.map((x) => (
          <div key={x.q}>
            <h3>{x.q}</h3>
            <p>{x.a}</p>
          </div>
        ))}
        <div>
          <h3>Does a published release mean my deployment is production-ready?</h3>
          <p>{publicStatus.maturity_summary}</p>
          <p>
            Release readiness and deployment acceptance are separate. The
            publication record lists v{publicStatus.publication.version} as{' '}
            {publicStatus.maturity}. A deployment still needs its own acceptance
            of configuration, enabled features, validator membership,
            attestation, and operational controls. See the{' '}
            <Link href="/status">publication record and capability boundaries</Link>{' '}
            and the <Link href="/trust-center">Trust Center</Link> for the
            evidence relevant to that assessment.
          </p>
        </div>
      </div>
    </DocPage>
  );
}
