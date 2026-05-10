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

export const metadata = { title: 'Trust Receipts' };

export default function Page() {
  return (
    <DocPage title="Trust Receipts" unstable>
      <h2>Anatomy</h2>
      <p>
        Each receipt carries: <code>id</code>, <code>avc_id</code>,{' '}
        <code>actor_id</code>, <code>policy_hash</code>,{' '}
        <code>action_descriptor</code>, <code>outcome</code>,{' '}
        <code>custody_hash</code>, optional <code>prev_hash</code>,{' '}
        <code>timestamp</code>, and a <code>signature</code> over the
        canonical encoding.
      </p>
      <h2>Outcomes</h2>
      <p>
        <code>permitted</code>, <code>denied</code>, or <code>partial</code>.
        Denied attempts produce receipts so the absence of authorization is
        itself attested.
      </p>
      <h2>Custody chain</h2>
      <p>
        Each receipt&apos;s <code>custody_hash</code> binds it to its{' '}
        <code>prev_hash</code>, forming a per-actor hash chain. The chain is
        anchored to the EXOCHAIN ledger at block boundaries.
      </p>
      <h2>Verification</h2>
      <p>
        Receipts are verifiable offline given the issuer&apos;s public key, the
        AVC, and the policy in effect at execution time. The SDK exposes a
        verifier that returns a structured result with reason codes.
      </p>
    </DocPage>
  );
}
