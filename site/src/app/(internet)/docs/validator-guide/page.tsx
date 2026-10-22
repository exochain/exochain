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
  title: 'Validator Guide',
  description: 'Validator Guide. EXOCHAIN is the trust fabric for autonomous commerce.',
  path: '/docs/validator-guide',
});

export default function Page() {
  const publicStatus = loadPublicStatus();
  return (
    <DocPage title="Validator Guide" unstable>
      <h2>Role</h2>
      <p>
        Validators in EXOCHAIN are <em>custody verifiers</em>. They produce
        blocks, but more importantly they attest custody, run the validator
        rules deterministically, and uphold the constitutional invariants
        of the protocol.
      </p>
      <h2>Hardware</h2>
      <p>
        Validators are expected to run on attested hardware with secure
        boot, key management in an HSM or equivalent, and synchronized time
        sources. Confirm the requirements for the target deployment. The
        console at <code>/app/validators</code> is a mock; it does not enroll
        validators or establish deployment acceptance.
      </p>
      <h2>Attestation</h2>
      <p>
        Hardware attestation is required before joining the validator set.
        Attestation evidence is recorded as part of the validator&apos;s
        registration AVC.
      </p>
      <h2>Observation period</h2>
      <p>
        New validators run in observation mode before participating in
        quorum. The observation period validates determinism, network
        behavior, and operational hygiene.
      </p>
      <h2>Slashing</h2>
      <p>
        Slashing rules are governed by the constitutional kernel and are
        published as part of governance documents. This site does not
        publish an active public slashing rule set; consult the latest
        governance amendment before treating any rule here as in force.
      </p>
      <h2>Release and deployment scope</h2>
      <p>{publicStatus.maturity_summary}</p>
      <p>
        Publication of v{publicStatus.publication.version} does not by itself
        accept a validator deployment. See <Link href="/status">public status</Link>{' '}
        for the publication record and current capability boundaries.
      </p>
    </DocPage>
  );
}
