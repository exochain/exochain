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

export const metadata = { title: 'Security Model' };

export default function Page() {
  return (
    <DocPage title="Security Model">
      <h2>Threat model</h2>
      <p>
        The threat model covers actor impersonation, key compromise,
        replay, scope widening, validator collusion, gateway compromise,
        side-channel disclosure, and revocation evasion. Mitigations are
        tracked in <code>governance/threat_matrix.md</code> in the public
        repository.
      </p>
      <h2>Cryptographic primitives</h2>
      <p>
        ML-DSA-65 (CRYSTALS-Dilithium) for signatures, with hybrid
        signature support. Hashing primitives and AEAD selections track
        current best practice and are documented in the security crate.
      </p>
      <h2>Determinism</h2>
      <p>
        No floating-point arithmetic anywhere in the protocol. Validation
        and consensus paths are deterministic so that disputes can be
        re-played bit-for-bit.
      </p>
      <h2>Disclosure</h2>
      <p>
        See the public <Link href="/security" className="underline">security page</Link>{' '}
        for coordinated-disclosure contact and PGP key.
      </p>
    </DocPage>
  );
}
