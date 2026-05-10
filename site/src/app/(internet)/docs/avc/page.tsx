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

export const metadata = { title: 'AVC' };

export default function Page() {
  return (
    <DocPage title="AVC — schema and validation" unstable>
      <h2>Schema</h2>
      <p>
        An AVC carries a unique id, subject and issuer actor ids, an optional
        parent AVC id (for delegation), a policy domain, a scope (action
        set + optional constraints), validity window, and an issuer signature.
      </p>
      <h2>Delegation</h2>
      <p>
        Delegation strictly narrows scope: a child AVC&apos;s permitted actions
        and constraints must be a subset of its parent&apos;s. Validation rejects
        any attempt to widen scope beyond the parent.
      </p>
      <h2>Validation rules</h2>
      <ul>
        <li>Signature verifies under the registered issuer key.</li>
        <li>Current time is within <code>not_before</code>/<code>not_after</code>.</li>
        <li>Subject actor is <code>active</code>.</li>
        <li>Issuer actor is <code>active</code> and authorized to issue in the policy domain.</li>
        <li>Parent AVC, if present, is itself valid and not revoked.</li>
        <li>Scope is contained within the parent&apos;s scope.</li>
        <li>Policy expressions evaluate without error.</li>
      </ul>
      <p>Validation is fail-closed and deterministic.</p>
      <h2>Revocation</h2>
      <p>
        An issuer revokes their AVC by submitting a signed revocation. The
        revocation cascades to all derivative AVCs. Already-issued trust
        receipts under the revoked AVC remain as evidence of past
        authorization.
      </p>
      <h2>Signature algorithms</h2>
      <p>
        ML-DSA-65 (CRYSTALS-Dilithium) is the post-quantum signature for new
        AVCs. Hybrid signatures are supported for transitional environments.
      </p>
    </DocPage>
  );
}
