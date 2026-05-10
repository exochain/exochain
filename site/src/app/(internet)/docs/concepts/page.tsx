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

export const metadata = { title: 'Concepts' };

export default function Page() {
  return (
    <DocPage title="Concepts">
      <h2>Identity</h2>
      <p>
        Who an actor is. EXOCHAIN actors are humans, organizations, agents,
        holons, services, and validators. Each carries a signing key,
        registered metadata, and a status (<code>active</code>,{' '}
        <code>inactive</code>, <code>quarantined</code>).
      </p>
      <h2>Authority</h2>
      <p>
        What an actor may invoke under policy. Authority lives across many
        systems. EXOCHAIN coordinates authority by referencing it from AVCs,
        not by replacing system-local controls.
      </p>
      <h2>Volition (delegated)</h2>
      <p>
        The operational intent encoded in an AVC. Volition is bounded:
        scoped, expiring, revocable, hierarchical. EXOCHAIN does not claim
        AI consciousness; volition here is precisely{' '}
        <em>delegated operational intent</em>.
      </p>
      <h2>Consent</h2>
      <p>
        A principal&apos;s grant. Consent is recorded as part of the AVC issuance
        flow and persists with a scope hash that proves what was agreed to,
        independent of presentation.
      </p>
      <h2>Execution</h2>
      <p>
        The action that occurs after validation succeeds. Executions are
        captured as receipts. Failed validations also produce receipts —
        with outcome <code>denied</code> — so the absence of authorization
        is itself attested.
      </p>
      <h2>Custody</h2>
      <p>
        The unbroken evidentiary chain across identity, authority, volition,
        consent, execution, and revocation. Custody is the purpose; the
        blockchain is the mechanism.
      </p>
    </DocPage>
  );
}
