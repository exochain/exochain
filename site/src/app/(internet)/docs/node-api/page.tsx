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
import { Pre } from '@/components/ui/Code';

export const metadata = { title: 'Node API' };

export default function Page() {
  return (
    <DocPage title="Node API" unstable>
      <h2>Surfaces</h2>
      <p>
        <code>exo-gateway</code> exposes a REST surface and a GraphQL
        surface. Health probes and a small admin set are also exposed.
      </p>
      <h2>Authentication</h2>
      <p>
        API keys created at <code>/app/api-keys</code> authenticate gateway
        requests. Keys are scoped per-org and per-capability. Rotate
        regularly. Never embed keys in client code.
      </p>
      <h2>Endpoint shape (excerpt)</h2>
      <Pre>
{`POST   /v1/actors                 register an actor
POST   /v1/avc/issue              issue an AVC
POST   /v1/avc/validate           validate an AVC
POST   /v1/avc/revoke             revoke an AVC
POST   /v1/receipts/trust         emit a trust receipt
POST   /v1/settlement/quote       request a settlement quote (zero-priced)
POST   /v1/settlement/commit      commit a quote into a settlement receipt
GET    /v1/custody/:actor_id      fetch custody trail for an actor
GET    /healthz, /readyz, /livez  health probes`}
      </Pre>
      <p>
        The full OpenAPI document will be served at <code>/api</code> once
        the gateway publishes it.
      </p>
    </DocPage>
  );
}
