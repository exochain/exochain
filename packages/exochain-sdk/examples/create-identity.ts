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

/**
 * Example: create a fresh identity and sign/verify a message.
 *
 * Build the package first: `npm run build`.
 * Run: `node examples/create-identity.js` (after tsc) or use your own runner.
 *
 * Published applications should import from `@exochain/sdk`:
 *
 * ```ts
 * import { Identity } from '@exochain/sdk';
 * ```
 */

import { Identity } from '../dist/index.js';

async function main(): Promise<void> {
  // Generate a fresh Ed25519 keypair and derive the DID from the public key.
  const alice = await Identity.generate('alice');
  console.log('DID:          ', alice.did);
  console.log('Public key:   ', alice.publicKeyHex);
  console.log('Label:        ', alice.label);

  // Sign a message and verify the signature.
  const message = new TextEncoder().encode('hello exochain');
  const signature = await alice.sign(message);
  const verified = await Identity.verify(alice.publicKeyHex, message, signature);

  console.log('Signature ok: ', verified);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
