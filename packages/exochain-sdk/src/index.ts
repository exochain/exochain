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
 * @exochain/sdk — TypeScript SDK for the EXOCHAIN constitutional governance fabric.
 *
 * The package entry point re-exports everything needed to build applications
 * against an `exo-gateway` or to use the pure-JS primitives (identity, consent,
 * governance, authority) in isolation.
 *
 * Distribution: ESM-only. Requires Node >= 20 or a modern browser with
 * Web Crypto. Applications bundled with legacy CJS-only tooling must
 * enable Node's ESM interop (`import()` or `--experimental-vm-modules`).
 * A dual CJS/ESM build is tracked as A-064 in the remediation plan.
 */

/**
 * Fabric protocol version this SDK speaks (A-066). Clients may `/version`-probe
 * a target gateway on init and warn when the server reports a different
 * major/minor so users can distinguish protocol skew from transport errors.
 */
export const PROTOCOL_VERSION = '0.2.1-beta';

export * from './types.js';
export * from './errors.js';
export * from './client.js';
export type { JsonObject, JsonValue } from './validation.js';

export { Identity, deriveDid } from './identity/keypair.js';
export { validateDid, isDid } from './identity/did.js';

export { BailmentBuilder } from './consent/bailment.js';
export type { BailmentProposal, HlcTimestamp } from './consent/bailment.js';

export { Decision, DecisionBuilder } from './governance/decision.js';
export type { DecisionStatus } from './governance/decision.js';
export { Vote, VoteChoice, isVoteChoice } from './governance/vote.js';

export { AuthorityChainBuilder } from './authority/chain.js';
export type { ChainLink, ValidatedChain } from './authority/chain.js';

export {
  blake3,
  blake3Hex,
  blake3Hash,
  sha256,
  sha256Hex,
  sha256Hash,
  bytesToHex,
  hexToBytes,
} from './crypto/hash.js';

export { HttpTransport } from './transport/http.js';
export type { HttpTransportOptions } from './transport/http.js';
