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
export declare const PROTOCOL_VERSION = "0.1.0-beta";
export * from './types.js';
export * from './errors.js';
export * from './client.js';
export { Identity, deriveDid } from './identity/keypair.js';
export { validateDid, isDid } from './identity/did.js';
export { BailmentBuilder } from './consent/bailment.js';
export type { BailmentProposal, HlcTimestamp } from './consent/bailment.js';
export { Decision, DecisionBuilder } from './governance/decision.js';
export type { DecisionStatus } from './governance/decision.js';
export { Vote, VoteChoice, isVoteChoice } from './governance/vote.js';
export { AuthorityChainBuilder } from './authority/chain.js';
export type { ChainLink, ValidatedChain } from './authority/chain.js';
export { sha256, sha256Hex, sha256Hash, bytesToHex, hexToBytes } from './crypto/hash.js';
export { HttpTransport } from './transport/http.js';
export type { HttpTransportOptions } from './transport/http.js';
//# sourceMappingURL=index.d.ts.map