# @exochain/sdk

TypeScript/JavaScript SDK for **EXOCHAIN** — the constitutional governance
fabric for AI systems and data sovereignty. EXOCHAIN provides cryptographically
verifiable identity (DID), consent (bailments), authority delegation, and
governance primitives that enforce policy *before* action rather than auditing
it after.

This package is the pure-TypeScript, zero-runtime-dependency client. It exposes
the same ergonomic builder surface as the Rust `exochain-sdk` crate and adds an
HTTP client for talking to a running `exo-gateway`.

## Installation

```bash
npm install @exochain/sdk
```

Requires **Node.js 20 or newer** (for stable Web Crypto Ed25519 support). The
package is ESM-only and ships with TypeScript declarations.

Browsers are supported anywhere the Web Crypto API exposes
`Ed25519` — current Chromium, Safari 17+, and Firefox 130+. See
[Browser vs Node considerations](#browser-vs-node-considerations) below.

## Quick start

The canonical five-domain flow: identity, consent, governance, authority,
kernel adjudication.

### 1. Create identities

```ts
import { Identity } from '@exochain/sdk';

const alice = await Identity.generate('alice');
const bob = await Identity.generate('bob');

console.log(alice.did);          // did:exo:<16 hex chars>
console.log(alice.publicKeyHex); // 64 hex chars (32 bytes)

const msg = new TextEncoder().encode('hello');
const sig = await alice.sign(msg);
const ok = await Identity.verify(alice.publicKeyHex, msg, sig);
```

`Identity.generate` produces a random Ed25519 keypair and derives a local
deterministic DID from the public key. `Identity.fromKeypair(...)` rehydrates
an identity from stored material with the same local derivation. Use
`Identity.fromResolvedKeypair(...)` when the canonical DID has already been
resolved from the fabric and must not be re-derived locally.

### 2. Propose a bailment (scoped consent)

```ts
import { BailmentBuilder } from '@exochain/sdk/consent';

const proposal = await new BailmentBuilder(alice.did, bob.did)
  .scope('data:medical')
  .durationHours(24)
  .build();

// proposal.proposalId is a deterministic, content-addressed hash — two
// parties independently building the same proposal get the same id.
```

### 3. Propose a decision, cast votes, check quorum

```ts
import { DecisionBuilder, Vote, VoteChoice } from '@exochain/sdk/governance';

const decision = await new DecisionBuilder({
  title: 'Ratify change X',
  description: 'Enable feature flag Y for cohort Z',
  proposer: alice.did,
}).build();

decision.castVote(new Vote({ voter: bob.did, choice: VoteChoice.Approve }));
decision.castVote(new Vote({ voter: carol.did, choice: VoteChoice.Approve }));

const quorum = decision.checkQuorum(2);
// { met: true, threshold: 2, approvals: 2, rejections: 0, abstentions: 0, ... }
```

The same voter may cast at most one vote on a decision; a second `castVote`
from the same voter throws `GovernanceError`.

### 4. Build and verify an authority chain

```ts
import { AuthorityChainBuilder } from '@exochain/sdk/authority';

const chain = new AuthorityChainBuilder()
  .addLink(root.did, alice.did, ['delegate'])
  .addLink(alice.did, bob.did, ['read'])
  .build(bob.did); // throws AuthorityError if the chain is broken

console.log(chain.depth); // 2
```

Topology rules: each link's `grantee` must match the next link's `grantor`,
and the final `grantee` must equal the `terminal` you pass to `build`.

### 5. Talk to a constitutional kernel via the gateway

The SDK ships an HTTP client for talking to a running `exo-gateway`. Kernel
adjudication happens server-side and results are returned as verdicts:

```ts
import { ExochainClient } from '@exochain/sdk';

const client = new ExochainClient({
  baseUrl: 'https://gateway.example.com',
  apiKey: process.env.EXOCHAIN_API_KEY,
});

const health = await client.health();
const resolved = await client.identity.resolve(alice.did);
```

## API surface

Each domain is available either from the package root or from a named subpath
export:

| Subpath                    | Exports                                                |
| -------------------------- | ------------------------------------------------------ |
| `@exochain/sdk`            | Everything — `ExochainClient`, all domain primitives   |
| `@exochain/sdk/identity`   | `Identity`, `validateDid`, `isDid`, `deriveDid`        |
| `@exochain/sdk/consent`    | `BailmentBuilder`, `BailmentProposal`                  |
| `@exochain/sdk/governance` | `Decision`, `DecisionBuilder`, `Vote`, `VoteChoice`    |
| `@exochain/sdk/authority`  | `AuthorityChainBuilder`, `ChainLink`, `ValidatedChain` |
| `@exochain/sdk/crypto`     | `sha256`, `sha256Hex`, `sha256Hash`, hex helpers       |

## Branded types

`Did` and `Hash256` are **branded string types**. A branded type is a string at
runtime but carries a compile-time tag that prevents arbitrary strings from
being accidentally passed where a validated DID or hash is expected:

```ts
import { Did, validateDid } from '@exochain/sdk/identity';

function send(to: Did): void { /* … */ }

// Compile error — a plain string is not a Did.
// send('did:exo:abc');

// OK — validateDid throws IdentityError on invalid input and returns Did.
send(validateDid('did:exo:deadbeefcafebabe'));
```

Use `validateDid(s)` at the boundary of untrusted input (HTTP payloads,
command-line arguments, user input). Inside your own code, keep the `Did`
brand end-to-end so the compiler catches accidental stringification.

`isDid(s)` is the non-throwing predicate variant for control-flow narrowing.

## HttpTransport

`HttpTransport` is the low-level fetch-based transport used by
`ExochainClient`. Reach for it directly when you need to override request
behavior (headers, timeouts, retries) or talk to endpoints the top-level
client has not yet wrapped.

```ts
import { HttpTransport } from '@exochain/sdk';

const transport = new HttpTransport({
  baseUrl: 'https://gateway.example.com',
  apiKey: process.env.EXOCHAIN_API_KEY,
  defaultHeaders: { 'X-Tenant': 'acme' },
  fetch: globalThis.fetch, // inject a custom fetch (e.g. undici, msw)
});

const res = await transport.request<{ version: string }>('GET', '/health');
```

`ExochainClient` wraps `HttpTransport` and exposes per-domain resources
(`client.identity.resolve`, `client.consent.propose`, etc.). Prefer the
client for normal use; drop down to `HttpTransport` only when you need raw
control.

## Browser vs Node considerations

| Concern                     | Node 20+                                                     | Browsers                                                     |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Ed25519 sign / verify       | Stable since Node 20 via Web Crypto.                         | Chromium, Safari 17+, Firefox 130+.                          |
| SHA-256                     | Web Crypto.                                                  | Web Crypto.                                                  |
| Random bytes                | `globalThis.crypto.getRandomValues`.                         | Same.                                                        |
| Secret key storage          | Your code's responsibility — keep out of process memory.     | Same — prefer `CryptoKey` (non-extractable) when possible.   |
| HTTP transport              | Built-in `fetch`.                                            | Built-in `fetch`.                                            |
| Bundle size                 | Tree-shakeable subpath exports.                              | Same.                                                        |

The SDK does not ship polyfills. If you need to support older runtimes, pin a
known-good runtime (for example in a Docker image), or apply your own
polyfills at the application boundary.

## Cross-language interop

EXOCHAIN ships three first-party SDKs that share the same model and wire
format:

- **Rust** — `crates/exochain-sdk`. The reference implementation; uses
  **BLAKE3** for hashing and DID derivation.
- **TypeScript** (this package).
- **Python** — `packages/exochain-py`, published as `exochain` on PyPI.

Local TypeScript SDK identities derive DIDs as:

```
did:exo: + first 16 hex chars of SHA-256(raw public key bytes)
```

because Web Crypto does not ship BLAKE3. **DIDs produced by local TypeScript
derivation will not match local DIDs produced by the Rust SDK for the same
keypair.** Applications that need canonical DIDs across SDKs should obtain the
canonical DID from the fabric (via `exo-gateway` or another DID-document
resolver) and construct the signing handle with `Identity.fromResolvedKeypair`.
That constructor preserves the fabric DID and verifies that the private key
matches the supplied public key before returning an identity.

```ts
const identity = await Identity.fromResolvedKeypair({
  label: 'alice',
  did: fabricResolvedDid,
  publicKeyHex,
  privateKeyPkcs8,
});
```

Bailment IDs, decision IDs, and chain identifiers are also hashed with
SHA-256 in this SDK and BLAKE3 in Rust, for the same reason. All three SDKs
agree on the *field layout* — so JSON round-trips work seamlessly — but not
on the hash digest of the serialized fields.

## Errors

All SDK errors extend `ExochainError`:

- `IdentityError` — invalid DID, key-material problem.
- `ConsentError` — bailment validation failure.
- `GovernanceError` — decision/vote validation failure (e.g. duplicate voter).
- `AuthorityError` — authority chain topology failure.
- `KernelError` — reserved for constitutional kernel adjudication errors.
- `CryptoError` — cryptographic operation failure.
- `TransportError` — HTTP/transport-layer failure.

Discriminate with `instanceof` rather than string matching:

```ts
import { BailmentBuilder, ConsentError } from '@exochain/sdk';

try {
  await new BailmentBuilder(alice.did, bob.did).build();
} catch (err) {
  if (err instanceof ConsentError) {
    // scope / duration missing — tell the user
  }
  throw err;
}
```

## Relation to the MCP server

The EXOCHAIN stack also ships an MCP (Model Context Protocol) server at
`exo-node` for use with AI agents. The SDK in this package targets
application developers writing TypeScript clients that speak directly to the
gateway; the MCP server is the bridge for AI agents that want constitutional
governance as tool-use.

When integrating with the MCP server, this SDK's types serve as the canonical
TypeScript representation of the objects the MCP server accepts and returns.

## Development

```bash
npm install
npm run build  # TypeScript compile to dist/
npm test       # compile tests and run with node --test
npm run lint   # tsc --noEmit
```

## Related

- **Rust SDK** — `crates/exochain-sdk` in the EXOCHAIN monorepo.
- **Python SDK** — `packages/exochain-py`, published as
  [`exochain`](https://pypi.org/project/exochain/) on PyPI.
- **MCP server** — `exo-node`, for LLM agent integration.

## License

Apache-2.0 — see `LICENSE` at the repository root.
