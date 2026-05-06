---
title: "TypeScript SDK Quickstart"
status: active
created: 2026-04-15
tags: [exochain, sdk, typescript, javascript, nodejs, quickstart, guide]
---

# TypeScript SDK Quickstart

**Get productive with `@exochain/sdk` on Node 20+ or a modern browser in ten minutes.**

The TypeScript SDK is a dependency-free pure-JS port of the canonical Rust SDK. It mirrors the same five domain APIs (identity, consent, governance, authority, crypto) plus an `HttpTransport` for talking to an `exo-gateway`.

---

## Table of Contents

- [Installation](#installation)
- [Runtime requirements](#runtime-requirements)
- [Hashing difference you must know](#hashing-difference-you-must-know)
- [Branded types: `Did`, `Hash256`](#branded-types-did-hash256)
- [Domain 1: Identity](#domain-1-identity)
- [Domain 2: Consent (bailments)](#domain-2-consent-bailments)
- [Domain 3: Governance (decisions + voting)](#domain-3-governance-decisions--voting)
- [Domain 4: Authority chains](#domain-4-authority-chains)
- [Domain 5: Crypto primitives](#domain-5-crypto-primitives)
- [Transport: talking to `exo-gateway`](#transport-talking-to-exo-gateway)
- [Error handling](#error-handling)
- [Browser vs Node](#browser-vs-node)
- [End-to-end example](#end-to-end-example)
- [What next](#what-next)

---

## Installation

### npm (once published)

```bash
npm install @exochain/sdk
```

### Local path during development

From inside the monorepo, consume the package directly:

```bash
cd packages/exochain-sdk
npm run build

# in your app
npm install ../../packages/exochain-sdk
```

Then in your app:

```ts
import { Identity } from '@exochain/sdk';
```

---

## Runtime requirements

| Requirement | Why |
|---|---|
| **Node 20+** (or modern browser) | Web Crypto `Ed25519` is natively available. |
| **ESM modules** (`"type": "module"`) | The package ships ES modules only (see `packages/exochain-sdk/package.json`). |
| **TypeScript 5.3+** | Branded types require modern TS. |

Verify your install:

```ts
// hello.ts
import { Identity } from '@exochain/sdk';

async function main() {
  const id = await Identity.generate('hello');
  console.log('DID:', id.did);
}
main();
```

```text
$ node --loader ts-node/esm hello.ts
DID: did:exo:a1b2c3d4e5f60789
```

---

## Hashing difference you must know

**The pure-JS SDK hashes with SHA-256. The Rust SDK hashes with BLAKE3.**

Why: BLAKE3 is not part of Web Crypto, so shipping a BLAKE3 implementation would require a ~150 kB WASM blob or a third-party pure-JS BLAKE3 package. The pure-JS SDK keeps zero runtime dependencies, so content-addressed IDs produced client-side (proposal IDs, decision IDs) do **not** match Rust-produced IDs byte-for-byte.

For cross-language interop in production:

- **Prefer** producing canonical hashes server-side (Rust) and trusting the returned `Hash256` from the gateway.
- **If you must hash identically in JS**, build with a BLAKE3 WASM shim that matches the Rust output. This is a deliberate non-default.
- **For a TS-only app**, SHA-256 is fine — the SDK is internally consistent.

The branded `Hash256` type is the same shape either way: a 64-character lowercase hex string.

See [`packages/exochain-sdk/src/crypto/hash.ts`](../../packages/exochain-sdk/src/crypto/hash.ts) for the full rationale in-source.

---

## Branded types: `Did`, `Hash256`

These are structural brands — no runtime tag, validated at the boundary:

```ts
import { validateDid, isDid } from '@exochain/sdk';

const d1 = validateDid('did:exo:alice');  // Did, or throws IdentityError
const d2: boolean = isDid('did:exo:bob');  // true

// This will throw IdentityError:
// validateDid('bad-did');
```

`Hash256` is produced by `sha256Hash` (branded) or `sha256Hex` (plain string):

```ts
import { sha256Hash, sha256Hex } from '@exochain/sdk';

const hash: string = await sha256Hex(new Uint8Array([1, 2, 3]));
// -> 64-char lowercase hex
```

Once you have a `Did` or `Hash256`, TypeScript will refuse to let you pass a plain `string` in its place — you must go through `validateDid` or the hash factory first.

---

## Domain 1: Identity

`Identity` wraps an Ed25519 keypair from Web Crypto. Keys never leave the object.

### Generate, sign, verify

```ts
import { Identity } from '@exochain/sdk';

async function main() {
  const alice = await Identity.generate('alice');
  console.log('alice.did         =', alice.did);
  console.log('alice.publicKeyHex=', alice.publicKeyHex);

  const msg = new TextEncoder().encode('I, Alice, consent.');
  const sig = await alice.sign(msg);

  console.log('verifySelf =', await alice.verifySelf(msg, sig));

  // Verify with a detached public key (same result here):
  console.log(
    'Identity.verify =',
    await Identity.verify(alice.publicKeyHex, msg, sig),
  );
}
main();
```

Expected output:

```text
alice.did         = did:exo:b7c14e2f8a3d1f90
alice.publicKeyHex= 1aef...  (64 hex chars)
verifySelf = true
Identity.verify = true
```

### DID derivation

The pure-JS SDK derives a DID as `did:exo:<first 16 hex chars of SHA-256(public_key_bytes)>`. This is stable within the TS SDK but does not match the Rust derivation (which uses BLAKE3). If you need the Rust-canonical DID, receive it from the server after submitting the public key, or use a BLAKE3 WASM shim.

### Rebuild from stored material

```ts
import { Identity } from '@exochain/sdk';

// `privateKeyPkcs8` is a 48-byte PKCS#8-encoded Ed25519 private key.
const id = await Identity.fromKeypair({
  label: 'restored',
  publicKeyHex: '1aef...',                    // 64 hex chars
  privateKeyPkcs8: new Uint8Array([/* ... */]),
});
```

---

## Domain 2: Consent (bailments)

A `BailmentBuilder` produces a frozen `BailmentProposal` with a deterministic `proposalId` (SHA-256 over canonical fields).

### Build a proposal

```ts
import { BailmentBuilder, validateDid } from '@exochain/sdk';

async function main() {
  const bailor = validateDid('did:exo:alice');
  const bailee = validateDid('did:exo:bob');

  const proposal = await new BailmentBuilder(bailor, bailee)
    .scope('data:medical:records')
    .durationHours(24)
    .build();

  console.log('proposalId    =', proposal.proposalId);
  console.log('bailor        =', proposal.bailor);
  console.log('bailee        =', proposal.bailee);
  console.log('scope         =', proposal.scope);
  console.log('durationHours =', proposal.durationHours);
  console.log('createdAt     =', new Date(proposal.createdAt).toISOString());
}
main();
```

### What fails

| Failure | Error |
|---|---|
| `scope` not set | `ConsentError: scope is required` |
| `scope === ''` | `ConsentError: scope must be non-empty` |
| `durationHours` not set | `ConsentError: durationHours is required` |
| `durationHours <= 0` | `ConsentError: durationHours must be > 0` |
| non-integer `durationHours` | `ConsentError: durationHours must be an integer` |

You can pass DID arguments as either a validated `Did` brand or a raw `string`; the builder validates on construction.

---

## Domain 3: Governance (decisions + voting)

### Create a decision

```ts
import { DecisionBuilder, validateDid } from '@exochain/sdk';

async function main() {
  const proposer = validateDid('did:exo:alice');

  const decision = await new DecisionBuilder({
    title: 'Raise quorum threshold to 3/4',
    description: 'Constitutional amendment.',
    proposer,
  })
    .decisionClass('amendment')
    .build();

  console.log('decisionId =', decision.decisionId);
  console.log('status     =', decision.status);
  console.log('class      =', decision.class);
}
main();
```

Expected output:

```text
decisionId = 9f3c2a1b8d7e6f45...
status     = proposed
class      = amendment
```

### Cast votes, check quorum

```ts
import { DecisionBuilder, Vote, VoteChoice, validateDid } from '@exochain/sdk';

async function main() {
  const proposer = validateDid('did:exo:alice');
  const decision = await new DecisionBuilder({
    title: 't',
    description: 'd',
    proposer,
  }).build();

  decision.castVote(new Vote({
    voter: validateDid('did:exo:v1'),
    choice: VoteChoice.Approve,
  }));
  decision.castVote(new Vote({
    voter: validateDid('did:exo:v2'),
    choice: VoteChoice.Approve,
    rationale: 'LGTM',
  }));
  decision.castVote(new Vote({
    voter: validateDid('did:exo:v3'),
    choice: VoteChoice.Reject,
  }));

  const q = decision.checkQuorum(2);
  console.log(q);
  // { met: true, threshold: 2, totalVotes: 3,
  //   approvals: 2, rejections: 1, abstentions: 0 }
}
main();
```

### Duplicate voters are rejected

```ts
import { GovernanceError } from '@exochain/sdk';

try {
  decision.castVote(new Vote({
    voter: validateDid('did:exo:v1'),
    choice: VoteChoice.Reject,
  }));
} catch (err) {
  if (err instanceof GovernanceError) {
    console.error('governance:', err.message);
  }
}
```

---

## Domain 4: Authority chains

```ts
import { AuthorityChainBuilder, validateDid } from '@exochain/sdk';

const root = validateDid('did:exo:root');
const mid  = validateDid('did:exo:mid');
const leaf = validateDid('did:exo:leaf');

const chain = new AuthorityChainBuilder()
  .addLink(root, mid,  ['read'])
  .addLink(mid,  leaf, ['read', 'write'])
  .build(leaf);

console.log('depth    =', chain.depth);
console.log('terminal =', chain.terminal);
chain.links.forEach((l, i) => {
  console.log(`  link[${i}]: ${l.grantor} -> ${l.grantee} [${l.permissions.join(', ')}]`);
});
```

Expected output:

```text
depth    = 2
terminal = did:exo:leaf
  link[0]: did:exo:root -> did:exo:mid [read]
  link[1]: did:exo:mid -> did:exo:leaf [read, write]
```

### Validation rules

Same as the Rust SDK: non-empty, consecutive grantees must match next grantor, and the last grantee must equal `terminalActor`. Violations throw `AuthorityError`.

---

## Domain 5: Crypto primitives

```ts
import { sha256, sha256Hex, sha256Hash, bytesToHex, hexToBytes } from '@exochain/sdk';

const raw = await sha256(new TextEncoder().encode('hello'));   // Uint8Array(32)
const hex = await sha256Hex(new TextEncoder().encode('hello')); // string (64 chars)
const h256 = await sha256Hash(new TextEncoder().encode('hello')); // branded Hash256

console.log(bytesToHex(raw) === hex);   // true
console.log(hexToBytes(hex).length);     // 32
```

All hash functions are pure `async` — they await `crypto.subtle.digest` under the hood.

---

## Transport: talking to `exo-gateway`

### `HttpTransport` (low-level)

```ts
import { HttpTransport } from '@exochain/sdk';

const transport = new HttpTransport('http://127.0.0.1:8080', {
  apiKey: process.env.EXO_API_KEY,    // sent as Authorization: Bearer
  timeout: 15_000,                     // ms
});

const health = await transport.get('/health');
console.log(health);
```

Low-level transport methods return `unknown`; prefer `ExochainClient` for
validated domain responses, or validate raw transport payloads before trusting
fields.

### `ExochainClient` (high-level)

The high-level `ExochainClient` groups per-domain calls and returns typed responses:

```ts
import { ExochainClient } from '@exochain/sdk';

const client = new ExochainClient({
  baseUrl: 'http://127.0.0.1:8080',
  apiKey: process.env.EXO_API_KEY,
  timeout: 15_000,
});

// Health
console.log(await client.health());

// Identity
const doc = await client.identity.resolve('did:exo:alice' as any);

// Consent
const { proposalId } = await client.consent.proposeBailment({
  bailor: 'did:exo:alice',
  bailee: 'did:exo:bob',
  scope: 'data:medical',
  durationHours: 24,
});

// Governance
const { decisionId } = await client.governance.createDecision({
  title: 'Fund X',
  description: 'Allocate budget.',
  proposer: 'did:exo:alice',
});
await client.governance.castVote(decisionId, {
  voter: 'did:exo:v1',
  choice: 'approve',
});
```

Typed client methods validate gateway response shapes before returning branded
`Did`, `Hash256`, quorum, and economy anchor values. Mutating calls must receive
a JSON object body; the SDK rejects arrays, primitives, functions, cycles, and
non-finite numbers before sending the request.

All transport errors surface as `TransportError` (see next section).

---

## Error handling

```ts
import {
  ExochainError,
  IdentityError,
  ConsentError,
  GovernanceError,
  AuthorityError,
  CryptoError,
  TransportError,
  KernelError,
} from '@exochain/sdk';

try {
  const id = await Identity.generate('example');
  // ...
} catch (err) {
  if (err instanceof IdentityError) {
    console.error('identity:', err.message);
  } else if (err instanceof TransportError) {
    console.error(`transport (HTTP ${err.status ?? '?'}):`, err.message);
    if (err.body) console.error('body:', err.body);
  } else if (err instanceof ExochainError) {
    console.error(err.name, err.message);
  } else {
    throw err;
  }
}
```

All SDK error classes derive from `ExochainError`. `TransportError` additionally carries `status?: number` and `body?: string` when the gateway returned a non-2xx response.

---

## Browser vs Node

| Concern | Node 20+ | Modern browser |
|---|---|---|
| `globalThis.crypto` | built-in since Node 19 | built-in |
| `globalThis.fetch` | built-in since Node 18 | built-in |
| Ed25519 via Web Crypto | supported since Node 20 | supported in Chrome 113+, Safari 17+, Firefox 128+ |
| ESM only | works with `"type": "module"` | works natively |
| TypeScript | compile with `tsc` | compile with your bundler |

The SDK throws `IdentityError` / `CryptoError` at construction time if Web Crypto is unavailable, so misconfiguration fails loud.

### Browser example (HTML)

```html
<!doctype html>
<html>
  <body>
    <script type="module">
      import { Identity, sha256Hex } from 'https://esm.sh/@exochain/sdk';
      const id = await Identity.generate('browser-alice');
      document.body.textContent = `DID: ${id.did}`;
      console.log('hash of empty string:', await sha256Hex(new Uint8Array()));
    </script>
  </body>
</html>
```

### Node ESM example

```json
// package.json
{
  "type": "module",
  "dependencies": { "@exochain/sdk": "^0.1.0" }
}
```

```ts
// index.ts
import { Identity } from '@exochain/sdk';
const id = await Identity.generate('node-alice');
console.log(id.did);
```

---

## End-to-end example

```ts
import {
  Identity,
  BailmentBuilder,
  DecisionBuilder,
  Vote,
  VoteChoice,
  AuthorityChainBuilder,
  validateDid,
  ExochainError,
} from '@exochain/sdk';

async function main() {
  try {
    // 1. Identities.
    const alice = await Identity.generate('alice');
    const bob   = await Identity.generate('bob');
    console.log('alice =', alice.did);
    console.log('bob   =', bob.did);

    // 2. Bailment: Alice grants Bob 24h of medical read.
    const proposal = await new BailmentBuilder(alice.did, bob.did)
      .scope('data:medical:records')
      .durationHours(24)
      .build();
    console.log('bailment proposal', proposal.proposalId);

    // 3. Decision.
    const decision = await new DecisionBuilder({
      title: 'Expand Bob\'s read scope to imaging',
      description: 'Access request for imaging.',
      proposer: alice.did,
    })
      .decisionClass('scope-expansion')
      .build();

    // 4. Three validator votes.
    for (const [i, choice] of [
      VoteChoice.Approve,
      VoteChoice.Approve,
      VoteChoice.Reject,
    ].entries()) {
      decision.castVote(new Vote({
        voter: validateDid(`did:exo:v${i}`),
        choice,
      }));
    }
    const q = decision.checkQuorum(2);
    console.log(`quorum met = ${q.met} (${q.approvals}/${q.totalVotes} approvals)`);

    // 5. Authority chain root -> alice -> bob.
    const chain = new AuthorityChainBuilder()
      .addLink('did:exo:root', alice.did, ['read', 'delegate'])
      .addLink(alice.did,      bob.did,   ['read'])
      .build(bob.did);
    console.log('chain depth =', chain.depth);
  } catch (err) {
    if (err instanceof ExochainError) {
      console.error(`[${err.name}]`, err.message);
      process.exit(1);
    }
    throw err;
  }
}

main();
```

---

## What next

- **Rust SDK** — [`docs/guides/sdk-quickstart-rust.md`](./sdk-quickstart-rust.md). Canonical implementation.
- **Python SDK** — [`docs/guides/sdk-quickstart-python.md`](./sdk-quickstart-python.md). Pydantic + asyncio.
- **MCP integration** — [`docs/guides/mcp-integration.md`](./mcp-integration.md). Connecting Claude to the fabric.
- **Getting Started** — [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md).
- **Source** — [`packages/exochain-sdk/src/`](../../packages/exochain-sdk/src/).
- **package.json** — [`packages/exochain-sdk/package.json`](../../packages/exochain-sdk/package.json).

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
