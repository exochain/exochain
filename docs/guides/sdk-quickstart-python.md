---
title: "Python SDK Quickstart"
status: active
created: 2026-04-15
tags: [exochain, sdk, python, quickstart, guide]
---
<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->


# Python SDK Quickstart

**Get productive with the `exochain` Python package in ten minutes.**

The Python SDK is a Pydantic v2 + asyncio port of the canonical Rust SDK. Same five domains (identity, consent, governance, authority, crypto), async transport to `exo-gateway`, frozen data classes where appropriate.

---

## Table of Contents

- [Installation](#installation)
- [Runtime requirements](#runtime-requirements)
- [Hashing difference you must know](#hashing-difference-you-must-know)
- [Domain 1: Identity](#domain-1-identity)
- [Domain 2: Consent (bailments)](#domain-2-consent-bailments)
- [Domain 3: Governance (decisions + voting)](#domain-3-governance-decisions--voting)
- [Domain 4: Authority chains](#domain-4-authority-chains)
- [Domain 5: Crypto primitives](#domain-5-crypto-primitives)
- [Transport + `ExochainClient`](#transport--exochainclient)
- [Error handling](#error-handling)
- [End-to-end example](#end-to-end-example)
- [What next](#what-next)

---

## Installation

### pip (once published)

```bash
pip install exochain
```

### Local editable install during development

From inside the monorepo:

```bash
cd packages/exochain-py
pip install -e '.[dev]'
```

Then:

```bash
$ python -c "from exochain import Identity; print(Identity.generate('hello').did)"
did:exo:a1b2c3d4e5f60789
```

### Dependencies

The package depends on:

| Package | Minimum | Why |
|---|---|---|
| `cryptography` | 42.0.0 | Ed25519 primitives |
| `pydantic` | 2.5.0 | Frozen data models |
| `httpx` | 0.25.0 | Async HTTP transport |

Dev extras add `pytest`, `pytest-asyncio`, `mypy`, and `ruff`.

---

## Runtime requirements

- **Python 3.11+** (the package uses `StrEnum` and modern type syntax).
- **`asyncio`** for the transport (`ExochainClient`, `HttpTransport`).

Verify your install:

```python
# hello.py
from exochain import Identity

alice = Identity.generate("alice")
print("DID:", alice.did)
```

```text
$ python hello.py
DID: did:exo:a1b2c3d4e5f60789
```

---

## Hashing difference you must know

Like the TypeScript SDK, the Python SDK uses **SHA-256** for client-side content-addressed IDs (proposal IDs, decision IDs). The Rust SDK uses **BLAKE3**. Client-derived IDs in Python therefore will not match Rust-derived IDs byte-for-byte. For cross-language interop:

- Trust IDs returned by the gateway (the gateway is Rust).
- Or use the full 64-character SHA-256 hex on the Python side, 16-hex prefix of BLAKE3 on the Rust side — they are canonically different namespaces, not lossy round-trips.

See [`packages/exochain-py/exochain/crypto/hash.py`](../../packages/exochain-py/exochain/crypto/hash.py) and [`packages/exochain-py/exochain/consent/bailment.py`](../../packages/exochain-py/exochain/consent/bailment.py) for the exact canonicalization.

---

## Domain 1: Identity

`Identity` wraps an Ed25519 keypair from the `cryptography` package. The private key is hidden from `repr`.

### Generate, sign, verify

```python
from exochain import Identity

alice = Identity.generate("alice")
print("alice.did             =", alice.did)
print("alice.public_key_hex  =", alice.public_key_hex)
print("alice.label           =", alice.label)

msg = b"I, Alice, consent."
sig = alice.sign(msg)

assert Identity.verify(alice.public_key_hex, msg, sig) is True
assert Identity.verify(alice.public_key_hex, b"tampered", sig) is False
```

Expected output:

```text
alice.did             = did:exo:b7c14e2f8a3d1f90
alice.public_key_hex  = 1aef... (64 hex chars)
alice.label           = alice
```

### DID validation

```python
from exochain import validate_did, is_did
from exochain import IdentityError

d1 = validate_did("did:exo:alice")  # returns the string
assert is_did("did:exo:alice") is True
assert is_did("bad-did") is False

try:
    validate_did("oops")
except IdentityError as e:
    print("invalid:", e)
```

---

## Domain 2: Consent (bailments)

### Build a proposal

```python
from exochain import BailmentBuilder

proposal = (
    BailmentBuilder("did:exo:alice", "did:exo:bob")
    .scope("data:medical:records")
    .duration_hours(24)
    .build()
)

print("proposal_id    =", proposal.proposal_id)
print("bailor         =", proposal.bailor)
print("bailee         =", proposal.bailee)
print("scope          =", proposal.scope)
print("duration_hours =", proposal.duration_hours)
```

`BailmentProposal` is a frozen Pydantic model — safe to pass around, hash into dict keys, and serialize with `proposal.model_dump_json()`.

### What fails

| Failure | Error |
|---|---|
| `scope` not set | `ConsentError: scope is required` |
| empty / whitespace scope | `ConsentError: scope cannot be empty` |
| `duration_hours <= 0` | `ConsentError: duration_hours must be a positive integer` |
| non-int `duration_hours` | `ConsentError: duration_hours must be a positive integer` |

---

## Domain 3: Governance (decisions + voting)

### Create a decision

```python
from exochain import DecisionBuilder, DecisionStatus

decision = (
    DecisionBuilder(
        title="Raise quorum threshold to 3/4",
        description="Constitutional amendment.",
        proposer="did:exo:alice",
    )
    .decision_class("amendment")
    .build()
)

print("decision_id    =", decision.decision_id)
print("status         =", decision.status)              # DecisionStatus.PROPOSED
print("decision_class =", decision.decision_class)
assert decision.status == DecisionStatus.PROPOSED
```

### Cast votes, check quorum

```python
from exochain import DecisionBuilder, Vote, VoteChoice

decision = DecisionBuilder("t", "d", "did:exo:alice").build()

decision.cast_vote(Vote(voter="did:exo:v1", choice=VoteChoice.APPROVE))
decision.cast_vote(Vote(voter="did:exo:v2", choice=VoteChoice.APPROVE, rationale="LGTM"))
decision.cast_vote(Vote(voter="did:exo:v3", choice=VoteChoice.REJECT))

quorum = decision.check_quorum(threshold=2)
print(quorum)
# met=True threshold=2 total_votes=3 approvals=2 rejections=1 abstentions=0
```

### Duplicate voters are rejected

```python
from exochain import GovernanceError

try:
    decision.cast_vote(Vote(voter="did:exo:v1", choice=VoteChoice.REJECT))
except GovernanceError as e:
    print("governance:", e)
```

`Vote` is frozen; use the constructor to build a new one with a rationale.

---

## Domain 4: Authority chains

```python
from exochain import AuthorityChainBuilder

chain = (
    AuthorityChainBuilder()
    .add_link("did:exo:root", "did:exo:mid",  ["read"])
    .add_link("did:exo:mid",  "did:exo:leaf", ["read", "write"])
    .build(terminal_actor="did:exo:leaf")
)

print("depth    =", chain.depth)
print("terminal =", chain.terminal)
for i, link in enumerate(chain.links):
    print(f"  link[{i}]: {link.grantor} -> {link.grantee} {link.permissions}")
```

Expected output:

```text
depth    = 2
terminal = did:exo:leaf
  link[0]: did:exo:root -> did:exo:mid ['read']
  link[1]: did:exo:mid -> did:exo:leaf ['read', 'write']
```

### Validation rules

Same rules as the Rust and TypeScript SDKs:

| Rule | Violation | Raises |
|---|---|---|
| At least one link | `.build(...)` on empty builder | `AuthorityError("authority chain is empty")` |
| Consecutive links connect | `links[i].grantee != links[i+1].grantor` | `AuthorityError("broken delegation: X != Y")` |
| Final grantee matches terminal | `last.grantee != terminal_actor` | `AuthorityError("terminal mismatch: ...")` |

---

## Domain 5: Crypto primitives

```python
from exochain import sha256, sha256_hex

raw = sha256(b"hello")            # bytes(32)
hex_digest = sha256_hex(b"hello") # str (64 lowercase hex chars)

assert len(raw) == 32
assert len(hex_digest) == 64
assert raw.hex() == hex_digest
```

---

## Transport + `ExochainClient`

The SDK's async transport talks to an `exo-gateway` over HTTPS. The high-level `ExochainClient` handles serialization, typed errors, and resource lifecycle.

### `HttpTransport` (low-level)

```python
import asyncio
from exochain import HttpTransport

async def main():
    async with HttpTransport("http://127.0.0.1:8080", timeout=15.0) as t:
        health = await t.get("/health")
        print(health)  # dict with keys: status, version, uptime

asyncio.run(main())
```

### `ExochainClient` (high-level)

```python
import asyncio
import os
from exochain import ExochainClient

async def main():
    async with ExochainClient(
        "http://127.0.0.1:8080",
        api_key=os.environ.get("EXO_API_KEY"),
        timeout=15.0,
    ) as client:
        # Health probe
        print(await client.health())

        # Resolve a DID
        doc = await client.resolve_did("did:exo:alice")
        print("doc:", doc)

        # Submit a bailment
        bailment = await client.submit_bailment({
            "bailor": "did:exo:alice",
            "bailee": "did:exo:bob",
            "scope": "data:medical",
            "durationHours": 24,
        })
        print("bailment:", bailment)

        # Create a decision
        decision = await client.submit_decision({
            "title": "Fund X",
            "description": "Allocate budget.",
            "proposer": "did:exo:alice",
        })
        decision_id = decision["decision_id"]

        # Vote
        await client.cast_vote(decision_id, {
            "voter": "did:exo:v1",
            "choice": "approve",
        })

        # Submit a kernel action — returns a TrustReceipt
        receipt = await client.submit_action({
            "actor_did": "did:exo:alice",
            "action_type": "read",
            "payload": {"scope": "data:medical"},
        })
        print("receipt:", receipt.receipt_hash, receipt.outcome)

asyncio.run(main())
```

`TrustReceipt` is a frozen Pydantic model with fields `receipt_hash`, `actor_did`, `action_type`, `outcome` (`"permitted" | "denied" | "escalated"`), and `timestamp_ms`. Malformed server responses raise `KernelError`.

---

## Error handling

All SDK errors derive from `ExochainError`:

```python
from exochain import (
    ExochainError,       # base
    IdentityError,
    ConsentError,
    GovernanceError,
    AuthorityError,
    CryptoError,
    KernelError,
    TransportError,
)

try:
    id = Identity.generate("example")
    # ... call the fabric ...
except IdentityError as e:
    print("identity:", e)
except TransportError as e:
    print("transport:", e)
except ExochainError as e:
    print(e.__class__.__name__, e)
```

Transport failures (HTTP errors, timeouts, malformed JSON) always surface as `TransportError`. Kernel-side rejection surfaces as `KernelError` via `ExochainClient.submit_action`.

---

## End-to-end example

```python
import asyncio
import os

from exochain import (
    AuthorityChainBuilder,
    BailmentBuilder,
    DecisionBuilder,
    ExochainClient,
    ExochainError,
    Identity,
    Vote,
    VoteChoice,
)


async def main() -> None:
    # 1. Identities.
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    print("alice =", alice.did)
    print("bob   =", bob.did)

    # 2. Bailment proposal.
    proposal = (
        BailmentBuilder(alice.did, bob.did)
        .scope("data:medical:records")
        .duration_hours(24)
        .build()
    )
    print("bailment proposal", proposal.proposal_id)

    # 3. Decision.
    decision = (
        DecisionBuilder(
            title="Expand Bob's read scope to imaging",
            description="Access request for imaging.",
            proposer=alice.did,
        )
        .decision_class("scope-expansion")
        .build()
    )

    # 4. Three validators vote.
    for i, choice in enumerate(
        [VoteChoice.APPROVE, VoteChoice.APPROVE, VoteChoice.REJECT]
    ):
        decision.cast_vote(Vote(voter=f"did:exo:v{i}", choice=choice))
    q = decision.check_quorum(2)
    print(f"quorum met = {q.met} ({q.approvals}/{q.total_votes} approvals)")

    # 5. Authority chain root -> alice -> bob.
    chain = (
        AuthorityChainBuilder()
        .add_link("did:exo:root", alice.did, ["read", "delegate"])
        .add_link(alice.did, bob.did, ["read"])
        .build(terminal_actor=bob.did)
    )
    print("chain depth =", chain.depth)

    # 6. (Optional) Talk to a gateway.
    gateway_url = os.environ.get("EXO_GATEWAY_URL")
    if gateway_url:
        async with ExochainClient(gateway_url) as client:
            print("gateway health:", await client.health())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ExochainError as e:
        print(f"[{type(e).__name__}] {e}")
        raise SystemExit(1)
```

Expected local output (without `EXO_GATEWAY_URL`):

```text
alice = did:exo:d9c21e4b7f1a8035
bob   = did:exo:a0314e8c7f9b2d11
bailment proposal 4f2a910b8c6d7e0815a233f871cbd9af4ae2f31b0d92c6e5b718dcf4a0183e7f
quorum met = True (2/3 approvals)
chain depth = 2
```

---

## What next

- **Rust SDK** — [`docs/guides/sdk-quickstart-rust.md`](./sdk-quickstart-rust.md). Canonical reference implementation.
- **TypeScript SDK** — [`docs/guides/sdk-quickstart-typescript.md`](./sdk-quickstart-typescript.md). Browser + Node.
- **MCP integration** — [`docs/guides/mcp-integration.md`](./mcp-integration.md). Wire Claude to the fabric.
- **Getting Started** — [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md).
- **Source** — [`packages/exochain-py/exochain/`](../../packages/exochain-py/exochain/).
- **pyproject.toml** — [`packages/exochain-py/pyproject.toml`](../../packages/exochain-py/pyproject.toml).

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
