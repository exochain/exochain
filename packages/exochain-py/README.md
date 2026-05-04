# exochain — Python SDK

`exochain` is the Python SDK for the **EXOCHAIN constitutional governance
fabric** — a substrate for AI agents and data sovereignty built around
DIDs, scoped consent (bailments), authority-chain delegation, and
quorum-based governance decisions.

This is the pure-Python SDK (no native extensions). It uses:

- `cryptography` for Ed25519 signing and SHA-256
- `pydantic` v2 for typed, frozen wire models
- `httpx` for an async HTTP client

Python **3.11+** only.

## Installation

```bash
pip install exochain
```

## Quick start

### Identity — generate a DID-backed Ed25519 keypair

```python
from exochain import Identity

alice = Identity.generate("alice")
print(alice.did)           # did:exo:xxxxxxxxxxxxxxxx

signature = alice.sign(b"hello")
assert Identity.verify(alice.public_key_hex, b"hello", signature)
```

### Consent — build a scoped, time-bounded bailment

```python
from exochain import BailmentBuilder

proposal = (
    BailmentBuilder(alice.did, bob.did)
    .scope("read:medical-records")
    .duration_hours(48)
    .created_at_hlc(1_700_000_000_000, 0)
    .build()
)
print(proposal.proposal_id)   # deterministic SHA-256 id
```

`created_at_hlc(physical_ms, logical)` must come from the caller's deterministic
HLC execution context, such as the gateway or adjudication context. The SDK does
not source timestamps from process wall-clock APIs while building consent
records.

### Governance — propose a decision, cast votes, check quorum

```python
from exochain import DecisionBuilder, Vote, VoteChoice

decision = DecisionBuilder(
    title="Fund Q3 safety initiative",
    description="Allocate 2% of treasury to AI safety research.",
    proposer=alice.did,
).build()

decision.cast_vote(Vote(voter=bob.did, choice=VoteChoice.APPROVE))
decision.cast_vote(Vote(voter=carol.did, choice=VoteChoice.APPROVE))

quorum = decision.check_quorum(threshold=2)
assert quorum.met
```

### Authority — build and validate a delegation chain

```python
from exochain import AuthorityChainBuilder

chain = (
    AuthorityChainBuilder()
    .add_link(root.did, mid.did, ["read", "write"])
    .add_link(mid.did, leaf.did, ["read"])
    .build(leaf.did)
)
print(chain.depth)   # 2
```

### Async client — talk to a fabric endpoint

```python
import asyncio
from exochain import ExochainClient

async def main() -> None:
    async with ExochainClient("https://fabric.example.com", api_key="...") as client:
        health = await client.health()
        print(health)

asyncio.run(main())
```

## API reference

| Domain       | Symbol(s)                                               |
|--------------|---------------------------------------------------------|
| Identity     | `Identity`, `validate_did`, `is_did`                    |
| Consent      | `BailmentBuilder`, `BailmentProposal`, `HlcTimestamp`   |
| Governance   | `DecisionBuilder`, `Decision`, `Vote`, `VoteChoice`     |
| Authority    | `AuthorityChainBuilder`, `ValidatedChain`, `ChainLink`  |
| Crypto       | `sha256`, `sha256_hex`                                  |
| Types        | `Did`, `Hash256Hex`, `TrustReceipt`, `QuorumResult`     |
| Transport    | `HttpTransport`, `ExochainClient`                       |
| Errors       | `ExochainError`, `IdentityError`, `ConsentError`, `GovernanceError`, `AuthorityError`, `KernelError`, `CryptoError`, `TransportError` |

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest              # run tests
mypy exochain       # strict type check
ruff check exochain # lint
```

## Related

- **Rust SDK:** `crates/exochain-sdk` in the EXOCHAIN monorepo
- **TypeScript SDK:** `packages/exochain-sdk`
- **MCP server:** for LLM agent integration

## License

Apache-2.0 © EXOCHAIN Foundation
