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

# EXOCHAIN — Rust crates

This directory is the authoritative home of the EXOCHAIN constitutional
governance fabric. Every feature of the fabric — identity, consent, authority
delegation, governance, kernel adjudication, DAG consensus, ZK proofs,
networking, tenancy, legal evidence, escalation — lives here as a workspace
crate.

Application developers should almost always start with
[`exochain-sdk`](./exochain-sdk/), which wraps the underlying crates behind a
single ergonomic API.

## Crate index

| Crate                                       | Purpose                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [`exo-core`](./exo-core/)                   | Foundational deterministic types (DID, Hash256, Signature, Timestamp), HLC, crypto, BCTS.  |
| [`exo-identity`](./exo-identity/)           | Privacy-preserving identity adjudication; DID documents.                                   |
| [`exo-consent`](./exo-consent/)             | Bailment-conditioned consent enforcement — no action without consent.                      |
| [`exo-authority`](./exo-authority/)         | Authority-chain verification and delegation management.                                    |
| [`exo-governance`](./exo-governance/)       | Legislative legitimacy — quorum, clearance, crosscheck, challenge, delegation.             |
| [`exo-gatekeeper`](./exo-gatekeeper/)       | Judicial branch — CGR kernel, combinator algebra, invariants, Holon runtime, MCP middleware. |
| [`exo-escalation`](./exo-escalation/)       | Operational nervous system — detection, triage, kanban, HITL, Sybil adjudication.          |
| [`exo-legal`](./exo-legal/)                 | Litigation-grade evidence, eDiscovery, privilege, fiduciary duty.                          |
| [`exo-messaging`](./exo-messaging/)         | End-to-end encrypted messaging with X25519 key exchange.                                   |
| [`exo-tenant`](./exo-tenant/)               | Multi-tenant isolation, cold storage, sharding.                                            |
| [`exo-dag`](./exo-dag/)                     | Append-only DAG with BFT consensus and Merkle structures.                                  |
| [`exo-proofs`](./exo-proofs/)               | Zero-knowledge proof system — SNARK, STARK, ZKML verifier.                                 |
| [`exo-consensus`](./exo-consensus/)         | Consensus machinery layered on top of the DAG and the legal record.                        |
| [`exo-api`](./exo-api/)                     | P2P networking and external API types.                                                     |
| [`exo-gateway`](./exo-gateway/)             | HTTP gateway server with default-deny pattern.                                             |
| [`exo-node`](./exo-node/)                   | Single-binary distributed node for joining the network.                                    |
| [`exo-catapult`](./exo-catapult/)           | Franchise business incubator with FM 3-05 operational doctrine.                            |
| [`decision-forum`](./decision-forum/)       | Constitutional governance application layer.                                               |
| [`exochain-sdk`](./exochain-sdk/)           | Ergonomic Rust API that wraps the `exo-*` crates behind one surface.                       |
| [`exochain-wasm`](./exochain-wasm/)         | WebAssembly bindings of the full governance engine, consumed by `packages/exochain-wasm`.  |

Seventeen `exo-*` crates plus `decision-forum`, `exochain-sdk`, and
`exochain-wasm` — twenty in total.

## Dependency layering

Crates are organized in roughly four tiers. Arrows point from a crate to
something it depends on.

```text
                             +----------+
                             | exo-core |  <-- foundational types, HLC, crypto
                             +----+-----+
                                  ^
     +----------------+-----------+-----------+---------------+
     |                |                       |               |
+----+-----+    +-----+------+         +------+-----+   +-----+------+
| exo-dag  |    | exo-proofs |         | exo-identity|  | exo-consent|
+----+-----+    +------------+         +------+------+  +-----+------+
     ^                                        ^              ^
     |                                        |              |
     |            +---------------+-----------+--------------+
     |            |               |                          |
     |     +------+------+   +----+--------+            +----+--------+
     |     | exo-authority|   | exo-api    |            | exo-tenant  |
     |     +------+-------+   +------------+            +-------------+
     |            ^
     |            |
     |    +-------+--------+        +------------------+
     |    | exo-governance |        | exo-gatekeeper   |  (depends only on exo-core)
     |    +-------+--------+        +---------+--------+
     |            ^                           ^
     |            +-------------+-------------+
     |                          |
     |                   +------+-------+
     |                   | exo-escalation|
     |                   +--------------+
     |
     |                   +------+-------+     +-----------------+
     +-----------------> | exo-legal   |     | exo-messaging    |
                         +------+-------+     +------------------+
                                ^
              +-----------------+-----------------+
              |                                   |
     +--------+---------+                 +-------+--------+
     | decision-forum   |                 | exo-catapult   |
     +--------+---------+                 +----------------+
              ^
              |
     +--------+---------+
     | exo-consensus    |
     +------------------+

     +------------------+
     | exo-gateway      |  (decision-forum + exo-consent + exo-gatekeeper
     +--------+---------+   + exo-governance + exo-identity + exo-core)
              ^
              |
     +--------+---------+   depends on exo-gateway, exo-gatekeeper,
     | exo-node         |   exo-governance, exo-escalation, exo-consent,
     +------------------+   exo-identity, exo-dag, exo-api, exo-core.
```

Two façade crates sit on top of the whole stack:

- **`exochain-sdk`** — depends on `exo-core`, `exo-identity`, `exo-consent`,
  `exo-authority`, `exo-governance`, `exo-gatekeeper`, `exo-escalation`,
  `exo-legal`, `exo-dag`, and `exo-proofs`. This is the developer-facing
  entrypoint.
- **`exochain-wasm`** — depends on every `exo-*` crate plus `decision-forum`;
  compiles the full engine to WebAssembly for use from Node.js.

## Build and test

Run from the repository root:

```bash
# Build every crate.
cargo build --workspace

# Run all tests (unit + integration + doctests).
cargo test --workspace

# Doctests only.
cargo test --doc --workspace

# Clippy at workspace lint level.
cargo clippy --workspace --all-targets -- -D warnings

# Docs with broken-intra-doc-link enforcement.
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --workspace --no-deps
```

The workspace `MSRV` and `edition` are set in the top-level `Cargo.toml` and
inherited by every crate.

## Non-Rust SDKs

The TypeScript and Python client SDKs — plus the precompiled WebAssembly
artifact — live in [`../packages`](../packages). See
[`../packages/README.md`](../packages/README.md) for which one to reach for.

## License

Each crate is licensed under **Apache-2.0**. See the top-level
[`LICENSE`](../LICENSE) for the full text.
