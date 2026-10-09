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

# MCP and A2A discovery profile

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Capability C1. Layer: discovery only.

## Standards this profile binds to

| Standard | What this profile uses | What this checkout implements today |
| --- | --- | --- |
| Model Context Protocol | JSON-RPC `initialize` and `tools/list` as the machine-readable tool catalog | `crates/exo-node/src/mcp/handler.rs` advertises `protocol_version` `2024-11-05`, server name `exochain-mcp`. Public MCP transport is off (`ExochainMcpDiscovery.public_transport = false`) |
| A2A Agent Card | `GET /.well-known/agent-card.json` as the well-known discovery document described by the A2A specification | Nothing. No A2A type, route, or card exists in this checkout |
| RFC 8615 | `/.well-known/` location | `GET /.well-known/exochain.json` already served by `exo-gateway` |

External references, for the human reviewers:

- MCP server behavior as implemented: `crates/exo-node/src/mcp/`.
- A2A Agent Card discovery: the A2A specification's Agent Card section,
  <https://github.com/a2aproject/a2a/blob/main/docs/specification.md>, which
  publishes the card at `/.well-known/agent-card.json`. Older drafts used
  `/.well-known/agent.json`. This proposal uses the `agent-card.json` path
  and does not serve a second card at `agent.json` until a decision says to
  alias it.
- Well-known URIs: RFC 8615.

This profile does not claim conformance to a newer MCP revision than
`2024-11-05` until the node advertises that revision.

## Discovery is not authority

A card, a tool list, or an SDK helper that returns successfully has granted
nothing. The response schema fixes `grants_authority` to `false`. Authority
evaluation ignores discovery documents except as untrusted hints about where
to send the next request. A poisoned card can cause a client to talk to the
wrong host. It cannot widen a mandate. Clients pin the expected service DID
and reject cards whose signature does not verify under that DID's already
known key.

## HTTP surface

Existing, unchanged by this proposal's text:

| Method | Path | Role |
| --- | --- | --- |
| GET | `/.well-known/exochain.json` | Public discovery for API, SDK package names, and MCP transport metadata |
| POST | MCP JSON-RPC on the node's existing stdio and loopback-SSE transports | `initialize`, `tools/list` |

Proposed additions, default-off until authorized:

| Method | Path | Role |
| --- | --- | --- |
| GET | `/.well-known/agent-card.json` | A2A Agent Card. Media type `application/json` until an authorized implementation adopts `application/a2a+json` |
| GET | `/.well-known/exochain.json` | Same document, plus optional `commercial_services` entries that point at the card and at the bailment and x402 HTTP paths. Existing fields stay |

The card's preferred interface is HTTP JSON, not a private RPC. The SDK is a
convenience over those HTTP routes. A client that speaks HTTP and verifies
signatures interoperates without the SDK. That is acceptance criterion AC-8.

Proposed card fields are in
[../schemas/discovery-profile.schema.json](../schemas/discovery-profile.schema.json).
Minimum contents:

- `name`, `description`, `version` of the service descriptor;
- `supported_interfaces[0]` with `url`, `protocol_binding = HTTP+JSON`, and
  `protocol_version`;
- `skills` whose ids point at negotiation, authority, settlement, and
  verification HTTP paths;
- `exochain` extension object: service DID, signing key id, schema URI,
  `grants_authority: false`, and the hash of the canonical card bytes.

A2A task methods (`SendMessage`, `GetTask`, and the rest) are not part of
this profile. Negotiation is the bailment protocol. Using A2A tasks as a
second negotiation brain is out of scope, for the same reason v0.3.0 refused
a second x402 brain.

## MCP catalog rule

`tools/list` may advertise a read-only descriptor tool for a commercial
service. The tool returns the same public card bytes. It does not call the
PDP, does not write a bailment, and does not stamp a claim. VCG-004 remains
open: MCP tools are not constitutional runtime actions. A commercial MCP tool
that mutated authority would violate this profile even if a human later
enables the feature.

Existing consent, authority, identity, and ledger MCP tools stay as they are.
This profile does not reclassify them as market settlement.

## SDK rule

`packages/exochain-sdk` and `packages/exochain-py` gain, when authorized,
functions that:

1. GET the well-known documents;
2. verify the service signature on the card;
3. POST later to the bailment and x402 URLs named by the card, using the
   existing HTTP transport and its response-size cap.

They do not embed trust decisions. If the HTTP call fails, times out, or
returns Deny, the SDK returns that failure. It does not synthesize Allow.

LYNK (`packages/exochain-llm-proxy`) is a receipted proxy for LLM calls. A
market service may be *discovered* as a skill that happens to be an LLM
endpoint. The proxy does not become the discovery protocol.

## Signing

The service signs the canonical CBOR of the card under domain
`exo.market.discovery.card.v1`. The JSON document carries the hex signature
and the signer DID. Verification uses the service's already published Ed25519
key. A card that arrives with a new key and no prior pin is untrusted. Key
rotation is an authority-evaluation event, not a discovery event.

## Failure behavior

| Condition | Result |
| --- | --- |
| Card missing or malformed | Client stops. No negotiation |
| Signature invalid | Client stops. No negotiation |
| `grants_authority` absent or not `false` | Client rejects the card |
| MCP transport unconfigured | Structured failure, same family as today's `dagdb_adapter_unconfigured` fail-closed pattern. Discovery does not fall open |
| Tool execution returns a permission | Client discards it. Permissions come only from authority evaluation |
