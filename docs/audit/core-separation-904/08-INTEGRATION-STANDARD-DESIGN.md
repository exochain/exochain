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

# Part 8: Proposed integration standard (design)

**Status: PROPOSAL. Not reviewed by any panel. Not adopted. Decides nothing.**

This record is not one of issue #904's deliverables. It answers a question
part 7 left open: once the core is its own repository, how does a tool, a
product or another system connect to it? It proposes a template an
integrator fills in and a set of conformance levels an integration can be
tested against. It is written for two readers: the panels that would have
to adopt it, and a team (ours or an outside one) that wants to build
toward it.

Every rule, principle and level below is proposed text. Where a sentence
reads as a rule, read "this record proposes that".

## What this record does and does not establish

It establishes:

- which interfaces the core offers to an outside program at the audited
  commit, with what was read to say so;
- what is missing for an integrator who has no access to the source tree;
- a proposed standard in three pieces: an integration manifest, four
  connection profiles and four conformance levels;
- what the core would have to change before each level is reachable, tied
  to the findings in parts 1 to 7.

It does not establish:

- that any interface named here is stable, supported or published. The
  workspace is at 0.4.0, which `VERSIONING.md:62` calls an unpublished
  candidate; the last recorded publication is 0.2.7 (`VERSIONING.md:41-47`);
- that the proposed levels are sufficient for any regulatory, legal or
  security purpose. A conformance result is the integrator's own test
  result. It is not a certification and not a cryptographic one;
- that the interface survey is complete (see "Evidence and limits");
- anything about how a specific product should be built. No product's
  code was read for this record;
- any change to `AGENTS.md`. Its intake gate, its conditions for a trust
  claim and its regression firewall apply as written to every surface in
  this repository, whatever this record proposes.

Nothing was compiled or run.

## Audited source

| Item | Value |
| --- | --- |
| Repository | `exochain/exochain` |
| Commit | `e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e` |
| Inputs | Parts 1 to 7 of this audit; `AGENTS.md`; `INTEGRATION.md`; `VERSIONING.md`; `governance/releases/v0.3.1/` (a proposal, not approved) |

## Terms

| Term | Meaning here |
| --- | --- |
| Core | The Rust trust fabric that would move to its own repository |
| Integration | Any tool, product or system outside the core that calls it. `AGENTS.md` calls these adjacent surfaces |
| Gateway, node | The core's two server programs (`exo-gateway`, and `exochain` built from `exo-node`) |
| AVC | Autonomous Volition Credential: the core's credential and receipt system (`exo-avc`) |
| DAG DB | The core's governed graph memory, served over twelve gateway routes |
| MCP | Model Context Protocol, the tool interface AI agents use |
| F-n, O-n, D-n | A finding, observation or disclosure requirement from parts 1 to 7. Part 7's register lists them. Those cited here: F-1 to F-6 (which boundary crates travel with the core), F-9, F-10, F-13 (product names in the core's API), F-12 (ExoForge, 0dentity and Telegram surfaces in the node), F-15, F-16, F-35 (product tests inside core tests), F-26, F-39 (package contents unverified), F-44 (standing of the copyright holder named in headers), F-48 and D-8 (verifying releases after a split), O-31 (products linking to the core by file path) |

## The problem in one paragraph

Today the products that use the core sit in the same directory tree and
reach it through that tree: two product packages link to the WASM build
output by relative path, a demo script compiles a core crate in place
(O-31), product tests live inside core tests (F-15, F-16, F-35), and
product names are in the core's own API (F-9, F-10, F-13). After a split
none of those connections survives as it is. `AGENTS.md` already says
what an adjacent surface must state and prove before it may claim the
core protects it. What was not found is a fixed format for stating it, a
list of the interfaces an outsider may rely on, or a way to test the
claim without the core's source tree.

## What the core offers today

"Read" means the cited lines were read for this record. "Survey" means
the fact comes from a one-off read-only survey and was not re-read.

| Interface | What it is | Version signal | Caller must hold | Basis |
| --- | --- | --- | --- | --- |
| Discovery document | `GET /.well-known/exochain.json` on the gateway: base URL, health and AVC route paths, SDK locations, MCP transport metadata | None. No version field; `base_url` is a fixed string; the SDK entries are repository paths, not package names | Nothing | Read: `crates/exo-gateway/src/rest.rs:33-104` |
| AVC routes (node) | Issue, validate, delegate, revoke, emit and read receipts, receipt proofs | A response type for `GET /api/v1/avc/protocol` carries current, minimum and maximum protocol version, a schema version and a deprecation window in days. The handler was not read | The node's admin bearer token for writes and for reading trust objects | Read: `crates/exo-node/src/avc.rs:2477-2486`, `crates/exo-node/src/auth.rs:17-31`; route list by survey |
| DAG DB routes (gateway) | Twelve mounted routes. Nine `POST`: intake, route, context-packet, validate, writeback, import, export, trust-check, council/decision. Three `GET`: receipts/:receipt_hash, catalog/:catalog_id, routes/:route_id. The gateway's own router includes them, so the node's server serves them too | Each of the twelve response types carries a `schema_version`. Request bodies and the shared error envelope are not versioned (`INTEGRATION.md:304`). The hand-authored OpenAPI 3.1 file describes five of the twelve, and is covered by a test "when main integration runs it" (`INTEGRATION.md:310-311`) | For writeback, import and export, a write signature with consent checked against stored state (`INTEGRATION.md:93-99`). What the other nine require was not read. Header names by survey | Read: `crates/exo-gateway/src/dagdb.rs:620-653` (the route table), `crates/exo-gateway/src/server.rs:4617-4639` (where the gateway mounts it), `docs/dagdb/api/openapi.json` (paths only), `INTEGRATION.md:71-104, 273-317`. The handlers of the seven routes the documentation omits were seen to exist (`dagdb.rs:661-1035`), not read. `AGENTS.md` says some activation evidence for this runtime is still pending |
| Other gateway and node routes | Decisions, audit, sessions, agents, identity, tenants, governance, challenges, passport, provenance, economy, and product-named routes | None found | Session bearer (gateway) or admin bearer (node) | Survey |
| MCP server (node) | stdio, and HTTP with server-sent events. Discovery metadata says loopback only and public transport off | MCP protocol `2024-11-05` | A signed `constitutional_context` on every tool call. A transport bearer, by survey | Read: `crates/exo-node/src/mcp/tools/mod.rs:17-62`, `middleware.rs:28`, `handler.rs:320`, `rest.rs:93-95`. The listener's binding and bearer check were not read |
| Packages | Rust `exochain-sdk`; WASM bridge (`@exochain/exochain-wasm`); `@exochain/sdk` (npm); `exochain` (PyPI); `@exochain/llm-proxy` | One number, 0.4.0. `PROTOCOL_VERSION` in the npm and Python packages equals the package version | Depends on the route called | Read: `Cargo.toml:66`, `packages/exochain-sdk/src/index.ts:35`, `packages/exochain-sdk/package.json:3`, `packages/exochain-py/exochain/__init__.py:75`, `packages/exochain-py/pyproject.toml:23`, `packages/exochain-llm-proxy/package.json:3`. Package contents unverified (F-26) |
| Offline verifier | Crate directory `exo-verify`, package name `exochain-verify`: checks an AVC receipt's signatures, its inclusion in the receipt chain, signer identity against a key bundle, and an RFC 3161 timestamp, with no network call | Key bundle and receipt bundle format constants | A key bundle the caller supplies; no credential | Read: `crates/exo-verify/src/lib.rs:17-44` |

**The DAG DB documentation and the router disagree.** At the audited
commit `dagdb_router` mounts twelve routes (`crates/exo-gateway/src/dagdb.rs:620-653`),
and the gateway's router mounts that router
(`crates/exo-gateway/src/server.rs:4617-4639`). `INTEGRATION.md:83-86` and
`AGENTS.md:130-133` say the gateway serves exactly five. `INTEGRATION.md:99-102`
and `:291-302` call the other seven "reserved" DTO surfaces that are not
mounted. This record takes the router as the inventory, because it is what
a client reaches. Whether the seven are meant to be served, and whether
they meet the same consent and fail-closed obligations as the five, was
not established: their handlers were seen, not read, and no route was
called.

**The discovery document is right for the node and wrong for the
standalone gateway.** The gateway's router serves it
(`crates/exo-gateway/src/server.rs:4548`), and it lists five AVC paths. The
AVC routes are in the node (`crates/exo-node/src/avc.rs:5613-5642`). The two
programs differ:

- The node merges its AVC router into `extra_router`
  (`crates/exo-node/src/main.rs:1451-1467`) and passes it to
  `serve_with_extra_routes` (`:1517-1521`), which merges it into the
  gateway's router (`crates/exo-gateway/src/server.rs:4524-4529`,
  `5004-5027`). In the node the document and the AVC routes are on one
  server, with no proxy needed.
- The standalone `exo-gateway` program calls `serve`
  (`crates/exo-gateway/src/main.rs:97`), which passes no extra routes
  (`server.rs:4996-4998`). It serves the document but none of the five AVC
  paths in it. A client that follows the document from that program is
  sent to routes it does not answer.

Three problems hold in both programs. `base_url` is the fixed string
`https://exochain.io` (`crates/exo-gateway/src/rest.rs:76`), not the
address of the server answering. The twelve DAG DB routes both programs
serve are not listed. One path is written in the router's own syntax
(`/api/v1/avc/receipts/:hash`).

**MCP.** The registry sorts tools into classes
(`crates/exo-node/src/mcp/tools/mod.rs:19-62`):

1. read-only tools that work in every build;
2. tools that refuse in every build (encrypted messaging);
3. mutation tools that refuse unless the node is built with a feature the
   source calls never safe for production: governance, identity, consent
   and legal tools, the ledger's `submit_event`, the escalation mutation
   tools and `delegate_authority`.

DAG DB tools are a separate family. Without a proxy feature and gateway
configuration they return a structured "unconfigured" result. With both,
`AGENTS.md` says they proxy to the gateway's DAG DB routes, which include
writes, and that evidence for that configured path is pending. So in a
default build an MCP caller can read and verify; governed writes over MCP
exist in source only through the DAG DB proxy, and that path is not
shown to be production-proven. The survey counted 52 registered tools;
`docs/guides/mcp-integration.md` says 40. Neither count was re-derived.

### Existing material this design reuses

| Material | Where | Standing |
| --- | --- | --- |
| The intake record, the conditions for a trust claim, the extra statements required of a new adjacent surface, and the regression firewall | `AGENTS.md`: "Adjacent Surface Intake Gate", "No Trust Claim By Proximity", "Adding Adjacent Surfaces", "Core Regression Firewall" | In force in this repository. This design restates them; it does not replace them |
| A discovery profile: a signed service card, "discovery is not authority", HTTP as the interface and the SDK as a convenience over it | `governance/releases/v0.3.1/specs/MCP-A2A-DISCOVERY.md` | Proposal, "Not approved" (line 21) |
| Nine JSON Schemas and 30 fixture files with an expectations file | `governance/releases/v0.3.1/schemas/`, `test-vectors/` | Proposal. The README says the digests are shape fixtures, not computed values, and that "a future harness" checks them (lines 23-28) |
| A versioned response contract with an OpenAPI file | `INTEGRATION.md:273-317`, `docs/dagdb/api/openapi.json` | Documented for DAG DB only |
| A protocol-version descriptor with a deprecation window | `GET /api/v1/avc/protocol` | Present in source for AVC only |
| A cross-implementation comparison of Rust and TypeScript outputs on shared vectors | `tools/cross-impl-test/` | Survey; not read. `AGENTS.md` names its script |

Where this design leans on the v0.3.1 proposal it inherits that
proposal's unapproved standing.

## What is missing for an outside integrator

These are what the reading and the survey found, not proofs of absence.

| Gap | Why it matters | Related finding |
| --- | --- | --- |
| No list of which interfaces are supported for outside use | An integrator cannot tell a stable route from an internal one | F-26, F-39 |
| The only HTTP contract file found covers DAG DB. MCP tools carry their own JSON Schemas; the v0.3.1 schemas are proposals | Other HTTP routes have to be learned from Rust source | None |
| The discovery document has no version, a fixed `base_url`, repository paths for the SDKs, and no DAG DB routes. Served by the standalone gateway, it lists AVC routes that program does not serve | It is the one place a client is told where to send a request | None |
| The DAG DB documentation lists five routes; the router mounts twelve | An integrator reading the documentation does not know seven routes exist, or what they promise | None |
| A version can be checked before a call only for AVC. DAG DB reports its version in the response, after a write has happened | An integration cannot refuse an unsupported contract before it has changed state | None |
| No deprecation rule outside AVC | `VERSIONING.md:216-217` says the public API may change between minor versions | None |
| Product names are in routes, credentials and the SDK | A neutral integrator would be reading another product's name in its own calls | F-9, F-10, F-13 |
| The node's general write credential is one admin token. The narrower mechanisms are tied to named surfaces: two product-scoped bearers, and DID session tokens with signed requests on the 0dentity routes | An integrator needing one write route would be handed authority over all of them | F-9, F-10, F-12 |
| No stated way for an integrator to obtain its own keys, or the trust anchors it needs: the keys the MCP middleware trusts, and the key bundle the offline verifier takes from the caller | Without it an integration either shares someone else's secret or verifies against keys it chose itself | F-48, D-8 |
| No conformance harness was found; the fixtures that exist are not computed | Nothing lets an integrator test "fail closed" without the source tree | None |
| The intake record has no fixed format or location | Each surface would state it differently, and nothing can check it | None |

## Design principles (proposed)

1. **One way in.** An integration reaches the core only through an
   interface the core publishes. No relative paths into the core's tree,
   no reading its files, no building its crates in place.
2. **For remote operations, HTTP is the reference and SDKs are
   conveniences.** Where the core acts as a service (deciding, recording,
   issuing), a client that speaks HTTP should be able to do what an SDK
   does. This follows the v0.3.1 proposal's criterion AC-8, which covers
   that proposal's own routes and is unapproved; extending it is an open
   decision below. It does not cover local operations such as offline
   verification or the WASM bridge's local functions, and it assumes
   responses a client can check, which was not shown to exist for every
   route.
3. **Discovery grants nothing.** A discovery document or a tool list
   tells a client where to send a request. Permission comes only from the
   core evaluating that request.
4. **Deny when in doubt, and reconcile.** If the core rejects, times out
   or cannot be reached, the integration treats the answer as "no" and
   never substitutes a cached or invented "yes". A timeout does not prove
   nothing happened: the core may have recorded a write whose response
   was lost. The integration must be able to ask again safely and find
   out.
5. **The integration never decides what the core decides.** It does not
   mint, cache or simulate consent, authority, provenance or governance
   outcomes.
6. **A claim needs a test of the real path.** An integration may say the
   core protects an action only for the actions it has shown to pass
   through the relevant core decision, in the words its level allows.
7. **No product names in the core's interfaces.** This depends on the
   panel decisions on F-9, F-10, F-12 and F-13 and prejudges none of
   them.

Principles 3 to 6 restate `AGENTS.md` and the v0.3.1 discovery proposal.
Principles 1, 2 and 7 are new here.

## The proposed standard

### How it relates to `AGENTS.md`

The standard is a format and a test method for rules `AGENTS.md` already
states. It relaxes none of them.

- A surface in this repository still owes the intake record in its pull
  request, and every adjacent pull request still owes the regression
  firewall's items: a classification of every touched path, a statement
  of whether core, adapter, CI, governance or deployment files changed,
  focused tests, the core gates when those files changed, and a bypass
  search. A conformance level is not a substitute for any of them.
- If the manifest cannot be completed, `AGENTS.md`'s rule applies: the
  surface is quarantined as adjacent and is not wired into core runtime
  paths.
- After a split, an outside integration cannot change core files in its
  own pull request, so the firewall's purpose is met differently: by
  principle 1 and by the core's own gates. A change the integration
  needs in the core is a separate pull request to the core.

### Piece 1: the integration manifest (the template)

One file in the integrating project's repository. It carries the
`AGENTS.md` intake record and the statements required under "Adding
Adjacent Surfaces" in a fixed form, plus the interfaces used and the
level sought. Proposed name: `exochain-integration.json`, validated by a
JSON Schema the core would publish. No such schema exists yet.

The example is hypothetical. Its contract name is a placeholder, and
because 0.4.0 is unpublished it could not reach level 1 today.

Note added after this record was written: a draft schema now exists in
`integration-manifest/`, and it has since changed. This example no
longer validates against it. The current example and the list of changes
are in `integration-manifest/README.md`.

```json
{
  "manifest_version": 1,
  "integration": {
    "name": "example-tool",
    "revision": "the integration's own commit",
    "owner": "Example Org",
    "accountable_maintainer": "role or team, not a personal address",
    "deployment_status": "prototype"
  },
  "core": { "release": "0.4.0" },
  "interfaces": [
    { "profile": "http", "contract": "PLACEHOLDER-dagdb-contract-id", "routes": ["POST /api/v1/dag-db/writeback"] },
    { "profile": "verify", "package": "exochain-verify", "version": "0.4.0" }
  ],
  "core_access": {
    "core_state":          { "read": false, "write": true,  "note": "dag-db writeback" },
    "signatures":          { "read": false, "write": false },
    "credentials":         { "read": false, "write": false },
    "governance_outcomes": { "read": false, "write": false },
    "consent_records":     { "read": false, "write": false },
    "provenance_records":  { "read": true,  "write": false, "note": "receipts" }
  },
  "actions": [
    {
      "name": "save-note",
      "entry_point": "where the action starts in the integration",
      "core_decision": "POST /api/v1/dag-db/writeback",
      "effect": "what happens only if the core allows it"
    }
  ],
  "trust_boundary": "What the integration decides and what the core decides.",
  "threat_model": "Path to a document covering secrets, identity, consent, authority, provenance and external writes.",
  "deployment_boundary": "Where it runs and what it can reach.",
  "credentials_model": "Which credentials it holds, who issued each, and their scope.",
  "trust_claims": { "allowed": false, "target_level": 2, "achieved_level": null, "result_file": null },
  "tests": { "command": "npm test", "ci_gate": "name of the required check" },
  "secrets": {
    "inventory": ["names only, never values"],
    "source": "where configuration comes from",
    "holds": ["a signing key issued to this integration as its own principal"]
  },
  "disablement": "How to switch it off if it leaks, misroutes or misstates a core decision."
}
```

| Manifest field | `AGENTS.md` requirement it carries |
| --- | --- |
| `integration.owner`, `accountable_maintainer` | Intake: owner and accountable maintainer |
| `integration.deployment_status` | Intake: deployment status (`prototype`, `internal`, `customer-zero`, `production`) |
| `trust_claims.allowed` | Intake: whether the surface may make constitutional trust claims |
| `core_access`, one entry per category, "false" stated explicitly | Intake: whether it can read or write core state, signatures, credentials, governance outcomes, consent records or provenance records |
| `trust_boundary` | Intake: exact trust boundary |
| `tests` | Intake: surface-specific test command and CI gate |
| `secrets` | Intake: secrets inventory and runtime configuration source |
| `disablement` | Intake: rollback or disablement path if the surface leaks, misroutes or misstates core trust decisions |
| `interfaces` | Adding Adjacent Surfaces: which core APIs it calls |
| `threat_model` | Adding Adjacent Surfaces: threat model |
| `deployment_boundary`, `credentials_model` | Adding Adjacent Surfaces: deployment boundary and credentials model |
| `core`, `actions`, `trust_claims.target_level`, `achieved_level`, `result_file` | New in this design |

The manifest holds names, never secret values, and no personal contact
details. `actions` must list every action for which the integration
calls the core, not only the ones it wants to make a claim about.

An integration may hold only key material issued to it as its own
principal. It never holds a tenant's secret, a production signing key, a
core bootstrap key or an emergency override credential; `AGENTS.md`
forbids sharing those. How an integration is issued its own key is an
open decision below.

### Piece 2: four connection profiles

An integration uses one or more.

| Profile | Use it when | Goes through | Holds | State today |
| --- | --- | --- | --- | --- |
| **Verify** | You only need to check something the core produced | For AVC receipts, the offline verifier. The SDKs and the WASM bridge also export verify functions; which properties each checks was not examined | Public keys and trust anchors obtained independently of the party being checked | The verifier is in source; 0.4.0 is not published; no key distribution is defined |
| **HTTP** | You ask the core to decide or record something | Gateway or node routes that have a published contract | A credential scoped to the routes used, and its own signing key where the route requires one | DAG DB routes have a response contract. AVC has a version descriptor but no contract file. No general way to issue a scoped credential exists |
| **MCP** | An AI agent is the caller | The node's MCP server | A signed context for each call | In a default build, read and verify tools; local transports. See "MCP" above for the DAG DB proxy |
| **Embedded** | You link core crates or the WASM bridge into your own process | The published crates or WASM package | Whatever the embedded code needs | The crates and bridge are in source |

In the HTTP and MCP profiles the core's own process makes the decision.
Verify makes no decision; it checks one already made. Embedded is
different in kind: governed logic runs in the integrator's process.

Linking the core does not change what an integration is. It remains an
adjacent surface under every `AGENTS.md` rule. `INTEGRATION.md:29-54`
says the same of WASM consumers: the bridge is the adapter, and a
consumer stays adjacent unless its own tested path meets the boundary
conditions. Whether any embedding boundary is classed as a core runtime
adapter is the core maintainers' decision for specific paths, never the
integrator's by choosing this profile. The conformance levels below are
not defined for Embedded: "the core is unreachable" has no meaning for a
library. This design recommends that outside integrators not use it and
leaves it outside the levels until a panel decides.

### Piece 3: four conformance levels

Each level includes the ones below it. The last column is the only
wording about the core's protection an integration may use at that
level.

| Level | Name | Requirements | Allowed wording |
| --- | --- | --- | --- |
| 0 | Declared | A complete manifest that validates against the schema | "Unaudited adjacent code." No trust claim |
| 1 | Connected | See below | "Unaudited adjacent code." It may add "uses EXOCHAIN's published interfaces" beside that phrase, never in place of it. No trust claim |
| 2 | Fail-closed | See below | "The following actions are checked by EXOCHAIN: (the tested actions)." Nothing wider |
| 3 | Verifiable | See below | "Each listed action produces an independently verifiable EXOCHAIN receipt." |

Levels 0 and 1 use the `AGENTS.md` phrase because at those levels none of
its conditions for a trust claim has been shown.

**Level 1, Connected**

- Uses only published interfaces at pinned versions. No path, file or
  in-place build dependency on the core's tree.
- Establishes that each interface's version is supported *before*
  sending any request that changes state, and stops if it is not. Today
  only AVC offers a way to ask first.
- Shares no core bootstrap key, production signing key, tenant secret or
  emergency override credential; uses its own secret scope.
- Authenticated calls use a credential scoped to the integration, not
  the node's admin token.
- `actions` lists every call into the core. The kit's runner checks this
  against the integration's dependencies and outbound calls as far as it
  can; the rest is the integrator's statement.

**Level 2, Fail-closed.** For every action in the manifest:

| Requirement | Source | How shown |
| --- | --- | --- |
| The action's effect happens only after the relevant core decision for that action and its parameters, not after some other call such as a health check | `AGENTS.md`: "the runtime path invokes the relevant EXOCHAIN core API or verified adapter" | Tests against a real core instance: allowed case; denied case; denied when the parameters differ from those decided; no effect without a decision |
| A denial when the core rejects, times out or is unreachable | `AGENTS.md`: fail-closed tests | Tests against the kit's fault cases |
| A lost response after the core has recorded a write is detected and reconciled; a repeat does not act twice | New here (principle 4) | Test against a fault case that records, then drops the response |
| No code path mints, caches or simulates consent, authority, provenance or governance outcomes | `AGENTS.md` | Inspection. This is a statement by the integrator, not a test result; the kit can only check that a forged or replayed "allow" from the stand-in is not accepted where the contract lets that be detected |
| Status, health, debug, telemetry and error responses disclose no bootstrap token, private key, raw secret, authority chain or tenant data | `AGENTS.md` | Tests on those outputs, and inspection |
| It stops when a required secret is absent or malformed | `AGENTS.md`: regression firewall | Tests |
| No hardcoded production credential; no development fallback in a production path | `AGENTS.md`: "Adding Adjacent Surfaces" | Inspection and a scan |
| A search for other entry points that reach the same effect without the core, with its method and output recorded | `AGENTS.md`: bypass search | The recorded search. A search cannot prove there is no bypass |

**Level 3, Verifiable.** For every action claimed:

- the action yields a receipt that passes the offline verifier;
- the receipt's authenticated contents are compared with the claimed
  action: its subject, tenant, outcome and request identity, as far as
  the receipt format carries them. A valid receipt for something else
  does not count. Any of these the format cannot carry is a stated gap,
  not a pass;
- the verifier's key bundle and timestamp-authority key come from the
  core's operator through a channel independent of the integration. A
  bundle the integration supplies about itself proves nothing.

Level 3 is defined today only for actions that produce an AVC receipt.
No offline verifier was found for DAG DB or other routes, so an
integration that uses only those cannot reach it.

**What a result is.** A level is recorded in a result file that names the
integration's revision, the manifest, the configuration and build
features tested, the kit version and the core release. Change any of
them and the level has to be established again. A level is not to be
shown without its result file. Results are self-run and self-reported
unless the open decision below says otherwise, and an integrator who
leaves an action out of the manifest has not tested it: the level covers
listed actions only, which is why the allowed wording names them.

### The conformance kit

What the core would publish so that the levels can be tested without its
source tree. None of it exists yet except where a starting point is
named.

| Item | Purpose | Starting point |
| --- | --- | --- |
| Manifest schema | Level 0 | New; fields from `AGENTS.md` |
| Interface list for the release | Level 1: which routes, tools and packages are supported for outside use, which host serves each, and each one's version signal | New |
| Contract files | Level 1: one machine-readable contract per supported HTTP surface, including requests and errors | `docs/dagdb/api/openapi.json` is the pattern |
| A real core for tests | Level 2: positive and negative cases against the actual decision path | A documented way to run the gateway and node locally; `AGENTS.md` describes one for a development VM |
| Fault cases | Level 2: a stand-in that answers supported routes with reject, delay past timeout, connection refused, record-then-drop, malformed response, and a forged "allow" | New |
| Computed test vectors | Levels 2 and 3: requests and responses with real digests and signatures and an expected decision | The v0.3.1 fixtures have the structure but shape-only values |
| Verifier and trust anchors | Level 3 | `exochain-verify`; anchor distribution is new |
| Runner | Runs the above, scans dependencies and outbound calls, and writes the result file | New |

The stand-in is a test double. It makes no decisions and must not be
usable as a core. Passing its cases shows how the integration reacts to
failures; it shows nothing about whether the real path reaches the core,
which is why level 2 also requires tests against a real instance.

## What the core would have to change

Nothing below is decided. Owners are suggestions.

| Change | Needed for | Depends on | Suggested owner |
| --- | --- | --- | --- |
| Publish the manifest schema | Level 0 | Nothing in parts 1 to 7 | Core maintainers |
| Publish an interface list per release | Level 1 | The boundary decisions (F-1 to F-6) | Architecture panel |
| Neutral names for product-named routes, credentials and SDK functions | Level 1 for any integrator other than those products | F-9, F-10, F-13 | Architecture panel |
| A discovery document with a version, package names, the host that serves each route, only routes that are served, and a standard path-template syntax | Level 1 | Overlaps the unapproved v0.3.1 discovery proposal | Architecture panel |
| A way to check the contract version before a state-changing call, on every supported surface | Level 1 | AVC's descriptor is the pattern | Core maintainers |
| A stated version and deprecation rule for each supported interface | Level 1 | `VERSIONING.md` has none outside the yank procedure | Core maintainers |
| A credential issued to an integration and scoped to its routes | Level 1 for any authenticated call to the node | New question. Two narrower mechanisms exist for named surfaces: `ScopedBearerAuth` (`crates/exo-node/src/auth.rs:93-100`) and DID session tokens with signed requests (`auth.rs:25-27`) | Security panel |
| Packages published with verified contents | Level 1 through an SDK | F-26, F-39, F-48 | Release owner |
| Contract files for supported routes beyond DAG DB | Level 1 over HTTP | The interface list | Core maintainers |
| Safe repeat of a write whose response was lost | Level 2 | Not examined: whether supported routes already accept an idempotency key | Core maintainers |
| Fault cases, computed vectors, a runner | Level 2 | The interface list and contract files | Core maintainers |
| Distribution of verifier key bundles and other trust anchors | Level 3; also the MCP profile | F-48, D-8 | Release owner, Security panel |
| A statement of what MCP is for: read-and-verify only, or governed writes too | The MCP profile above level 1 | The source's note that most mutation tools have no live backing; the pending DAG DB proxy evidence | Architecture and Security panels |

## Phasing

| Phase | Content | Can start |
| --- | --- | --- |
| A | Draft manifest schema; this design reviewed | Now. It touches no boundary decision |
| B | Interface list; neutral names; discovery; version rules; scoped credentials | After the boundary decisions in part 2 and the name decisions in part 3 |
| C | Contract files; conformance kit; trust-anchor distribution | After B |
| D | First integrations tested; decision on who reviews results | After C |

Anything written in phase A is a draft with no standing until the
standard is adopted. No level may be claimed publicly before then, and
phase A changes nothing about what a surface in this repository owes
under `AGENTS.md` today.

A first adopter can still do useful work in phase A: draft its manifest,
list every place it reaches the core, and mark each as "published
interface" or "tree access". That list is the integration's own
migration plan and the first real test of whether the manifest's fields
are the right ones.

## Open decisions

| Decision | Options | For |
| --- | --- | --- |
| Is HTTP the reference interface for remote operations | Yes, as proposed; or the SDKs are the reference and HTTP is internal | Architecture panel |
| The level definitions and the allowed wording | As proposed; or amended | Architecture and Security panels |
| Where the standard and kit live | In the core repository; or a separate repository the core's CI consumes | Architecture panel, split plan owner |
| Whether conformance results are reviewed | Self-reported only; reviewed by core maintainers; or a listed registry of results | Architecture and Security panels |
| How an integration is issued its own credential and signing key | Generalise the existing scoped bearer; a per-integration DID with signed requests; or another mechanism | Security panel |
| How trust anchors reach integrators and third-party verifiers | With each release; from a service; or another channel | Security panel, release owner |
| Whether the Embedded profile is offered to outside integrators | No, as recommended; or yes, with requirements defined for it | Security panel |
| Relation to the v0.3.1 discovery proposal | Adopt its discovery rules as part of this standard; keep them separate; or wait for its own authorization | Whoever authorizes v0.3.1 |
| Manifest file name and format | JSON as proposed; or TOML | Core maintainers |

## Evidence and limits

- **Read for this record:** the files and line ranges marked "Read" in
  the interface table; `AGENTS.md`; `INTEGRATION.md`; the cited lines of
  `VERSIONING.md`; `governance/releases/v0.3.1/specs/MCP-A2A-DISCOVERY.md`;
  `governance/releases/v0.3.1/test-vectors/README.md`; a file listing of
  the v0.3.1 schema and test-vector directories.
- **From the survey, not re-read:** the route lists for the gateway and
  node; the gateway's session authentication; the MCP transport binding
  and bearer; the tool count; the package export lists; the release
  workflow; the DAG DB header names; `tools/cross-impl-test/`. The
  survey was one read-only pass by an AI subagent on 2026-11-17. Its
  report is not filed in the repository, so these facts cannot be checked
  from this record. Its fixture count (34) was wrong against a file
  listing (30 and an expectations file), which is a reason to treat its
  other counts with care.
- **Searches:** the statement that the gateway mounts no AVC route rests
  on a text search of `crates/exo-gateway/src` and `crates/exo-node/src`,
  not on reading the routers.
- "Not found" and "no ... exists" mean not found by this reading and
  survey.
- No route was called, no package was installed and nothing was built.
  "In source" means present at the audited commit, not that it works.
- The design was not tried against any real integration. The manifest
  fields and the level boundaries are untested.
- This design was reviewed once by two AI reviewers; both graded it C
  and their findings were applied here without a second review. That is
  not a panel or owner review.
- The levels describe the integration's behaviour toward the core. They
  say nothing about the integration's own security, privacy or
  correctness.
- This record gives no legal opinion and makes no licence statement
  about the kit or the manifest.
- Like parts 1 to 7, this file carries the repository's standard header.
  F-44's open question about that holder's standing applies to it too.

## Path classification of this record

| Path | Proposed class | Basis |
| --- | --- | --- |
| `docs/audit/core-separation-904/08-INTEGRATION-STANDARD-DESIGN.md` | EXOCHAIN core (a documentation proposal) | Part 1 rule C5 (`docs/audit/`) |

No file under `crates/`, `packages/`, `governance/`, `tools/`, CI or
deployment was changed for this record.
