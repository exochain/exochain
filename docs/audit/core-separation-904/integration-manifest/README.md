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

# Integration manifest schema (draft)

**Status: PROPOSAL. Draft. Not reviewed by any panel. Not adopted.**

EXOCHAIN's `AGENTS.md` asks any product or tool that sits next to the
core (an "adjacent surface") to state who owns it, what it can touch in
the core, where its trust boundary is and how to switch it off. Today
that is free text in a pull request. This directory proposes a fixed form
for it: one JSON file, `exochain-integration.json`, kept in the
integrating project's repository, and a JSON Schema that checks its
shape.

The schema is the first draft piece of the integration standard proposed
in [the design record](../08-INTEGRATION-STANDARD-DESIGN.md). That record
says its early drafts have no standing, and that applies here:

- Nothing in this directory changes a rule in `AGENTS.md`. A surface in
  the core repository still owes the intake record and the regression
  firewall checks that file describes.
- A manifest that validates has not passed the intake gate. A person
  still has to read it.
- **No conformance level may be claimed publicly until the standard is
  adopted.** Until then a real manifest keeps `trust_claims.allowed` at
  `false` and `achieved_level` at `null`. The draft schema does not force
  this, so that the level rules below can be reviewed and tested.
- The schema applies to a surface that calls the core. One that calls no
  core interface has nothing to list under `interfaces` and cannot
  produce a valid manifest; `AGENTS.md` still applies to it.

## Files

| File | What it is |
|---|---|
| `exochain-integration.schema.json` | The schema, JSON Schema draft 2020-12. |
| `example.exochain-integration.json` | A filled-in manifest for an invented tool. It validates. It names core release 0.4.0, which is not published, so the tool could not reach level 1 today. |
| `check_manifest_schema.py` | Checks the schema, the example and 87 cases; also validates manifests named on the command line. |

## How to use it

Check the schema against its own cases:

```bash
python -I check_manifest_schema.py
```

Validate a manifest:

```bash
python -I check_manifest_schema.py path/to/exochain-integration.json
```

The checker needs the Python package `jsonschema` (4.x). It compiles
nothing and calls no network. Another draft 2020-12 validator should give
the same answers; only the Python one has been run.

## For integrators: filling it in

**Profiles.** Each entry under `interfaces` says how you reach the core:

| `profile` | Meaning | Entry fields |
|---|---|---|
| `http` | You call gateway or node routes and the core decides | `contract`, `routes` |
| `mcp` | An AI agent calls the node's MCP server | `protocol_version`, `tools` |
| `verify` | You only check something the core produced | `package`, `source` |
| `library` | You link a core package only to build, sign or parse what you exchange with a core that decides | `package`, `source` |
| `embedded` | Governed logic from a core package runs in your own process | `package`, `source` |

The design recommends that outside integrators not use `embedded`, and
defines no levels for it. `library` is new in this draft; see "Changes
from the pilot" below.

**Where a package comes from.** `source` is `registry` (a published
package; give `version`), `git` (a commit of the core repository; give
`revision`), `path` (a path into a core checkout) or `vendored` (a copy
in your own tree). Likewise `core` takes a `release`, a `revision`, or
both. Anything other than a published release is a dependency on the
core's tree, and rules out level 1.

**Levels.** `target_level` is the level you are working toward and
`achieved_level` the one a result file shows. Use `null` for "none".

| Level | Name | In one line |
|---|---|---|
| 0 | Declared | The manifest is complete and validates |
| 1 | Connected | Only published interfaces at pinned versions; own credentials |
| 2 | Fail-closed | Each listed action happens only after the core allows it, and is refused when the core rejects, times out or is unreachable |
| 3 | Verifiable | Each listed action yields a receipt that passes the offline verifier |

Levels 0 and 1 allow no trust claim. The design record gives the full
requirements and the only wording allowed at each level.

**`core_access`.** Answer for what your integration itself can do through
the interfaces it uses. Holding your own signing key to sign your own
requests is not `signatures.write`; that category is about signatures
the core holds or issues.

**`actions`.** List every action for which you call the core, not only
those you want to make a claim about. `core_decision` names the route or
tool, written as it appears under `interfaces`. `gating` says how the
action depends on the answer:

| `gating` | Meaning |
|---|---|
| `gated` | The effect happens only after the core allows it |
| `not_gated` | The core is asked, but the effect happens whatever it answers |
| `no_decision` | The call asks the core to decide nothing, such as a health probe |

**`secrets.holds`.** One entry per credential or key you hold, in words,
each with `issued_to_self`. Answer `false` for anything shared, such as a
node's admin token.

**`threat_model`.** A path to the document, or `null` if there is none
yet.

**`contract`.** The identifier of the published contract, including its
version. The core publishes no such identifiers yet, so use a value that
begins `PLACEHOLDER`.

**Text fields.** One line each, no tabs or line breaks. Put long material
in a document and give its path.

## What each field answers

Most fields carry one thing `AGENTS.md` already asks an adjacent surface
to state; the last row lists what the design adds. "Intake" is the
section "Adjacent Surface Intake Gate"; "Adding" is the section "Adding
Adjacent Surfaces".

| Manifest field | Source |
|---|---|
| `integration.owner`, `integration.accountable_maintainer` | Intake: owner and accountable maintainer |
| `integration.deployment_status` | Intake: deployment status, same four values |
| `trust_claims.allowed` | Intake: whether it may make constitutional trust claims |
| `core_access` | Intake: read or write of core state, signatures, credentials, governance outcomes, consent records, provenance records |
| `trust_boundary` | Intake: exact trust boundary |
| `tests.command`, `tests.ci_gate` | Intake: test command and CI gate |
| `secrets.inventory`, `secrets.source` | Intake: secrets inventory and configuration source |
| `disablement` | Intake: rollback or disablement path |
| `interfaces` | Adding: which core APIs it calls |
| `threat_model` | Adding: threat model |
| `deployment_boundary`, `credentials_model` | Adding: deployment boundary and credentials model |
| `manifest_version`, `integration.name`, `integration.revision`, `core.release`, `actions`, `trust_claims.target_level`, `trust_claims.achieved_level`, `trust_claims.result_file`, `secrets.holds`, `actions[].gating`, `core.revision`, package `source` | The design record only. Not asked for by `AGENTS.md`. |

## Rules the schema enforces

- Every top-level field is required and no unknown field is accepted, at
  any depth.
- All six `core_access` categories are present, each with an explicit
  `read` and `write` answer.
- `deployment_status` is one of `prototype`, `internal`, `customer-zero`,
  `production`.
- Every text field has at least one visible character and no control
  character.
- `owner` and `accountable_maintainer` contain nothing shaped like an
  email address. A team handle such as `@org/team` is accepted.
- A secret inventory entry is made of letters, digits and `_ . : / -`,
  at most 128 characters, and is not repeated.
- Each interface entry matches exactly one profile, and no entry is
  repeated word for word.
- A version is a Semantic Versioning 2.0.0 string.
- A route is a method in capitals, a space, and a path of visible ASCII
  characters.
- `trust_claims.allowed` may be `true` only when `achieved_level` is 2
  or 3.
- An `achieved_level` of 1 or more needs a `result_file`.
- `achieved_level` cannot be higher than `target_level`, and is `null`
  when `target_level` is `null`.
- A package from a registry names a `version`; one from git names a
  `revision`. `core` names a release, a commit, or both.
- An `achieved_level` of 1 or more needs a `core.release`, no package
  whose `source` is `git`, `path` or `vendored`, a `threat_model` that
  is not `null`, and nothing under `secrets.holds` with
  `issued_to_self` `false`.
- An `achieved_level` of 2 or 3 needs at least one `gated` action, no
  `not_gated` action, and at least one `http` or `mcp` interface,
  because those are the profiles in which the core decides.
- An `achieved_level` of 3 needs a `verify` interface.
- A manifest with an `embedded` interface has `target_level` and
  `achieved_level` both `null` and `trust_claims.allowed` `false`.

## What the schema cannot check

These need a reviewer or the conformance kit, which does not exist yet:

- whether any statement is true, including the `core_access` answers and
  `achieved_level`, which is the integrator's own statement until a kit
  checks it;
- whether `trust_claims.allowed` was really granted by whoever admits
  the surface. Writing `true` grants nothing;
- whether a `gating`, `source` or `issued_to_self` answer is true. They
  are the integrator's statements, like everything else here;
- whether a package marked `library` really makes no governed decision
  in the integrator's process;
- whether `actions` lists every call into the core, whether each
  `core_decision` is a route or tool listed under `interfaces`, and
  whether action names are unique;
- whether `interfaces`, `actions`, `core_access`, `secrets` and
  `credentials_model` agree with each other;
- whether a prose field says anything useful, or whether the threat
  model covers the six topics `AGENTS.md` names;
- whether a secret value has been pasted in. The name pattern rejects
  spaces and `=`; it cannot tell a token from a name, in `inventory` or
  anywhere else;
- whether the integration holds something it must not: a tenant secret,
  a production signing key, a core bootstrap key or an emergency override
  credential;
- whether personal contact details appear. Only email-shaped text in
  `owner` and `accountable_maintainer` is rejected; a name, a phone
  number, or an address in another field is not;
- whether `result_file` exists, belongs to this revision, or supports
  the level recorded;
- whether a level 3 action really produces a receipt the offline
  verifier accepts. Today only AVC receipts can;
- whether a listed route, tool, package or contract exists in the core
  release named, or whether two entries describe the same interface at
  different versions. The core publishes no machine-readable list to
  check against, which the design record lists as a prerequisite.

## Choices made here that the design record did not settle

Each is a proposal for the reviewing panel, not a decision.

- `manifest_version` is the integer 1.
- `target_level` may be `null`. The design's example always showed a
  number; `null` is needed for the `embedded` profile, which is outside
  the levels.
- `achieved_level` may not exceed `target_level`. The design names both
  but states no order. The effect is that an integrator who reaches a
  higher level than planned updates the target first.
- Level 0 needs no `result_file`. The design says a level is recorded in
  a result file, and also that level 0 is only "a manifest that
  validates". This draft reads the second as the rule for level 0.
- `actions` may be empty below level 2, so a verify-only integration can
  be described.
- An MCP interface entry names a `protocol_version` and a list of
  `tools`. The design's example showed only `http` and `verify` entries.
- An `http` entry has no separate version field; the `contract`
  identifier is expected to carry it.
- Versions follow Semantic Versioning. `VERSIONING.md` was not checked
  for a stricter or looser rule.
- Any method written in capitals is accepted in a route.
- Text fields are single-line.
- The draft does not force `allowed` to `false` before adoption (see the
  top of this file).
- The `$id` sits under `https://exochain.io/schemas/proposal/`, following
  the v0.3.1 proposal schemas in `governance/releases/v0.3.1/schemas/`.
  Nothing is published at that address.
- The file lives under the audit record for now. Where the schema would
  live if adopted is one of the design record's open decisions.

## Changes from the pilot

The schema was tried on two real integrations after its review. Both
called the core over HTTP and also linked core crates, pinned to a
commit, only to build and sign requests. The first draft could not
describe them honestly, and these changes followed. They have not been
reviewed.

| Change | Why |
|---|---|
| New `library` profile | `embedded` put both integrations outside the levels although the core, not their process, made the decision |
| `core.revision`; `source` and `revision` on packages | Both pinned a commit, and one vendored a patched core crate. The schema only had room for a release |
| `gating` on each action | One integration acted whatever the core answered. That could only be said in prose |
| `no_decision` actions | Health probes and a route the core does not serve looked like decisions |
| `host` on an HTTP entry | The integrations called node routes through a URL they named a gateway |
| `secrets.holds` entries carry `issued_to_self` | One integration held a node's shared admin token, which level 1 forbids |
| `threat_model` may be `null` | Neither had one, and "none yet" passed as text |
| Level 1 rules on release, source, threat model and held credentials | So the answers above are checked, not only recorded |

## Path classification

| Path | Class | Basis |
|---|---|---|
| `docs/audit/core-separation-904/integration-manifest/*` | EXOCHAIN core | The audit's own sorting rule for `docs/audit/` (part 1, rule C5); `AGENTS.md` does not name audit records |

No file under `crates/`, `packages/`, `governance/`, `tools/`, CI or
deployment is changed.
