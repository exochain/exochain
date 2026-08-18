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

# fix-mcp-cgr-proof-verification-stub

This is a minimal pointer document, not an implementation plan. This
initiative is tracked as **GAP-REGISTRY.md row VCG-004**.

## Refusal payload that cites this file

`crates/exo-node/src/mcp/tools/proofs.rs`, `execute_verify_cgr_proof`
(the `exochain_verify_cgr_proof` MCP tool). Its refusal payload's
`initiative` field and error message both cite
`Initiatives/fix-mcp-cgr-proof-verification-stub.md`:

> "CGR proof verification is unavailable: exochain_verify_cgr_proof has
> no proof bytes, public inputs, checkpoint root, validator signature
> set, or production CGR proof verifier wired; refusing hash-only
> verification claims. See Initiatives/fix-mcp-cgr-proof-verification-stub.md."

Hash-only calls remain unconditionally fail-closed. When `combinator`,
`input`, and a sealed `trace` are supplied, the tool verifies by
deterministic combinator replay against the sealed BLAKE3 trace hash.
That is CGR completeness as specified in §19.6.1 (replay, not a SNARK).

Production SNARK/STARK/ZKML verification remains GAP-REGISTRY.md row
VCG-001 and is not claimed by this tool. Wiring this tool to the
pedagogical `exo-proofs` verifiers is still an explicit non-closure
for VCG-001.
