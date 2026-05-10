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

# EXOCHAIN Licensing Position

**Effective**: 2026-03-20
**License**: Apache License 2.0 (`Apache-2.0`)

---

## 1. Authoritative License

EXOCHAIN is licensed under the **Apache License, Version 2.0**. The full license text is in [`LICENSE`](../../LICENSE) at the repository root.

All Rust crates in the workspace inherit this license via `license.workspace = true` in their `Cargo.toml` manifests.

## 2. Scope

The Apache-2.0 license applies to:
- All Rust source code in `crates/`
- All tooling in `tools/`
- All documentation in `docs/` and `governance/`
- The demo platform in `demo/`
- CI/CD configurations in `.github/`
- The WASM compilation target (`exochain-wasm`)

## 3. Rationale

Apache-2.0 was chosen because:
- It permits use in both open-source and proprietary downstream projects
- It includes an explicit patent grant, important for a cryptographic substrate
- It is compatible with the vast majority of Rust ecosystem dependencies
- It allows constitutional governance experimentation without imposing copyleft obligations on downstream adopters
- It is widely understood in enterprise and government procurement contexts

## 4. Dependency License Screening

All dependencies are screened via `cargo-deny` (see `deny.toml`):

**Allowed dependency licenses**:
- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, CC0-1.0, BSL-1.0, Unicode-3.0, Unicode-DFS-2016, OpenSSL

**Denied dependency licenses**:
- GPL-2.0, GPL-3.0, LGPL-2.0/2.1/3.0, MPL-2.0, EUPL-1.1/1.2, CPAL-1.0, SSPL-1.0
- Any unlicensed crate

**Banned crates**:
- `openssl` / `openssl-sys` — EXOCHAIN uses pure-Rust cryptography (ed25519-dalek, blake3)

## 5. Downstream Users

If you use EXOCHAIN in your project:
- You may use, modify, and distribute under the terms of Apache-2.0
- You must include the license notice and any NOTICE file
- You must state changes if you modify the source
- The patent grant in Apache-2.0 covers contributions made by ExoChain contributors
- No copyleft obligation is imposed on your downstream code

## 6. Consistency Enforcement

The following sources must all declare `Apache-2.0`:
- `LICENSE` file (full text)
- `Cargo.toml` workspace `license` field
- All crate `Cargo.toml` files (via `license.workspace = true`)
- `deny.toml` comments
- `README.md` license section
- `CONTRIBUTING.md` license references

Any divergence is a bug. The `tools/repo_truth.sh` utility checks for consistency.

## 7. Historical Note

Prior to 2026-03-20, the `Cargo.toml` incorrectly declared `AGPL-3.0-or-later` while the LICENSE file contained Apache-2.0 text and all public documentation referenced Apache-2.0. This was an error introduced during initial scaffolding. The authoritative intent was always Apache-2.0, as evidenced by the LICENSE file, README, and CONTRIBUTING.md. This has been corrected.
