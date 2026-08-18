// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

fn main() {
    // Guest compile needs the rzup RISC-V toolchain. Default workspace
    // CI (build/test/clippy) must not require it. Rebuild the guest with
    // RISC0_BUILD_GUEST=1 when regenerating receipts.
    if std::env::var("RISC0_BUILD_GUEST").ok().as_deref() == Some("1") {
        risc0_build::embed_methods();
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(
        format!("{out_dir}/methods.rs"),
        r#"
pub const EXOCHAIN_CGR_GUEST_ELF: &[u8] = &[];
pub const EXOCHAIN_CGR_GUEST_PATH: &str = "";
pub const EXOCHAIN_CGR_GUEST_ID: [u32; 8] = [893841976, 2368770385, 1509043099, 1024983472, 1961237384, 2080506814, 4049918768, 1885929724];
"#,
    )
    .expect("write default methods.rs");
}
