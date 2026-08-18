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

//! Host handles for the CGR combinator-reduction zkVM guest.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

/// RISC Zero image id as 32 little-endian bytes.
#[must_use]
pub fn guest_image_id_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, word) in EXOCHAIN_CGR_GUEST_ID.iter().enumerate() {
        let offset = index * 4;
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
