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

#![no_main]

use exo_core::Signature;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_CBOR_BYTES: usize = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_CBOR_BYTES {
        return;
    }

    let decoded: Result<Signature, _> = ciborium::from_reader(data);
    if let Ok(signature) = decoded {
        let _ = signature.algorithm();
        let _ = signature.ed25519_bytes();
        let _ = signature.ed25519_component_is_zero();
        let _ = signature.is_empty();
        let _ = signature.to_bytes();
    }
});
