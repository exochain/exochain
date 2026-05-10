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

use exo_core::Did;
use exo_governance::clearance::{ClearancePolicy, ClearanceRegistry, check_clearance};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_JSON_BYTES: usize = 16 * 1024;
const MAX_ACTIONS_TO_EVALUATE: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_JSON_BYTES {
        return;
    }

    let policy: Result<ClearancePolicy, _> = serde_json::from_slice(data);
    let Ok(policy) = policy else {
        return;
    };
    let Ok(actor) = Did::new("did:exo:fuzz-clearance-actor") else {
        return;
    };

    let registry = ClearanceRegistry::default();
    for action in policy.actions.keys().take(MAX_ACTIONS_TO_EVALUATE) {
        let _ = check_clearance(&actor, action, &policy, &registry);
    }
});
