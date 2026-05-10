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

/// Generates a prompt for the devil's advocate based on the synthesized consensus.
pub fn generate_advocate_prompt(question: &str, consensus: &str) -> String {
    format!(
        "The panel has reached a consensus on the following question:\nQuestion: {}\nConsensus: {}\n\nYour job is to find the strongest counterarguments, logical flaws, or edge cases that break this consensus. Be adversarial but strictly logical.",
        question, consensus
    )
}
