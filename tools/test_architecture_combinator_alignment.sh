#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$0")/.."

architecture="docs/architecture/ARCHITECTURE.md"
implementation="crates/exo-gatekeeper/src/combinator.rs"

for term in Identity Sequence Parallel Choice Guard Transform Retry Timeout Checkpoint; do
  grep -q "| \`$term\`" "$architecture" || {
    echo "ARCHITECTURE.md must document implemented combinator term: $term" >&2
    exit 1
  }

  grep -q "$term" "$implementation" || {
    echo "combinator implementation must define documented term: $term" >&2
    exit 1
  }
done

if grep -q "| \\*\\*S\\*\\* | Composition with sharing" "$architecture"; then
  echo "ARCHITECTURE.md must not describe the current engine as an S/K/I/B/C basis" >&2
  exit 1
fi

if grep -q "| \`NOT\`, \`AND\`, \`OR\`, \`IMPLIES\`" "$architecture"; then
  echo "ARCHITECTURE.md must not document absent propositional combinator terms" >&2
  exit 1
fi

grep -q "The implemented terms are" "$architecture" || {
  echo "ARCHITECTURE.md must state that the listed combinator terms are the implemented terms" >&2
  exit 1
}

echo "architecture combinator alignment test passed"
