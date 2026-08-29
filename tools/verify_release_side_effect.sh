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

github_sha="${GITHUB_SHA:-}"
if ! [[ "$github_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GITHUB_SHA must be a full lowercase 40-character commit SHA." >&2
  exit 1
fi

# This wrapper and both child guards are loaded from the immutable workflow
# dispatch commit. A build tool or npm lifecycle script may mutate checkout
# files, but it cannot replace the guard code executed at a release boundary.
GIT_NO_REPLACE_OBJECTS=1 git show "${GITHUB_SHA}:tools/verify_release_source.sh" | \
  GIT_NO_REPLACE_OBJECTS=1 BASH_ENV=/dev/null bash
GIT_NO_REPLACE_OBJECTS=1 git show "${GITHUB_SHA}:tools/verify_release_tag.sh" | \
  GIT_NO_REPLACE_OBJECTS=1 BASH_ENV=/dev/null bash
