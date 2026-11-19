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
#
# Sibling-removal experiment for the issue #904 audit (part 5, Method item 5).
#
# Usage: bash sibling_removal_run.sh <repository> <empty-work-directory>
#
# Runs the guard commands of ci.yml that compile nothing, twice: in a
# byte-exact export of the audited commit (`full`) and in the same export
# with the removal list deleted (`core`). cargo, npm, docker and the
# network tools are replaced by stubs that exit 97, so nothing is compiled
# or downloaded. Writes <work>/results.tsv with one row per guard and tree:
# ci.yml line, tree, exit code, number of stub calls, command. Per-guard
# logs go to <work>/logs/. Nothing is written inside <repository>.
#
# A guard that exits 0 in `full` and non-zero in `core` depends on a deleted
# path. A guard that fails in both says nothing either way on this machine.
set -u
if [ "$#" -ne 2 ]; then
  echo "usage: bash sibling_removal_run.sh <repository> <empty-work-directory>" >&2
  exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$1" && pwd)"
SHA=e6ecf4388a69fa3a1a352ebda4c8226697dcfd2e
mkdir -p "$2"
E="$(cd "$2" && pwd)"
if [ -n "$(ls -A "$E")" ]; then
  echo "work directory is not empty: $E" >&2
  exit 2
fi
PY="$(command -v python3 || command -v python)"
mkdir -p "$E/full" "$E/stub" "$E/logs" "$E/nohooks"
for t in cargo docker npm npx pip pip3 curl wget gh wasm-pack rustc rustup; do
  printf '#!/usr/bin/env bash\necho "stub: %s refused" >&2\nexit 97\n' "$t" > "$E/stub/$t"
  chmod +x "$E/stub/$t"
done
git -C "$REPO" -c core.autocrlf=false -c core.eol=lf archive "$SHA" | tar -x -C "$E/full"
"$PY" -I -B "$HERE/sibling_removal_prep.py" "$HERE/path-classification.tsv" \
  "$E/full/.github/workflows/ci.yml" "$E/remove.txt" "$E/guards.tsv"
cp -a "$E/full" "$E/core"
( cd "$E/core" && while IFS= read -r p; do rm -f -- "$p"; done < "$E/remove.txt"; find . -depth -type d -empty -delete )
for t in full core; do
  ( cd "$E/$t" && git init -q && git config core.autocrlf false && git config core.hooksPath "$E/nohooks" \
    && git config user.email audit@example.invalid && git config user.name audit \
    && git add -A >/dev/null 2>&1 && git commit -q -m "export $t" )
done
printf 'ci_line\ttree\texit_code\tstub_calls\tcommand\n' > "$E/results.tsv"
while IFS=$'\t' read -r line cmd; do
  for t in full core; do
    log="$E/logs/$line-$t.log"
    ( cd "$E/$t" && PATH="$E/stub:$PATH" timeout 180 bash -c "$cmd" ) > "$log" 2>&1
    code=$?
    stub=$(grep -c '^stub: ' "$log")
    printf '%s\t%s\t%s\t%s\t%s\n' "$line" "$t" "$code" "$stub" "$cmd" >> "$E/results.tsv"
  done
done < "$E/guards.tsv"
sha256sum "$E/remove.txt" "$E/results.tsv"
