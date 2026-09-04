#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'LYNK lifecycle boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=.github/workflows/release.yml
transport=tools/transport_release_file_set.py
[ -f "$workflow" ] || fail "$workflow is missing"
[ -f "$transport" ] || fail "$transport is missing"

python_path="${PYTHON:-$(command -v python3)}"
python_path="$($python_path -c 'import os,sys; print(os.path.realpath(sys.executable))')"
[ -f "$python_path" ] && [ -x "$python_path" ] && [ ! -L "$python_path" ] \
  || fail "a real Python interpreter is required"
"$python_path" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required"

# Bind the inline production sequence: immutable-source validation, clean test
# compilation, test lifecycle, a second clean boundary, final build, transport.
"$python_path" -I -B - "$workflow" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
start = text.index("  test-llm-proxy-npm:\n")
end = text.index("  prepare-llm-proxy-npm:\n", start)
job = text[start:end]
verify = job.index("llm-source \"$RELEASE_LLM_PACKAGE_DIR\"")
install = job.index('"$npm_path" ci --ignore-scripts', verify)
test = job.index('"$npm_path" run test:coverage', install)
build = job.index('"$npm_path" run build', test)
transport = job.index("--profile llm-dist", build)

clean_token = '''/bin/rm -rf -- \\
            "$RELEASE_LLM_PACKAGE_DIR/dist" \\
            "$RELEASE_LLM_PACKAGE_DIR/dist-test"'''
first_clean = job.index(clean_token, verify)
second_clean = job.index(clean_token, first_clean + len(clean_token))
if not (verify < first_clean < install < test < second_clean < build < transport):
    raise SystemExit("LYNK lifecycle clean/build/transport sequence is not fail-closed")
if job.find(clean_token, second_clean + len(clean_token)) != -1:
    raise SystemExit("unexpected third LYNK cleanup obscures the lifecycle boundary")
PY

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-llm-clean-build.XXXXXX")"
trap '/bin/rm -rf -- "$fixture_root"' EXIT
stale_dist="$fixture_root/stale-dist"
clean_dist="$fixture_root/clean-dist"
mkdir -p "$stale_dist" "$clean_dist"

suffixes=(.d.ts .d.ts.map .js .js.map)
stems=(cli delivery evidence index mcp openai receipt types)
for stem in "${stems[@]}"; do
  for suffix in "${suffixes[@]}"; do
    printf 'reviewed-%s%s\n' "$stem" "$suffix" > "$stale_dist/$stem$suffix"
  done
done

# Control: a compiler that no longer emits cli outputs leaves the four stale
# allowed filenames behind. The exact 32-file profile alone accepts that tree,
# which reproduces why cleaning immediately before the final build is required.
for stem in delivery evidence index mcp openai receipt types; do
  for suffix in "${suffixes[@]}"; do
    printf 'fresh-%s%s\n' "$stem" "$suffix" > "$stale_dist/$stem$suffix"
  done
done
printf 'ATTACKER-STALE-CLI\n' > "$stale_dist/cli.js"
"$python_path" -I -B "$transport" create \
  --profile llm-dist --version 0.2.6 \
  --input-dir "$stale_dist" \
  --archive "$fixture_root/stale.tar" \
  --inventory "$fixture_root/stale.inventory" >/dev/null \
  || fail "control tree should reproduce the stale allowed-file bypass"

# Production behavior starts the final build with an absent dist tree. The
# same compiler output is incomplete and therefore cannot become transport.
/bin/rm -rf -- "$clean_dist"
/bin/mkdir -m 700 "$clean_dist"
for stem in delivery evidence index mcp openai receipt types; do
  for suffix in "${suffixes[@]}"; do
    printf 'fresh-%s%s\n' "$stem" "$suffix" > "$clean_dist/$stem$suffix"
  done
done
if "$python_path" -I -B "$transport" create \
    --profile llm-dist --version 0.2.6 \
    --input-dir "$clean_dist" \
    --archive "$fixture_root/clean.tar" \
    --inventory "$fixture_root/clean.inventory" >/dev/null 2>&1; then
  fail "clean final build accepted a missing compiler output via stale bytes"
fi

printf 'LYNK lifecycle boundary test passed\n'
