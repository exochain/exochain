#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'LYNK lifecycle boundary test failed: %s\n' "$1" >&2
  exit 1
}

case "${1:-}" in
  '') benign_only=false ;;
  --benign-only) benign_only=true ;;
  *) fail "usage: $0 [--benign-only]" ;;
esac
[ "$#" -le 1 ] || fail "usage: $0 [--benign-only]"

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
import json
import subprocess
import sys
import tempfile
import textwrap

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

# Exercise the actual workflow archive pipeline. Omitting the shared Rust/TS
# fixtures must fail here, before package coverage runs from the isolated tree.
archive_git = job.index('/usr/bin/git --no-replace-objects -C "$GITHUB_WORKSPACE" archive')
archive_start = job.rfind("          /usr/bin/env -i \\\n", 0, archive_git)
archive_end = job.index('\n          [ -d "$RELEASE_LLM_PACKAGE_DIR" ]', archive_git)
if archive_start < 0:
    raise SystemExit("LYNK immutable source archive pipeline is missing")
if archive_end >= verify:
    raise SystemExit("LYNK source archive must precede source validation and lifecycle execution")
archive_program = textwrap.dedent(job[archive_start:archive_end])
repository = Path.cwd().resolve()
git_env = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
}
git = ["/usr/bin/git", "--no-replace-objects", "-C", str(repository)]
head = subprocess.check_output(git + ["rev-parse", "HEAD"], env=git_env, text=True).strip()
fixture_paths = (
    "crates/exo-node/fixtures/lynk/rust_receipt_emit_response_v1.json",
    "crates/exo-node/fixtures/lynk/typescript_receipt_emit_request_v1.json",
)
expected = {
    path: subprocess.check_output(git + ["show", f"{head}:{path}"], env=git_env)
    for path in fixture_paths
}
with tempfile.TemporaryDirectory(prefix="exochain-llm-source-fixtures.") as source_root:
    subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-p", "-c", "set -euo pipefail\n" + archive_program],
        env={
            **git_env,
            "GITHUB_WORKSPACE": str(repository),
            "GITHUB_SHA": head,
            "RELEASE_LLM_SOURCE_ROOT": source_root,
        },
        check=True,
    )
    for path, committed_bytes in expected.items():
        captured = Path(source_root, path)
        if not captured.is_file() or captured.is_symlink():
            raise SystemExit(f"LYNK captured source is missing required canonical fixture: {path}")
        if captured.read_bytes() != committed_bytes:
            raise SystemExit(f"LYNK captured fixture differs from the exact committed source: {path}")
        with captured.open(encoding="utf-8") as fixture:
            json.load(fixture)
PY

if [ "$benign_only" = true ]; then
  printf 'LYNK lifecycle ordering and captured fixture guards passed\n'
  exit 0
fi

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-llm-clean-build.XXXXXX")"
trap '/bin/rm -rf -- "$fixture_root"' EXIT
stale_dist="$fixture_root/stale-dist"
clean_dist="$fixture_root/clean-dist"
mkdir -p "$stale_dist" "$clean_dist"

suffixes=(.d.ts .d.ts.map .js .js.map)
stems=()
for source in packages/exochain-llm-proxy/src/*.ts; do
  [ -f "$source" ] && [ ! -L "$source" ] || fail "LYNK source must be a regular file"
  stem="${source##*/}"
  stems+=("${stem%.ts}")
done
for stem in "${stems[@]}"; do
  for suffix in "${suffixes[@]}"; do
    printf 'reviewed-%s%s\n' "$stem" "$suffix" > "$stale_dist/$stem$suffix"
  done
done

# Control: a compiler that no longer emits cli outputs leaves the four stale
# allowed filenames behind. The exact current profile alone accepts that tree,
# which reproduces why cleaning immediately before the final build is required.
for stem in "${stems[@]}"; do
  [ "$stem" = cli ] && continue
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
for stem in "${stems[@]}"; do
  [ "$stem" = cli ] && continue
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
