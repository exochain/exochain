#!/usr/bin/env bash
# Fast regression checks for the repo-truth generator and the README claims that
# are supposed to be derived from it.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "repo-truth test failed: $*" >&2
  exit 1
}

if grep -n -- 'grep -oP' tools/repo_truth.sh >/tmp/repo_truth_portability.txt; then
  cat /tmp/repo_truth_portability.txt >&2
  fail "tools/repo_truth.sh must not use grep -P; macOS grep does not support it"
fi

err_file=$(mktemp)
json_file=$(mktemp)
fake_err_file=$(mktemp)
fake_json_file=$(mktemp)
fake_bin_dir=$(mktemp -d)
trap 'rm -f "$err_file" "$json_file" "$fake_err_file" "$fake_json_file" /tmp/repo_truth_portability.txt; rm -rf "$fake_bin_dir"' EXIT

if ! bash tools/repo_truth.sh --json --skip-tests >"$json_file" 2>"$err_file"; then
  cat "$err_file" >&2
  fail "tools/repo_truth.sh --json --skip-tests exited non-zero"
fi

if [ -s "$err_file" ]; then
  cat "$err_file" >&2
  fail "tools/repo_truth.sh --json --skip-tests must not write stderr"
fi

jq -e . "$json_file" >/dev/null

real_cargo=$(command -v cargo)
cat >"$fake_bin_dir/cargo" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "+nightly" ] && [ "\${2:-}" = "fmt" ]; then
  echo "nightly formatter unavailable"
  echo "rustup formatter error" >&2
  exit 1
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$fake_bin_dir/cargo"

if ! PATH="$fake_bin_dir:$PATH" bash tools/repo_truth.sh --json --skip-tests >"$fake_json_file" 2>"$fake_err_file"; then
  cat "$fake_err_file" >&2
  fail "tools/repo_truth.sh must still emit JSON when formatter check fails"
fi

if [ -s "$fake_err_file" ]; then
  cat "$fake_err_file" >&2
  fail "formatter check output must not leak to stderr in JSON mode"
fi

jq -e . "$fake_json_file" >/dev/null
fake_fmt_clean=$(jq -r '.fmt_clean' "$fake_json_file")
[ "$fake_fmt_clean" = "false" ] || fail "formatter failure should report fmt_clean=false, got $fake_fmt_clean"

expected_crates=$(cargo metadata --no-deps --format-version 1 | jq '.packages | length')
actual_crates=$(jq '.crates' "$json_file")
[ "$actual_crates" = "$expected_crates" ] || fail "crate count $actual_crates != $expected_crates"

expected_rs_files=$(git ls-files 'crates/**/*.rs' | wc -l | tr -d ' ')
actual_rs_files=$(jq '.rust_source_files' "$json_file")
[ "$actual_rs_files" = "$expected_rs_files" ] || fail "Rust source file count $actual_rs_files != $expected_rs_files"

expected_rs_loc=$(git ls-files 'crates/**/*.rs' | xargs wc -l | tail -1 | awk '{print $1}')
actual_rs_loc=$(jq '.rust_loc' "$json_file")
[ "$actual_rs_loc" = "$expected_rs_loc" ] || fail "Rust LOC $actual_rs_loc != $expected_rs_loc"

expected_gates=$(grep -E 'name: "Gate [0-9]+' .github/workflows/ci.yml | sed -E 's/.*Gate ([0-9]+).*/\1/' | sort -n | uniq | wc -l | tr -d ' ')
actual_gates=$(jq '.ci_gates.numbered' "$json_file")
[ "$actual_gates" = "$expected_gates" ] || fail "CI gate count $actual_gates != $expected_gates"

grep -F 'cargo clippy --workspace --all-targets -- -D warnings' .github/workflows/ci.yml >/dev/null \
  || fail "CI clippy gate must cover all workspace targets"
if grep -nE 'cargo clippy --workspace --(lib|bins|tests|benches)' .github/workflows/ci.yml; then
  fail "CI clippy gate must not split target classes; use --all-targets"
fi

test_mode=$(jq -r '.tests.mode' "$json_file")
[ "$test_mode" = "skipped" ] || fail "--skip-tests should report tests.mode=skipped, got $test_mode"

grep -F "| Rust crates | $expected_crates |" README.md >/dev/null || fail "README crate count is not repo-truth derived"
grep -F "| Rust source files | $expected_rs_files |" README.md >/dev/null || fail "README Rust source file count is not repo-truth derived"
grep -F "| Rust LOC | $expected_rs_loc |" README.md >/dev/null || fail "README Rust LOC is not repo-truth derived"
grep -F "| CI quality gates | $expected_gates |" README.md >/dev/null || fail "README CI gate count is not repo-truth derived"

if grep -nE 'Autonomous implementation engine|Core Crates \(16\)|16 crates|1,846 tests|1,603 workspace tests' README.md; then
  fail "README contains stale Basalt truth claims"
fi

echo "repo-truth test passed"
