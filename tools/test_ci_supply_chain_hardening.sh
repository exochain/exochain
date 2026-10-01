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

fail() {
  printf 'ci supply-chain hardening test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/ci.yml"
release_workflow=".github/workflows/release.yml"
retry_helper="tools/ci_cargo_retry.sh"
[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$release_workflow" ]] || fail "$release_workflow is missing"
[[ -f "$retry_helper" ]] || fail "$retry_helper is missing"

if grep -nE 'curl[^\n]*(\|[[:space:]]*(sh|bash)|>[[:space:]]*/tmp/)' "$workflow"; then
  fail "GitHub Actions workflow must not install tools through curl-piped shell scripts"
fi

for checked_workflow in "$workflow" "$release_workflow"; do
  grep -F 'CARGO_NET_RETRY: "10"' "$checked_workflow" >/dev/null \
    || fail "$checked_workflow must set CARGO_NET_RETRY for registry fetch resilience"
  grep -F 'CARGO_HTTP_TIMEOUT: "120"' "$checked_workflow" >/dev/null \
    || fail "$checked_workflow must set CARGO_HTTP_TIMEOUT for registry fetch resilience"
  grep -F 'CARGO_HTTP_MULTIPLEXING: "false"' "$checked_workflow" >/dev/null \
    || fail "$checked_workflow must disable Cargo HTTP multiplexing for CI fetch resilience"
done

if grep -nE 'run:[[:space:]]+cargo build[[:space:]]+' "$workflow" "$release_workflow"; then
  fail "cargo build steps must use $retry_helper"
fi

if grep -nE 'run:[[:space:]]+cargo install[[:space:]]+' "$workflow" "$release_workflow"; then
  fail "cargo install steps must use $retry_helper"
fi

if grep -nE 'run:[[:space:]]+wasm-pack build[[:space:]]+' "$workflow" "$release_workflow"; then
  fail "wasm-pack build steps must use $retry_helper"
fi

cargo_install_lines=0
for checked_workflow in "$workflow" "$release_workflow"; do
  while IFS=: read -r line_no line; do
    [[ -n "$line_no" ]] || continue
    cargo_install_lines=$((cargo_install_lines + 1))
    if ! grep -Fq -- "$retry_helper cargo install" <<<"$line"; then
      fail "$checked_workflow:$line_no cargo install must use $retry_helper: $line"
    fi
    if ! grep -Eq -- '--version[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)' <<<"$line"; then
      fail "$checked_workflow:$line_no cargo install must pin an explicit x.y.z --version: $line"
    fi
    if ! grep -Fq -- '--locked' <<<"$line"; then
      fail "$checked_workflow:$line_no cargo install must use --locked: $line"
    fi
  done < <(grep -nE 'cargo install[[:space:]]+' "$checked_workflow" || true)
done

[[ "$cargo_install_lines" -gt 0 ]] || fail "expected workflows to contain Cargo tool installs"

install_block=$(
  awk '
    /name: Install wasm-pack/ { capture = 1 }
    capture { print }
    capture && /name: Build WASM/ { exit }
  ' "$workflow"
)

[[ -n "$install_block" ]] || fail "CI workflow must include an Install wasm-pack step"

grep -F 'cargo install wasm-pack' <<<"$install_block" >/dev/null \
  || fail "wasm-pack must be installed through Cargo, not a shell installer"

grep -E -- '--version[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' <<<"$install_block" >/dev/null \
  || fail "wasm-pack Cargo install must pin an explicit version"

grep -F -- '--locked' <<<"$install_block" >/dev/null \
  || fail "wasm-pack Cargo install must use --locked for dependency resolution"

# Parse the Deny job, then execute its actual run strings with a controlled
# cargo executable. The fixture never delegates to the host Cargo or network.
ruby - "$workflow" <<'RUBY' || fail "parsed Deny job or shell boundary violated"
require "psych"
require "tmpdir"
require "open3"

def scalar(node)
  node.value if node.is_a?(Psych::Nodes::Scalar)
end

def plain(node)
  case node
  when Psych::Nodes::Scalar then node.value
  when Psych::Nodes::Sequence then node.children.map { |child| plain(child) }
  when Psych::Nodes::Mapping
    node.children.each_slice(2).each_with_object({}) do |(key, value), result|
      name = scalar(key)
      raise "duplicate or non-scalar YAML key" if name.nil? || result.key?(name)
      result[name] = plain(value)
    end
  else
    raise "unsupported YAML node"
  end
end

checkout = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
toolchain = "dtolnay/rust-toolchain@d1031067263f94b142dd6c0ce24c5eb9d02d52a0"
install_run = "bash tools/ci_cargo_retry.sh cargo install cargo-deny --version 0.19.2 --locked"
version_run = "VERSION=\"$(cargo deny --version)\"\nprintf '%s\\n' \"$VERSION\"\ntest \"$VERSION\" = 'cargo-deny 0.19.2'\n"
check_run = "cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check"
expected_steps = [
  {"uses" => checkout},
  {"uses" => toolchain, "with" => {"toolchain" => "1.98.1"}},
  {"name" => "Install cargo-deny", "env" => {"CI_CARGO_RETRY_ATTEMPTS" => "1"}, "run" => install_run},
  {"name" => "Verify cargo-deny version", "run" => version_run},
  {"name" => "Check dependency policy", "env" => {"CARGO_NET_GIT_FETCH_WITH_CLI" => "false"}, "run" => check_run},
  {"name" => "Workspace dependency exact pin guard", "run" => "bash tools/test_security_critical_dependencies_pinned.sh"}
]
valid = lambda do |root|
  jobs = root.fetch("jobs")
  job = jobs.fetch("deny")
  gate = jobs.fetch("all-gates")
  job == {"name" => "Gate 7 — Cargo Deny", "runs-on" => "ubuntu-latest",
    "timeout-minutes" => "30", "steps" => expected_steps} &&
    gate.is_a?(Hash) && !gate.key?("if") && !gate.key?("continue-on-error") &&
    gate["needs"].is_a?(Array) && gate["needs"].count("deny") == 1
end

fixture = {"jobs" => {"deny" => {"name" => "Gate 7 — Cargo Deny", "runs-on" => "ubuntu-latest",
  "timeout-minutes" => "30", "steps" => Marshal.load(Marshal.dump(expected_steps))},
  "all-gates" => {"needs" => ["deny"]}}}
raise "valid Deny fixture rejected" unless valid.call(fixture)
mutations = [
  ->(x) { x["jobs"]["deny"].delete("timeout-minutes") },
  ->(x) { x["jobs"]["deny"]["runs-on"] = "macos-latest" },
  ->(x) { x["jobs"]["deny"]["steps"][1]["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["deny"]["steps"][2]["run"] = install_run.sub("0.19.2", "0.19.3") },
  ->(x) { x["jobs"]["deny"]["steps"][2]["run"] = install_run.sub(" --locked", "") },
  ->(x) { x["jobs"]["deny"]["steps"][2]["env"]["CI_CARGO_RETRY_ATTEMPTS"] = "2" },
  ->(x) { x["jobs"]["deny"]["steps"][3]["run"] = "cargo deny --version" },
  ->(x) { x["jobs"]["deny"]["steps"][3]["run"] += " || true" },
  ->(x) { x["jobs"]["deny"]["steps"][4]["run"] = check_run.sub(" --all-features", "") },
  ->(x) { x["jobs"]["deny"]["steps"][4]["run"] = check_run.sub(" --manifest-path ./Cargo.toml", "") },
  ->(x) { x["jobs"]["deny"]["steps"][4]["run"] = "cargo deny check licenses" },
  ->(x) { x["jobs"]["deny"]["steps"][4]["run"] += " || true" },
  ->(x) { x["jobs"]["deny"]["steps"][4]["env"]["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true" },
  ->(x) { x["jobs"]["deny"]["steps"][4]["continue-on-error"] = "true" },
  ->(x) { x["jobs"]["deny"]["steps"][2]["if"] = "false" },
  ->(x) { x["jobs"]["deny"]["steps"].delete_at(5) },
  ->(x) { x["jobs"]["deny"]["steps"][4], x["jobs"]["deny"]["steps"][5] = x["jobs"]["deny"]["steps"][5], x["jobs"]["deny"]["steps"][4] },
  ->(x) { x["jobs"]["deny"]["steps"] << {"run" => "cargo deny check"} },
  ->(x) { x["jobs"]["all-gates"]["needs"] = [] },
  ->(x) { x["jobs"]["all-gates"]["if"] = "always()" }
]
mutations.each_with_index do |mutate, index|
  altered = Marshal.load(Marshal.dump(fixture))
  mutate.call(altered)
  raise "Deny mutation #{index} accepted" if valid.call(altered)
end
puts "rejected #{mutations.length} Deny contract mutations"

root = plain(Psych.parse_file(ARGV.fetch(0)).root)
raise "current Deny job uses Docker action or differs from locked, fail-closed 0.19.2 contract" unless valid.call(root)

directory = Dir.mktmpdir("exochain-ci-deny-shell-")
raise "fixture directory must be absolute" unless directory.start_with?("/")
fake = File.join(directory, "cargo")
File.write(fake, <<~SH)
  #!/usr/bin/env bash
  printf 'CALL\\0' >> "$FIXTURE_CALLS"
  printf '%s\\0' "$@" >> "$FIXTURE_CALLS"
  printf 'END\\0' >> "$FIXTURE_CALLS"
  if [[ "$1" == "install" ]]; then exit "$FIXTURE_INSTALL_STATUS"; fi
  if [[ "$1" == "deny" && "$2" == "--version" ]]; then
    printf '%s\\n' "$FIXTURE_VERSION"
    exit 0
  fi
  if [[ "$1" == "deny" ]]; then exit "$FIXTURE_CHECK_STATUS"; fi
  exit 91
SH
File.chmod(0755, fake)
env_base = {"PATH" => "#{directory}:/usr/bin:/bin",
  "CI_CARGO_RETRY_ATTEMPTS" => "1", "CARGO_NET_GIT_FETCH_WITH_CLI" => "false"}
resolved, status = Open3.capture2(env_base, "bash", "-c", "command -v cargo")
raise "fixture cargo does not shadow host Cargo" unless status.success? && resolved.strip == fake
steps = root.fetch("jobs").fetch("deny").fetch("steps")
cases = [
  ["install-fails", "17", "cargo-deny 0.19.2", "0", 17,
    [["install", "cargo-deny", "--version", "0.19.2", "--locked"]]],
  ["wrong-version", "0", "cargo-deny 0.19.3", "0", 1,
    [["install", "cargo-deny", "--version", "0.19.2", "--locked"], ["deny", "--version"]]],
  ["check-fails", "0", "cargo-deny 0.19.2", "19", 19,
    [["install", "cargo-deny", "--version", "0.19.2", "--locked"], ["deny", "--version"],
     ["deny", "--log-level", "warn", "--manifest-path", "./Cargo.toml", "--all-features", "check"]]],
  ["success", "0", "cargo-deny 0.19.2", "0", 0,
    [["install", "cargo-deny", "--version", "0.19.2", "--locked"], ["deny", "--version"],
     ["deny", "--log-level", "warn", "--manifest-path", "./Cargo.toml", "--all-features", "check"]]]
]
cases.each do |name, install_status, version, check_status, wanted_status, wanted_calls|
  calls = File.join(directory, "#{name}.calls")
  env = env_base.merge("FIXTURE_CALLS" => calls, "FIXTURE_INSTALL_STATUS" => install_status,
    "FIXTURE_VERSION" => version, "FIXTURE_CHECK_STATUS" => check_status)
  status = 0
  output = +""
  steps[2..4].each do |step|
    stdout, stderr, result = Open3.capture3(env.merge(step.fetch("env", {})),
      "bash", "-e", "-o", "pipefail", "-c", step.fetch("run"))
    output << stdout << stderr
    status = result.exitstatus
    break unless status == 0
  end
  File.write(File.join(directory, "#{name}.log"), output + "exit_status=#{status}\n")
  tokens = File.exist?(calls) ? File.binread(calls).split("\0") : []
  observed = []
  until tokens.empty?
    raise "#{name}: malformed call record" unless tokens.shift == "CALL"
    ending = tokens.index("END")
    raise "#{name}: unterminated call record" unless ending
    observed << tokens.shift(ending)
    tokens.shift
  end
  raise "#{name}: status #{status}, wanted #{wanted_status}" unless status == wanted_status
  raise "#{name}: argv/call order #{observed.inspect}" unless observed == wanted_calls
end
puts "Deny shell fixtures passed (4 cases); raw outputs: #{directory}"
RUBY

printf 'ci supply-chain hardening test passed\n'
