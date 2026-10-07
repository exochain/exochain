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
  printf 'github actions pinning test failed: %s\n' "$1" >&2
  exit 1
}

shopt -s nullglob

# Upstream requires full-SHA pins to come from master history; branch-generated
# stable/nightly/version commits may be garbage-collected. This is the verified
# master commit whose action accepts an explicit toolchain input. Upstream
# refs/heads/master resolved to this commit on 2026-09-04.
readonly rust_toolchain_action_sha="d1031067263f94b142dd6c0ce24c5eb9d02d52a0"

violations=()
for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  while IFS= read -r match; do
    line_no=${match%%:*}
    uses_ref=${match#*:}
    uses_ref=${uses_ref#*uses:}
    uses_ref=${uses_ref%%#*}
    uses_ref=$(printf '%s' "$uses_ref" | sed -E "s/^[[:space:]]+//;s/[[:space:]]+$//;s/^['\\\"]//;s/['\\\"]$//")

    [[ -z "$uses_ref" ]] && continue
    [[ "$uses_ref" == ./* ]] && continue

    ref=${uses_ref##*@}
    if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
      violations+=("${workflow}:${line_no}: ${uses_ref}")
    fi
  done < <(grep -nE 'uses:[[:space:]]+[^[:space:]#]+@[^[:space:]#]+' "$workflow" || true)
done

if ((${#violations[@]} > 0)); then
  printf '%s\n' "${violations[@]}" >&2
  fail "external actions must be pinned to immutable commit SHAs"
fi

if ! rust_toolchain_analysis=$(
  ruby - "$rust_toolchain_action_sha" .github/workflows/*.yml .github/workflows/*.yaml <<'RUBY'
require "psych"

def scalar_value(node)
  node.value if node.is_a?(Psych::Nodes::Scalar)
end

def mapping_pairs(node)
  return [] unless node.is_a?(Psych::Nodes::Mapping)

  node.children.each_slice(2).to_a
end

def walk(node, &block)
  yield node
  node.children&.each { |child| walk(child, &block) }
end

# Read the formatter contract from parsed YAML, not comment-satisfiable text.
def plain_node(node)
  case node
  when Psych::Nodes::Scalar
    node.value
  when Psych::Nodes::Sequence
    node.children.map { |child| plain_node(child) }
  when Psych::Nodes::Mapping
    mapping_pairs(node).each_with_object({}) do |(key, value), result|
      name = scalar_value(key)
      raise "duplicate or non-scalar YAML key" if name.nil? || result.key?(name)

      result[name] = plain_node(value)
    end
  else
    raise "unsupported YAML node in formatter contract"
  end
end

def formatter_contract?(job, gate, caller, expected_job, expected_caller)
  job == expected_job && gate.is_a?(Hash) &&
    gate["needs"].is_a?(Array) && gate["needs"].count("format") == 1 &&
    !gate.key?("if") && !gate.key?("continue-on-error") &&
    caller == [expected_caller]
end

def warning_env_safe?(env)
  return true if env.nil?
  return false unless env.is_a?(Hash) && !env.key?("CARGO_ENCODED_RUSTFLAGS")

  !env.key?("RUSTFLAGS") || env["RUSTFLAGS"] == "-D warnings"
end

def ci_contract?(root, action)
  jobs = root.fetch("jobs")
  expected = %w[build test coverage lint deny doc machete integration-tests
    integration-tests-db consensus-integration state-sync-integration cross-platform
    zerodentity-coverage root-genesis-coverage root-genesis-portal-coverage
    build-wasm unaudited-feature-matrix private-file-windows hygiene audit]
  expected_with = expected.to_h do |name|
    options = {"toolchain" => "1.98.1"}
    options["components"] = "rustfmt, clippy" if name == "build"
    options["components"] = "clippy" if name == "lint"
    options["targets"] = '${{ matrix.target }}' if name == "cross-platform"
    options["targets"] = "wasm32-unknown-unknown" if name == "build-wasm"
    [name, options]
  end
  conditional_if = {
    "integration-tests" => "steps.filter.outputs.gateway == 'true'",
    "consensus-integration" => "steps.filter.outputs.node == 'true'",
    "state-sync-integration" => "steps.filter.outputs.sync == 'true'",
    "unaudited-feature-matrix" => "steps.filter.outputs.crates == 'true'"
  }
  installations = Hash.new(0)
  jobs.each do |name, job|
    return false unless job.is_a?(Hash) && job["steps"].is_a?(Array)
    return false unless warning_env_safe?(job["env"])
    job["steps"].each do |step|
      return false unless step.is_a?(Hash) && warning_env_safe?(step["env"])
      uses = step["uses"]
      next unless uses.is_a?(String) && uses.start_with?("dtolnay/rust-toolchain@")

      installations[name] += 1
      wanted = expected_with[name] || {
        "format" => {"toolchain" => "nightly-2026-09-21", "components" => "rustfmt"},
        "sbom" => {"toolchain" => "1.97.1"}
      }[name]
      return false unless wanted
      expected_step = {"uses" => action, "with" => wanted}
      expected_step["if"] = conditional_if.fetch(name) if conditional_if.key?(name)
      return false unless step == expected_step
    end
  end
  return false unless installations == (expected + %w[format sbom]).to_h { |name| [name, 1] }
  return false unless root.fetch("env")["RUSTFLAGS"] == "-D warnings" &&
    warning_env_safe?(root.fetch("env"))
  return false if %w[build private-file-windows].any? { |name|
    jobs.fetch(name).key?("if") || jobs.fetch(name).key?("continue-on-error") }
  return false unless jobs.fetch("build").fetch("steps").count { |step|
    step["run"] == "bash tools/ci_cargo_retry.sh cargo build --workspace --release" &&
      !step.key?("if") && !step.key?("continue-on-error") } == 1
  return false unless jobs.fetch("private-file-windows").fetch("steps").count { |step|
    step["run"] == "cargo test -p exochain-node private_file::tests::windows -- --nocapture" &&
      !step.key?("if") && !step.key?("continue-on-error") } == 1

  lint = jobs.fetch("lint")
  return false if lint.key?("if") || lint.key?("continue-on-error")
  lint_steps = lint.fetch("steps")
  version_index = lint_steps.index { |step| step["name"] == "Report Rust and Clippy versions" }
  return false unless version_index && lint_steps[version_index] == {
    "name" => "Report Rust and Clippy versions",
    "run" => "rustc --version --verbose\ncargo clippy --version\n"
  }
  return false unless lint_steps[version_index + 1] == {
    "name" => "Clippy (all workspace targets, deny all warnings)",
    "run" => "cargo clippy --workspace --all-targets -- -D warnings"
  }
  hygiene = jobs.fetch("hygiene")
  gate = jobs.fetch("all-gates")
  return false if [hygiene, gate].any? { |job| job.key?("if") || job.key?("continue-on-error") }
  return false unless gate["needs"].is_a?(Array) && gate["needs"].uniq == gate["needs"] &&
    (expected + %w[hygiene format sbom]).all? { |name| gate["needs"].include?(name) }
  %w[test_github_actions_pinned test_ci_supply_chain_hardening].all? do |guard|
    hygiene.fetch("steps").count { |step| step["run"] == "bash tools/#{guard}.sh" &&
      !step.key?("if") && !step.key?("continue-on-error") } == 1
  end
end

expected_action_sha = ARGV.shift
expected_action = "dtolnay/rust-toolchain@#{expected_action_sha}"
formatter = "nightly-2026-09-21"
formatter_command = "cargo +#{formatter} fmt --all -- --check"
expected_formatter = {
  "name" => "Gate 5 — Format Check", "runs-on" => "ubuntu-latest",
  "steps" => [
    {"uses" => "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"},
    {"uses" => expected_action, "with" => {"toolchain" => formatter, "components" => "rustfmt"}},
    {"name" => "Check formatting", "run" => formatter_command}
  ]
}
expected_caller = 'FMT_OK=$(' + formatter_command + ' >/dev/null 2>&1 && echo "true" || echo "false")'

# Behavioral mutations protect the guard itself against weakened checks.
baseline = [expected_formatter, {"needs" => ["format"]}, [expected_caller]]
validate = lambda { |job, gate, caller| formatter_contract?(job, gate, caller, expected_formatter, expected_caller) }
raise "valid formatter contract rejected" unless validate.call(*baseline)
mutations = [
  ->(job, _gate, _caller) { job["steps"][1]["with"]["toolchain"] = "nightly" },
  ->(job, _gate, _caller) { job["steps"][1]["with"]["toolchain"] = "nightly-2026-09-22" },
  ->(job, _gate, _caller) { job["steps"][1]["with"]["toolchain"] = '${{ inputs.toolchain }}' },
  ->(job, _gate, _caller) { job["steps"][1]["with"]["components"] = "clippy" },
  ->(job, _gate, _caller) { job["steps"][2]["run"] = "cargo +nightly fmt --all -- --check" },
  ->(job, _gate, _caller) { job["steps"][2]["run"] = formatter_command.sub(" --all", "") },
  ->(job, _gate, _caller) { job["steps"][2]["run"] = formatter_command.sub(" --check", "") },
  ->(job, _gate, _caller) { job["steps"][2]["run"] += " || true" },
  ->(job, _gate, _caller) { job["steps"][2]["if"] = "false" },
  ->(job, _gate, _caller) { job["continue-on-error"] = "true" },
  ->(job, _gate, _caller) { job["if"] = "false" },
  ->(_job, gate, _caller) { gate["needs"] = [] },
  ->(_job, gate, _caller) { gate["if"] = "always()" },
  ->(_job, _gate, caller) { caller[0] = caller[0].sub(formatter, "nightly") },
  ->(_job, _gate, caller) { caller << caller.first }
]
mutations.each_with_index do |mutate, index|
  fixture = Marshal.load(Marshal.dump(baseline))
  mutate.call(*fixture)
  raise "formatter mutation #{index} accepted" if validate.call(*fixture)
end
warn "rejected #{mutations.length} formatter contract mutations"

# The contract must reject each realistic weakening before it inspects source.
fixture_jobs = ("build test coverage lint deny doc machete integration-tests integration-tests-db " \
  "consensus-integration state-sync-integration cross-platform zerodentity-coverage " \
  "root-genesis-coverage root-genesis-portal-coverage build-wasm unaudited-feature-matrix " \
  "private-file-windows format sbom hygiene audit all-gates").split.to_h do |name|
  with = {"toolchain" => "1.98.1"}
  with = {"toolchain" => "nightly-2026-09-21", "components" => "rustfmt"} if name == "format"
  with = {"toolchain" => "1.97.1"} if name == "sbom"
  with["components"] = "rustfmt, clippy" if name == "build"
  with["components"] = "clippy" if name == "lint"
  with["targets"] = '${{ matrix.target }}' if name == "cross-platform"
  with["targets"] = "wasm32-unknown-unknown" if name == "build-wasm"
  steps = name == "all-gates" ? [] : [{"uses" => expected_action, "with" => with}]
  conditional_if = {
    "integration-tests" => "steps.filter.outputs.gateway == 'true'",
    "consensus-integration" => "steps.filter.outputs.node == 'true'",
    "state-sync-integration" => "steps.filter.outputs.sync == 'true'",
    "unaudited-feature-matrix" => "steps.filter.outputs.crates == 'true'"
  }[name]
  steps.first["if"] = conditional_if if conditional_if
  steps += [{"name" => "Report Rust and Clippy versions", "run" => "rustc --version --verbose\ncargo clippy --version\n"},
    {"name" => "Clippy (all workspace targets, deny all warnings)",
     "run" => "cargo clippy --workspace --all-targets -- -D warnings"}] if name == "lint"
  steps += %w[test_github_actions_pinned test_ci_supply_chain_hardening].map do |guard|
    {"run" => "bash tools/#{guard}.sh"}
  end if name == "hygiene"
  steps << {"run" => "bash tools/ci_cargo_retry.sh cargo build --workspace --release"} if name == "build"
  steps << {"run" => "cargo test -p exochain-node private_file::tests::windows -- --nocapture"} if name == "private-file-windows"
  [name, {"steps" => steps}]
end
fixture_jobs["all-gates"]["needs"] = fixture_jobs.keys - ["all-gates"]
fixture = {"env" => {"RUSTFLAGS" => "-D warnings"}, "jobs" => fixture_jobs}
raise "valid CI fixture rejected" unless ci_contract?(fixture, expected_action)
ci_mutations = [
  ->(x) { x["jobs"].delete("build") },
  ->(x) { x["jobs"].delete("private-file-windows") },
  ->(x) { x["jobs"]["build"]["steps"] << x["jobs"]["build"]["steps"][0].dup },
  ->(x) { x["jobs"]["build"]["steps"][0]["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["private-file-windows"]["steps"][0]["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["build"]["steps"][0]["with"]["toolchain"] = "1.99.0" },
  ->(x) { x["jobs"]["build"]["steps"][0]["with"]["toolchain"] = '${{ inputs.rust }}' },
  ->(x) { x["jobs"]["test"]["steps"] << {"uses" => expected_action, "with" => {"toolchain" => "stable"}} },
  ->(x) { x["jobs"]["lint"]["steps"].last["run"] += " || true" },
  ->(x) { x["jobs"]["lint"]["steps"].last["run"] = "cargo clippy --workspace -- -D warnings" },
  ->(x) { x["jobs"]["lint"]["steps"].last["if"] = "false" },
  ->(x) { x["jobs"]["build"]["steps"].last["run"] += " || true" },
  ->(x) { x["jobs"]["private-file-windows"]["steps"].last["run"] += " || true" },
  ->(x) { x["jobs"]["build"]["if"] = "false" },
  ->(x) { x["jobs"]["private-file-windows"]["if"] = "false" },
  ->(x) { x["env"]["RUSTFLAGS"] = "-A warnings" },
  ->(x) { x["jobs"]["format"]["steps"][0]["with"]["toolchain"] = "nightly" },
  ->(x) { x["jobs"]["sbom"]["steps"][0]["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["hygiene"]["if"] = "false" },
  ->(x) { x["jobs"]["hygiene"]["steps"].first["if"] = "false" },
  ->(x) { x["jobs"]["hygiene"]["steps"].first["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["hygiene"]["steps"].first["with"]["toolchain"] = "1.99.0" },
  ->(x) { x["jobs"]["hygiene"]["steps"].shift },
  ->(x) { x["jobs"]["audit"]["steps"].first["with"]["toolchain"] = "stable" },
  ->(x) { x["jobs"]["audit"]["steps"].shift },
  ->(x) { x["jobs"]["all-gates"]["needs"].delete("hygiene") },
  ->(x) { x["jobs"]["all-gates"]["if"] = "always()" },
  ->(x) { x["jobs"]["build"]["steps"].first["if"] = "false" },
  ->(x) { x["jobs"]["private-file-windows"]["steps"].first["continue-on-error"] = "true" },
  ->(x) { x["jobs"]["integration-tests"]["steps"].first.delete("if") },
  ->(x) { x["jobs"]["consensus-integration"]["steps"].first["if"] = "always()" },
  ->(x) { x["jobs"]["state-sync-integration"]["steps"].first["if"] = "false" },
  ->(x) { x["jobs"]["unaudited-feature-matrix"]["steps"].first["if"] = "steps.filter.outputs.other == 'true'" },
  ->(x) { x["jobs"]["test"]["steps"].first["env"] = {"RUSTFLAGS" => "-A warnings"} },
  ->(x) { x["jobs"]["lint"]["steps"].first["name"] = "optional toolchain" },
  ->(x) { x["jobs"]["test"]["env"] = {"RUSTFLAGS" => "-A warnings"} },
  ->(x) { x["jobs"]["build"]["steps"].last["env"] = {"RUSTFLAGS" => "-A warnings"} },
  ->(x) { x["jobs"]["lint"]["steps"].last["env"] = {"RUSTFLAGS" => "-A warnings"} },
  ->(x) { x["env"]["CARGO_ENCODED_RUSTFLAGS"] = "-A warnings" },
  ->(x) { x["jobs"]["doc"]["env"] = {"CARGO_ENCODED_RUSTFLAGS" => "-A warnings"} },
  ->(x) { x["jobs"]["build"]["steps"].last["env"] = {"CARGO_ENCODED_RUSTFLAGS" => "-A warnings"} }
]
allowed_warning_override = Marshal.load(Marshal.dump(fixture))
allowed_warning_override["jobs"]["build"]["env"] = {"RUSTFLAGS" => "-D warnings"}
allowed_warning_override["jobs"]["build"]["steps"].last["env"] = {"RUSTFLAGS" => "-D warnings"}
raise "exact warning-denial override rejected" unless ci_contract?(allowed_warning_override, expected_action)
ci_mutations.each_with_index do |mutate, index|
  changed = Marshal.load(Marshal.dump(fixture))
  mutate.call(changed)
  raise "CI mutation #{index} accepted" if ci_contract?(changed, expected_action)
end
duplicate_rejected = begin
  plain_node(Psych.parse("jobs:\n  build: one\n  build: two\n").root)
  false
rescue RuntimeError
  true
end
raise "duplicate YAML job key accepted" unless duplicate_rejected
malformed_rejected = begin
  Psych.parse("jobs: [\n")
  false
rescue Psych::SyntaxError
  true
end
raise "malformed YAML accepted" unless malformed_rejected
warn "rejected #{ci_mutations.length} CI contract mutations, duplicate YAML job and malformed YAML"

ARGV.each do |workflow|
  document = Psych.parse_file(workflow)
  if workflow == ".github/workflows/ci.yml"
    jobs = plain_node(document.root).fetch("jobs")
    caller = File.readlines("tools/repo_truth.sh", chomp: true).select { |line| line.start_with?("FMT_OK=") }
    unless validate.call(jobs["format"], jobs["all-gates"], caller)
      puts "#{workflow}: full-workspace formatter and repo_truth must use #{formatter}, without skips or suppressed failures"
    end
    unless ci_contract?(plain_node(document.root), expected_action)
      puts "#{workflow}: Rust 1.98.1 compile inventory including hygiene and audit, full lint, and aggregator contract required"
    end
  end
  walk(document) do |node|
    if node.is_a?(Psych::Nodes::Alias)
      puts "#{workflow}:#{node.start_line + 1}: YAML aliases cannot carry auditable action identity"
      next
    end

    pairs = mapping_pairs(node)
    uses_pairs = pairs.select { |key, _value| scalar_value(key) == "uses" }
    rust_uses = uses_pairs.select do |_key, value|
      scalar_value(value)&.strip&.downcase&.start_with?("dtolnay/rust-toolchain@")
    end
    next if rust_uses.empty?

    uses_key, uses_value = rust_uses.first
    line_no = uses_key.start_line + 1
    if uses_pairs.length != 1 || rust_uses.length != 1
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain step must contain exactly one uses key"
      next
    end
    unless scalar_value(uses_value) == expected_action
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain must use verified master-history commit #{expected_action_sha}"
      next
    end

    with_pairs = pairs.select { |key, _value| scalar_value(key) == "with" }
    unless with_pairs.length == 1 && with_pairs.first.last.is_a?(Psych::Nodes::Mapping)
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain requires exactly one with mapping"
      next
    end

    toolchain_pairs = mapping_pairs(with_pairs.first.last).select do |key, _value|
      scalar_value(key) == "toolchain"
    end
    unless toolchain_pairs.length == 1 && toolchain_pairs.first.last.is_a?(Psych::Nodes::Scalar)
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain requires exactly one scalar with.toolchain value"
      next
    end

    toolchain = scalar_value(toolchain_pairs.first.last)
    unless toolchain == formatter || toolchain&.match?(/\A(?:stable|nightly|1\.[0-9]+\.[0-9]+)\z/)
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain requires a literal stable, nightly, #{formatter}, or exact 1.x.y toolchain"
    end
  end
rescue Psych::SyntaxError => error
  warn "#{workflow}:#{error.line}: invalid workflow YAML: #{error.problem}"
  exit 1
end
RUBY
); then
  fail "workflow YAML could not be parsed while validating dtolnay/rust-toolchain"
fi

rust_toolchain_violations=()
while IFS= read -r violation; do
  [[ -n "$violation" ]] && rust_toolchain_violations+=("$violation")
done <<<"$rust_toolchain_analysis"

if ((${#rust_toolchain_violations[@]} > 0)); then
  printf '%s\n' "${rust_toolchain_violations[@]}" >&2
  fail "pinned dtolnay/rust-toolchain actions must select a supported literal toolchain through with.toolchain"
fi

printf 'github actions pinning test passed\n'
