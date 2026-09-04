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

expected_action_sha = ARGV.shift
expected_action = "dtolnay/rust-toolchain@#{expected_action_sha}"

ARGV.each do |workflow|
  document = Psych.parse_file(workflow)
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
    unless toolchain&.match?(/\A(?:stable|nightly|1\.[0-9]+\.[0-9]+)\z/)
      puts "#{workflow}:#{line_no}: dtolnay/rust-toolchain requires a literal with.toolchain value of stable, nightly, or an exact 1.x.y release"
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
