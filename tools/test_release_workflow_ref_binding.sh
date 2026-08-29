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
  printf 'release workflow ref-binding test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
source_guard="tools/verify_release_source.sh"
tag_guard="tools/verify_release_tag.sh"
[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$source_guard" ]] || fail "$source_guard is missing"
[[ -f "$tag_guard" ]] || fail "$tag_guard is missing"

# Parse the workflow as YAML and reject duplicate mapping keys. YAML parsers
# otherwise commonly accept the last duplicate silently, which can replace a
# guarded `run` block with an unguarded one.
ruby - "$workflow" <<'RUBY'
require "psych"

class DuplicateMappingKey < StandardError; end

def assert_unique_mapping_keys(node, source, path = "$")
  if node.is_a?(Psych::Nodes::Mapping)
    seen = {}
    node.children.each_slice(2) do |key, value|
      if key.is_a?(Psych::Nodes::Scalar)
        location = "#{path}.#{key.value}"
        raise DuplicateMappingKey, "#{source}: duplicate mapping key #{location}" if seen.key?(key.value)
        seen[key.value] = true
        assert_unique_mapping_keys(value, source, location)
      else
        assert_unique_mapping_keys(value, source, path)
      end
    end
  elsif node.respond_to?(:children) && node.children
    node.children.each_with_index do |child, index|
      assert_unique_mapping_keys(child, source, "#{path}[#{index}]")
    end
  end
end

workflow_path = ARGV.fetch(0)
assert_unique_mapping_keys(Psych.parse_file(workflow_path), workflow_path)

fixture = Psych.parse_stream("jobs:\n  publish:\n    steps:\n      - run: guarded\n        run: unguarded\n")
begin
  assert_unique_mapping_keys(fixture, "duplicate-key regression fixture")
  warn "duplicate-key regression fixture was accepted"
  exit 1
rescue DuplicateMappingKey
  # Expected: proves the guard rejects the class of malformed workflow.
end
RUBY

repo_root="$(pwd -P)"
fixture_root="$(mktemp -d)"
fixture_dir="$fixture_root/checkout"
fixture_remote="$fixture_root/remote.git"
trap 'rm -rf "$fixture_root"' EXIT
git init --bare -q "$fixture_remote"
git init -q "$fixture_dir"
git -C "$fixture_dir" config user.name EXOCHAIN
git -C "$fixture_dir" config user.email release-test@example.invalid
git -C "$fixture_dir" config commit.gpgSign false
git -C "$fixture_dir" config tag.gpgSign false
printf 'tracked\n' > "$fixture_dir/tracked.txt"
git -C "$fixture_dir" add tracked.txt
git -C "$fixture_dir" commit -qm fixture
fixture_sha="$(git -C "$fixture_dir" rev-parse HEAD)"
git -C "$fixture_dir" remote add origin "$fixture_remote"
git -C "$fixture_dir" push -q origin HEAD

run_source_guard() {
  local expected_sha="$1"
  local dispatch_sha="$2"
  local trusted_ref="$3"
  (
    cd "$fixture_dir"
    EXPECTED_COMMIT_SHA="$expected_sha" \
      GITHUB_SHA="$dispatch_sha" \
      TRUSTED_RELEASE_REF="$trusted_ref" \
      bash "$repo_root/$source_guard"
  )
}

run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null \
  || fail "source guard must accept one clean matching immutable commit"
if run_source_guard "0000000000000000000000000000000000000000" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject an expected-commit mismatch"
fi
if run_source_guard "$fixture_sha" "0000000000000000000000000000000000000000" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject a workflow-dispatch mismatch"
fi
if run_source_guard "$fixture_sha" "$fixture_sha" "0000000000000000000000000000000000000000" >/dev/null 2>&1; then
  fail "source guard must reject a mutable or mismatched trusted ref"
fi

release_tag="v0.2.6"
git -C "$fixture_dir" tag -a "$release_tag" -m "verified fixture"
git -C "$fixture_dir" push -q origin "refs/tags/$release_tag"
fixture_tag_object="$(git -C "$fixture_dir" rev-parse "refs/tags/$release_tag")"
fixture_tag_commit="$(git -C "$fixture_dir" rev-parse "refs/tags/$release_tag^{commit}")"

run_tag_guard() {
  local dry_run="$1"
  local expected_object="$2"
  local expected_tag_commit="$3"
  (
    cd "$fixture_dir"
    DRY_RUN="$dry_run" \
      RELEASE_TAG="$release_tag" \
      EXPECTED_TAG_OBJECT_SHA="$expected_object" \
      EXPECTED_TAG_COMMIT_SHA="$expected_tag_commit" \
      EXPECTED_COMMIT_SHA="$fixture_sha" \
      GITHUB_SHA="$fixture_sha" \
      bash "$repo_root/$tag_guard"
  )
}

run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null \
  || fail "tag guard must accept the exact remote annotated-tag object and peeled commit"
git -C "$fixture_dir" tag -f -a "$release_tag" -m "retargeted object" "$fixture_sha" >/dev/null
git -C "$fixture_dir" push -q --force origin "refs/tags/$release_tag"
if run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "tag guard must reject a retargeted annotated-tag object even when its peeled commit is unchanged"
fi
git -C "$fixture_dir" push -q --delete origin "$release_tag"
if run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "tag guard must reject a release tag deleted after signature verification"
fi
git -C "$fixture_dir" tag -d "$release_tag" >/dev/null
git -C "$fixture_dir" tag "$release_tag" "$fixture_sha"
git -C "$fixture_dir" push -q origin "refs/tags/$release_tag"
if run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "tag guard must reject a signed annotated tag replaced by a lightweight tag"
fi
git -C "$fixture_dir" push -q --delete origin "$release_tag"
run_tag_guard true "" "" >/dev/null \
  || fail "tag guard must preserve the tag-free dry-run contract"
if run_tag_guard true "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "tag guard must reject signed-tag identity leaking into the dry-run branch"
fi

printf 'untracked\n' > "$fixture_dir/untracked.txt"
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject an untracked dirty checkout"
fi

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

for job in release-build sbom-and-attest publish publish-wasm-npm publish-llm-proxy-npm github-release; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  grep -E '^    needs: .*verify-signed-tag' <<<"$block" >/dev/null \
    || fail "job $job must directly depend on verify-signed-tag to consume its immutable outputs"
  grep -F 'ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" >/dev/null \
    || fail "job $job checkout must use the validated immutable trusted ref"
  grep -F 'name: Verify checked-out release source' <<<"$block" >/dev/null \
    || fail "job $job must verify the checked-out release source before work begins"
  grep -F 'EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job source check must consume the validated commit SHA"
  grep -F 'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" >/dev/null \
    || fail "job $job source check must consume the validated trusted ref"
  grep -F 'run: bash tools/verify_release_source.sh' <<<"$block" >/dev/null \
    || fail "job $job must execute the shared source-identity guard"
  grep -F 'DRY_RUN: ${{ inputs.dry_run }}' <<<"$block" >/dev/null \
    || fail "job $job tag check must preserve the tag-free dry-run branch"
  grep -F 'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' <<<"$block" >/dev/null \
    || fail "job $job must revalidate the sanitized release tag"
  grep -F 'EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify-signed-tag.outputs.tag_object_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified signed-tag object ID"
  grep -F 'EXPECTED_TAG_COMMIT_SHA: ${{ needs.verify-signed-tag.outputs.tag_commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified tag's peeled commit"
  grep -F 'run: bash tools/verify_release_tag.sh' <<<"$block" >/dev/null \
    || fail "job $job must re-fetch and compare the current remote tag before side effects"

  checkout_line=$(grep -nF 'ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" | head -n 1 | cut -d: -f1)
  verify_line=$(grep -nF 'run: bash tools/verify_release_source.sh' <<<"$block" | head -n 1 | cut -d: -f1)
  if [ "$verify_line" -le "$checkout_line" ]; then
    fail "job $job must verify source identity after checkout"
  fi
  tag_verify_line=$(grep -nF 'run: bash tools/verify_release_tag.sh' <<<"$block" | head -n 1 | cut -d: -f1)
  if [ "$tag_verify_line" -le "$verify_line" ]; then
    fail "job $job must revalidate remote tag identity after verifying the checked-out source"
  fi

  if grep -F 'id: release-ref' <<<"$block" >/dev/null; then
    fail "job $job must not recompute a mutable release ref locally"
  fi
done

github_release_block=$(job_block "github-release")
github_tag_verify_count=$(grep -cF 'run: bash tools/verify_release_tag.sh' <<<"$github_release_block")
if [ "$github_tag_verify_count" -ne 2 ]; then
  fail "github-release must revalidate the remote tag both after checkout and immediately before release creation"
fi
last_tag_verify_line=$(grep -nF 'run: bash tools/verify_release_tag.sh' <<<"$github_release_block" | tail -n 1 | cut -d: -f1)
create_release_step_line=$(grep -nF 'name: Create release' <<<"$github_release_block" | head -n 1 | cut -d: -f1)
if [ "$last_tag_verify_line" -ge "$create_release_step_line" ]; then
  fail "github-release tag revalidation must run immediately before the release-creation action"
fi
between_tag_and_release=$(sed -n "$((last_tag_verify_line + 1)),$((create_release_step_line - 1))p" <<<"$github_release_block")
if grep -E '^[[:space:]]+- (name:|uses:)' <<<"$between_tag_and_release" >/dev/null; then
  fail "github-release must not run another step between final tag revalidation and release creation"
fi
grep -F 'target_commitish: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$github_release_block" >/dev/null \
  || fail "github-release must bind tag auto-creation fallback to the validated commit"

release_build_block=$(job_block "release-build")
grep -F 'cargo build --workspace --release --locked --target ${{ matrix.target }}' <<<"$release_build_block" >/dev/null \
  || fail "release-build must refuse lockfile refresh while producing artifacts"

printf 'release workflow ref-binding test passed\n'
