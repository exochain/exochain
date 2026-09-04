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
ci_workflow=".github/workflows/ci.yml"
source_guard="tools/verify_release_source.sh"
tag_guard="tools/verify_release_tag.sh"
side_effect_guard="tools/verify_release_side_effect.sh"
tool_path_resolver="tools/resolve_release_tool_path.sh"
npm_package_guard="tools/verify_npm_release_package.mjs"
cargo_config_guard="tools/verify_release_cargo_config.sh"
crate_preflight="tools/preflight_release_crates.sh"
crate_publisher="tools/publish_release_crates.sh"
npm_tarball_guard="tools/verify_npm_release_tarball.py"
capture_helper="tools/capture_release_helper.sh"
[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"
[[ -f "$source_guard" ]] || fail "$source_guard is missing"
[[ -f "$tag_guard" ]] || fail "$tag_guard is missing"
[[ -f "$side_effect_guard" ]] || fail "$side_effect_guard is missing"
[[ -f "$tool_path_resolver" ]] || fail "$tool_path_resolver is missing"
[[ -f "$npm_package_guard" ]] || fail "$npm_package_guard is missing"
[[ -f "$cargo_config_guard" ]] || fail "$cargo_config_guard is missing"
[[ -f "$crate_preflight" ]] || fail "$crate_preflight is missing"
[[ -f "$crate_publisher" ]] || fail "$crate_publisher is missing"
[[ -f "$npm_tarball_guard" ]] || fail "$npm_tarball_guard is missing"
[[ -f "$capture_helper" ]] || fail "$capture_helper is missing"
grep -F 'GIT_NO_REPLACE_OBJECTS=1' "$capture_helper" >/dev/null \
  && grep -F '/usr/bin/git --no-replace-objects' "$capture_helper" >/dev/null \
  && grep -F 'hash-object --stdin' "$capture_helper" >/dev/null \
  || fail "$capture_helper must bind captured bytes to replacement-disabled immutable Git objects"
for focused_guard in \
  test_capture_release_helper.sh \
  test_publish_release_crates_registry_validation.sh \
  test_publish_release_npm_registry_validation.sh \
  test_release_llm_lifecycle_boundary.sh \
  test_release_npm_config_boundary.sh \
  test_stage_llm_release_package.sh \
  test_transport_release_build_output.sh \
  test_transport_release_file_set.sh \
  test_transport_wasm_release_output.sh \
  test_verify_npm_release_tarball.sh \
  test_verify_release_sbom.sh; do
  grep -F "bash tools/$focused_guard" "$ci_workflow" >/dev/null \
    || fail "CI must execute tools/$focused_guard"
done
grep -F 'trusted_git show "${GITHUB_SHA}:tools/verify_release_source.sh"' "$side_effect_guard" >/dev/null \
  || fail "$side_effect_guard must execute the source guard from the immutable dispatch commit"
grep -F 'trusted_git show "${GITHUB_SHA}:tools/verify_release_tag.sh"' "$side_effect_guard" >/dev/null \
  || fail "$side_effect_guard must execute the tag guard from the immutable dispatch commit"
immutable_child_count=$(grep -cF 'BASH_ENV=/dev/null /bin/bash --noprofile --norc -p' "$side_effect_guard")
[ "$immutable_child_count" -eq 2 ] \
  || fail "$side_effect_guard must disable replacement objects and BASH_ENV for both child guards"
for hardened_guard in "$source_guard" "$tag_guard" "$side_effect_guard" tools/verify_release_tag_signer.sh; do
  grep -F '/usr/bin/git' "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must resolve Git through the trusted system utility path"
  grep -F -- '-c core.fsmonitor=false' "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must disable fsmonitor while examining release source"
  grep -F -- '-c core.untrackedCache=false' "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must disable the untracked cache while examining release source"
  grep -F -- '-C "$release_workspace"' "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must anchor every Git command to GITHUB_WORKSPACE"
  grep -F 'export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1' "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must ignore HOME-selected global and system Git configuration"
  grep -F "^BASH_FUNC_.*%%=" "$hardened_guard" >/dev/null \
    || fail "$hardened_guard must reject inherited shell functions"
  scrub_block="$(awk '/^scrub_git_environment\(\) \{/,/^}/' "$hardened_guard")"
  for poisoned_git_name in GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_CONFIG_COUNT; do
    grep -wF "$poisoned_git_name" <<<"$scrub_block" >/dev/null \
      || fail "$hardened_guard must scrub $poisoned_git_name"
  done
done
grep -F 'shell: /bin/bash --noprofile --norc -p -e -o pipefail {0}' "$workflow" >/dev/null \
  || fail "$workflow must run every release shell in privileged mode without inherited functions"
grep -F 'trusted_remote_git' "$tag_guard" >/dev/null \
  || fail "$tag_guard must query tag state from an isolated Git context"
grep -F '/usr/bin/env -i' "$tag_guard" >/dev/null \
  || fail "$tag_guard must give the authoritative tag query an empty inherited environment"
grep -F 'ls-remote "$authoritative_remote_url"' "$tag_guard" >/dev/null \
  || fail "$tag_guard must query the authoritative remote without trusting checkout remote config"
grep -F 'GITHUB_SERVER_URL' "$tag_guard" >/dev/null \
  || fail "$tag_guard must derive the authoritative server from runner-protected context"
grep -F 'GITHUB_REPOSITORY' "$tag_guard" >/dev/null \
  || fail "$tag_guard must derive the authoritative repository from runner-protected context"
grep -F 'RELEASE_TRUSTED_NODE_VERSION must be an exact numeric Node.js version' "$tool_path_resolver" >/dev/null \
  || fail "$tool_path_resolver must require an exact trusted Node.js tool-cache version"
grep -F 'Cargo configuration above GITHUB_WORKSPACE is forbidden' "$cargo_config_guard" >/dev/null \
  || fail "$cargo_config_guard must reject untrusted Cargo configuration above the checkout"
grep -F 'publishConfig is forbidden' "$npm_package_guard" >/dev/null \
  || fail "$npm_package_guard must reject package-local publication overrides"
grep -F 'ls-tree -r -t -z --full-tree "$expected_commit_sha"' "$source_guard" >/dev/null \
  || fail "$source_guard must derive a NUL-safe manifest from the immutable commit tree"
grep -F 'hash-object --no-filters' "$source_guard" >/dev/null \
  || fail "$source_guard must hash raw tracked bytes without clean filters"
grep -F 'release source cannot contain Git submodules' "$source_guard" >/dev/null \
  || fail "$source_guard must fail closed when the commit tree contains a gitlink"
grep -F 'trusted_git ls-files --others -z' "$source_guard" >/dev/null \
  || fail "$source_guard must enumerate every untracked path without consulting exclude files"
grep -F 'trusted_git ls-files --stage -z' "$source_guard" >/dev/null \
  || fail "$source_guard must compare a NUL-safe index manifest before classifying untracked paths"
if grep -F -- '--exclude-per-directory' "$source_guard" >/dev/null; then
  fail "$source_guard must not consume worktree .gitignore files while enumerating untracked release inputs"
fi

# Parse the workflow as YAML and reject duplicate mapping keys. YAML parsers
# otherwise commonly accept the last duplicate silently, which can replace a
# guarded `run` block with an unguarded one.
ruby - "$workflow" <<'RUBY'
require "psych"
require "set"

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
workflow_document = Psych.parse_file(workflow_path)
assert_unique_mapping_keys(workflow_document, workflow_path)

def mapping_value(mapping, key_name)
  return nil unless mapping.is_a?(Psych::Nodes::Mapping)

  mapping.children.each_slice(2) do |key, value|
    return value if key.is_a?(Psych::Nodes::Scalar) && key.value == key_name
  end
  nil
end

def scalar_mapping(mapping)
  raise "expected a YAML mapping" unless mapping.is_a?(Psych::Nodes::Mapping)

  mapping.children.each_slice(2).to_h do |key, value|
    raise "expected scalar mapping key" unless key.is_a?(Psych::Nodes::Scalar)
    raise "expected scalar mapping value for #{key.value}" unless value.is_a?(Psych::Nodes::Scalar)
    [key.value, value.value]
  end
end

root = workflow_document.root
jobs = mapping_value(root, "jobs")
raise "#{workflow_path}: jobs mapping is missing" unless jobs.is_a?(Psych::Nodes::Mapping)
workflow_permissions = mapping_value(root, "permissions")
unless workflow_permissions && scalar_mapping(workflow_permissions) == { "contents" => "read" }
  raise "#{workflow_path}: workflow default permissions must be exactly contents: read"
end

expected_permissions = {
  "ci" => { "contents" => "read" },
  "approve" => {},
  "approve-second" => {},
  "validate-release-inputs" => { "contents" => "read" },
  "verify-signed-tag" => { "contents" => "read" },
  "release-build" => { "contents" => "read" },
  "package-release" => { "contents" => "read" },
  "install-cargo-cyclonedx" => {},
  "generate-sbom" => { "contents" => "read" },
  "validate-sbom" => { "contents" => "read" },
  "attest-release" => {
    "contents" => "read",
    "attestations" => "write",
    "id-token" => "write"
  },
  "preflight-crates" => { "contents" => "read" },
  "reproduce-crates" => { "contents" => "read" },
  "publish" => { "contents" => "read" },
  "install-wasm-pack" => {},
  "build-wasm-npm" => { "contents" => "read" },
  "prepare-wasm-npm" => { "contents" => "read" },
  "test-llm-proxy-npm" => { "contents" => "read" },
  "prepare-llm-proxy-npm" => { "contents" => "read" },
  "publish-wasm-npm" => { "contents" => "read", "id-token" => "write" },
  "publish-llm-proxy-npm" => { "contents" => "read", "id-token" => "write" },
  "github-release" => { "contents" => "write" }
}

job_names = Set.new
jobs.children.each_slice(2) do |job_key, job|
  if job_key.is_a?(Psych::Nodes::Scalar) && job.is_a?(Psych::Nodes::Mapping)
    job_names.add(job_key.value)
  end
end

jobs.children.each_slice(2) do |job_key, job|
  next unless job_key.is_a?(Psych::Nodes::Scalar) && job.is_a?(Psych::Nodes::Mapping)

  job_name = job_key.value
  steps = mapping_value(job, "steps")
  has_checkout = steps.is_a?(Psych::Nodes::Sequence) && steps.children.any? do |step|
    uses = mapping_value(step, "uses")
    uses.is_a?(Psych::Nodes::Scalar) && uses.value.start_with?("actions/checkout@")
  end
  if steps.is_a?(Psych::Nodes::Sequence)
    steps.children.each do |step|
      uses = mapping_value(step, "uses")
      next unless uses.is_a?(Psych::Nodes::Scalar) && uses.value.start_with?("actions/checkout@")

      checkout_with = mapping_value(step, "with")
      unless checkout_with.is_a?(Psych::Nodes::Mapping) &&
             scalar_mapping(checkout_with)["persist-credentials"] == "false"
        raise "#{workflow_path}: #{job_name} checkout must set persist-credentials: false"
      end
    end
  end
  permissions = mapping_value(job, "permissions")

  needs = mapping_value(job, "needs")
  dependency_names = if needs.is_a?(Psych::Nodes::Sequence)
                       needs.children.map(&:value)
                     elsif needs.is_a?(Psych::Nodes::Scalar)
                       [needs.value]
                     else
                       []
                     end
  dependency_names.each do |dependency|
    raise "#{workflow_path}: #{job_name} has dangling needs dependency #{dependency}" unless job_names.include?(dependency)
  end

  raise "#{workflow_path}: #{job_name} needs an explicit reviewed permissions block" unless permissions
  actual = scalar_mapping(permissions)
  expected = expected_permissions.fetch(job_name) do
    raise "#{workflow_path}: no reviewed least-privilege permission set for job #{job_name}"
  end
  unless actual == expected
    raise "#{workflow_path}: #{job_name} permissions #{actual.inspect} must equal #{expected.inspect}"
  end
end

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
attacker_remote="$fixture_root/attacker-remote.git"
attacker_dir="$fixture_root/attacker-checkout"
fake_bin_dir="$fixture_root/fake-bin"
fake_git="$fake_bin_dir/git"
poison_tool_bin="$fixture_root/poison-tool-bin"
trusted_cargo_home="$fixture_root/trusted-cargo-home"
trusted_rustup_home="$fixture_root/trusted-rustup-home"
trusted_rust_sysroot="$trusted_rustup_home/toolchains/1.97.1-fixture"
trusted_node_root="$fixture_root/trusted-node-cache/node"
trusted_node_bin="$trusted_node_root/22.14.0/x64/bin"
poisoned_tool_marker="$fixture_root/poisoned-release-tool-ran"
trusted_tool_marker="$fixture_root/trusted-release-tool-ran"
loader_marker="$fixture_root/poisoned-loader-ran"
poison_home="$fixture_root/poison-home"
poison_fsmonitor="$fixture_root/poison-fsmonitor.sh"
poison_bash_env="$fixture_root/poison-bash-env.sh"
trap 'rm -rf "$fixture_root"' EXIT
cat > "$poison_bash_env" <<'POISON'
export RELEASE_SOURCE_CLEAN_MODE=invalid
export DRY_RUN=true
export RELEASE_TAG=v999.999.999
export EXPECTED_TAG_OBJECT_SHA=0000000000000000000000000000000000000000
export EXPECTED_TAG_COMMIT_SHA=0000000000000000000000000000000000000000
export EXPECTED_COMMIT_SHA=0000000000000000000000000000000000000000
export TRUSTED_RELEASE_REF=0000000000000000000000000000000000000000
exit 0
POISON
mkdir -p \
  "$fake_bin_dir" \
  "$poison_home" \
  "$poison_tool_bin" \
  "$trusted_cargo_home/bin" \
  "$trusted_rust_sysroot/bin" \
  "$trusted_node_bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fake_git"
printf '#!/usr/bin/env bash\nprintf "poison-clock\\n"\n' > "$poison_fsmonitor"
printf '[core]\n\tworktree = %s\n\tfsmonitor = %s\n' "$attacker_dir" "$poison_fsmonitor" > "$poison_home/.gitconfig"
chmod +x "$fake_git" "$poison_fsmonitor"
for poisoned_tool in cargo npm node bash tar; do
  printf '#!/bin/sh\n: > "$POISONED_TOOL_MARKER"\nexit 0\n' > "$poison_tool_bin/$poisoned_tool"
  chmod +x "$poison_tool_bin/$poisoned_tool"
done
for trusted_tool in cargo rustdoc; do
  printf '#!/bin/sh\nprintf "%s\\n" "$0" >> "$TRUSTED_TOOL_MARKER"\nexit 0\n' > "$trusted_rust_sysroot/bin/$trusted_tool"
  chmod +x "$trusted_rust_sysroot/bin/$trusted_tool"
done
cat > "$trusted_rust_sysroot/bin/rustc" <<RUSTC
#!/bin/sh
if [ "\${1:-}" = "--print" ] && [ "\${2:-}" = "sysroot" ]; then
  printf '%s\\n' '$trusted_rust_sysroot'
  exit 0
fi
printf '%s\\n' "\$0" >> "\$TRUSTED_TOOL_MARKER"
exit 0
RUSTC
chmod +x "$trusted_rust_sysroot/bin/rustc"
printf '#!/bin/sh\ncase "${1:-}" in --version) printf "v22.14.0\\n" ;; *) printf "%s\\n" "$0" >> "$TRUSTED_TOOL_MARKER" ;; esac\nexit 0\n' > "$trusted_node_bin/node"
printf '#!/bin/sh\nprintf "%s\\n" "$0" >> "$TRUSTED_TOOL_MARKER"\nexit 0\n' > "$trusted_node_bin/npm"
chmod +x "$trusted_node_bin/node" "$trusted_node_bin/npm"
cat > "$trusted_cargo_home/bin/rustup" <<RUSTUP
#!/bin/sh
if [ "\${1:-}" != which ]; then exit 1; fi
case "\${4:-}" in
  cargo|rustc|rustdoc) printf '%s/%s\\n' '$trusted_rust_sysroot/bin' "\${4}" ;;
  *) exit 1 ;;
esac
RUSTUP
chmod +x "$trusted_cargo_home/bin/rustup"

if [ "$(uname -s)" = "Linux" ] && command -v cc >/dev/null 2>&1; then
  loader_source="$fixture_root/loader-poison.c"
  loader_object="$fixture_root/loader-poison.so"
  printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '__attribute__((constructor)) static void poison(void) {' \
    '  const char *marker = getenv("LOADER_MARKER");' \
    '  if (marker != NULL) {' \
    '    FILE *handle = fopen(marker, "w");' \
    '    if (handle != NULL) { fputs("loaded", handle); fclose(handle); }' \
    '  }' \
    '}' > "$loader_source"
  cc -shared -fPIC -o "$loader_object" "$loader_source"
  LD_PRELOAD="$loader_object" LOADER_MARKER="$loader_marker" \
    /bin/bash --noprofile --norc -p -c ':'
  [ -e "$loader_marker" ] \
    || fail "Linux loader-poison fixture must execute before privileged Bash starts"
  rm "$loader_marker"
  LD_PRELOAD= LD_AUDIT= LD_LIBRARY_PATH= LOADER_MARKER="$loader_marker" \
    /bin/bash --noprofile --norc -p -c ':'
  [ ! -e "$loader_marker" ] \
    || fail "empty step-scoped loader controls must prevent pre-shell constructor execution"
fi
git init --bare -q "$fixture_remote"
git init -q "$fixture_dir"
git -C "$fixture_dir" config user.name EXOCHAIN
git -C "$fixture_dir" config user.email release-test@example.invalid
git -C "$fixture_dir" config commit.gpgSign false
git -C "$fixture_dir" config tag.gpgSign false
printf 'tracked\n' > "$fixture_dir/tracked.txt"
printf 'plain\n' > "$fixture_dir/plain.txt"
printf '#!/bin/sh\nexit 0\n' > "$fixture_dir/executable.sh"
chmod +x "$fixture_dir/executable.sh"
ln -s tracked.txt "$fixture_dir/tracked-link"
mkdir -p "$fixture_dir/tools"
cp "$repo_root/$source_guard" "$fixture_dir/$source_guard"
cp "$repo_root/$tag_guard" "$fixture_dir/$tag_guard"
cp "$repo_root/$side_effect_guard" "$fixture_dir/$side_effect_guard"
git -C "$fixture_dir" add tracked.txt plain.txt executable.sh tracked-link tools
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
      GITHUB_WORKSPACE="$fixture_dir" \
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

# Repository-local stat-cache settings can make Git report a same-size tracked
# mutation as clean when its mtime is restored. Establish the exact concealment
# precondition, then require the source guard to compare committed bytes rather
# than trusting cached index metadata or checkout configuration.
tracked_mtime_reference="$fixture_root/tracked-mtime-reference"
touch -t 200001010000 "$fixture_dir/tracked.txt"
cp -p "$fixture_dir/tracked.txt" "$tracked_mtime_reference"
git -C "$fixture_dir" config core.trustctime false
git -C "$fixture_dir" config core.checkStat minimal
git -C "$fixture_dir" update-index --really-refresh
printf 'changed\n' > "$fixture_dir/tracked.txt"
touch -r "$tracked_mtime_reference" "$fixture_dir/tracked.txt"
if [ -n "$(git -C "$fixture_dir" status --porcelain=v1 --untracked-files=no)" ]; then
  fail "stat-cache regression fixture must conceal the same-size tracked mutation from git status"
fi
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject tracked byte changes concealed by local trustctime and checkStat settings"
fi
git -C "$fixture_dir" restore --source=HEAD --worktree -- tracked.txt
git -C "$fixture_dir" config --unset core.trustctime
git -C "$fixture_dir" config --unset core.checkStat
git -C "$fixture_dir" add -- tracked.txt
git -C "$fixture_dir" diff --cached --quiet -- tracked.txt \
  || fail "stat-cache regression cleanup must preserve the committed tracked blob"

chmod -x "$fixture_dir/executable.sh"
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject a committed executable whose execute bit was removed"
fi
chmod +x "$fixture_dir/executable.sh"

chmod +x "$fixture_dir/plain.txt"
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject an executable bit added to a non-executable committed file"
fi
chmod -x "$fixture_dir/plain.txt"

rm "$fixture_dir/tracked-link"
ln -s plain.txt "$fixture_dir/tracked-link"
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject a tracked symlink whose target changed"
fi
rm "$fixture_dir/tracked-link"
ln -s tracked.txt "$fixture_dir/tracked-link"

rm "$fixture_dir/tracked.txt"
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "source guard must reject a deleted tracked file"
fi
git -C "$fixture_dir" restore --source=HEAD --worktree -- tracked.txt

mkdir "$fixture_dir/concealed"
printf '*\n' > "$fixture_dir/concealed/.gitignore"
printf 'registry=https://attacker.invalid/\n' > "$fixture_dir/concealed/.npmrc"
printf 'hidden lifecycle input\n' > "$fixture_dir/concealed/payload"
if [ -n "$(git -C "$fixture_dir" ls-files --others --exclude-per-directory=.gitignore)" ]; then
  fail "nested-ignore regression fixture must conceal its own untracked config and payload from worktree ignore processing"
fi
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "all-source mode must reject an untracked nested .gitignore and every payload it conceals"
fi
rm \
  "$fixture_dir/concealed/.gitignore" \
  "$fixture_dir/concealed/.npmrc" \
  "$fixture_dir/concealed/payload"
rmdir "$fixture_dir/concealed"

printf 'registry=https://attacker.invalid/\n' > "$fixture_dir/.npmrc"
git -C "$fixture_dir" add -N .npmrc
if [ "$(git -C "$fixture_dir" write-tree)" != "$(git -C "$fixture_dir" rev-parse "${fixture_sha}^{tree}")" ]; then
  fail "intent-to-add regression fixture must retain the committed tree object"
fi
if [ -n "$(git -C "$fixture_dir" ls-files --others)" ]; then
  fail "intent-to-add regression fixture must disappear from ordinary untracked enumeration"
fi
if run_source_guard "$fixture_sha" "$fixture_sha" "$fixture_sha" >/dev/null 2>&1; then
  fail "all-source mode must reject intent-to-add index entries"
fi
if (
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    RELEASE_ALLOWED_UNTRACKED_PATHS=.npmrc \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "tracked-source mode must reject intent-to-add index entries before applying generated-output allowlists"
fi
git -C "$fixture_dir" reset -q -- .npmrc
rm "$fixture_dir/.npmrc"

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
      GITHUB_WORKSPACE="$fixture_dir" \
      GITHUB_ACTIONS=false \
      GITHUB_SERVER_URL="file://$fixture_root" \
      GITHUB_REPOSITORY=remote \
      bash "$repo_root/$tag_guard"
  )
}

run_immutable_side_effect_guard() {
  local clean_mode="$1"
  local expected_object="$2"
  local expected_tag_commit="$3"
  local allowed_untracked_paths="${4:-}"
  (
    cd "$fixture_dir"
    # Simulate a prior step writing every trusted input plus BASH_ENV through
    # GITHUB_ENV. The late step's exact bindings must override every poison.
    export BASH_ENV="$poison_bash_env"
    export RELEASE_SOURCE_CLEAN_MODE=invalid
    export DRY_RUN=true
    export RELEASE_TAG=v999.999.999
    export EXPECTED_TAG_OBJECT_SHA=0000000000000000000000000000000000000000
    export EXPECTED_TAG_COMMIT_SHA=0000000000000000000000000000000000000000
    export EXPECTED_COMMIT_SHA=0000000000000000000000000000000000000000
    export TRUSTED_RELEASE_REF=0000000000000000000000000000000000000000
    export GITHUB_SHA="$fixture_sha"
    export GITHUB_WORKSPACE="$fixture_dir"
    # Simulate GITHUB_PATH and GITHUB_ENV redirecting Git itself, repository
    # discovery, the index, and runtime config to attacker-controlled state.
    export PATH="$fake_bin_dir:$PATH"
    export HOME="$poison_home"
    export GIT_DIR="$attacker_dir/.git"
    export GIT_COMMON_DIR="$attacker_dir/.git"
    export GIT_WORK_TREE="$attacker_dir"
    export GIT_INDEX_FILE="$attacker_dir/.git/index"
    export GIT_CONFIG_COUNT=1
    export GIT_CONFIG_KEY_0=core.fsmonitor
    export GIT_CONFIG_VALUE_0="$poison_fsmonitor"
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_NAMESPACE GIT_REPLACE_REF_BASE GIT_NO_REPLACE_OBJECTS GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_EXEC_PATH GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
    /usr/bin/git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" | \
      BASH_ENV=/dev/null \
      RELEASE_SOURCE_CLEAN_MODE="$clean_mode" \
      RELEASE_ALLOWED_UNTRACKED_PATHS="$allowed_untracked_paths" \
      DRY_RUN=false \
      RELEASE_TAG="$release_tag" \
      EXPECTED_TAG_OBJECT_SHA="$expected_object" \
      EXPECTED_TAG_COMMIT_SHA="$expected_tag_commit" \
      EXPECTED_COMMIT_SHA="$fixture_sha" \
      TRUSTED_RELEASE_REF="$fixture_sha" \
      GITHUB_SHA="$fixture_sha" \
      GITHUB_WORKSPACE="$fixture_dir" \
      GITHUB_ACTIONS=false \
      GITHUB_SERVER_URL="file://$fixture_root" \
      GITHUB_REPOSITORY=remote \
      /bin/bash --noprofile --norc -p
  )
}

run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null \
  || fail "tag guard must accept the exact remote annotated-tag object and peeled commit"
git clone -q "$fixture_dir" "$attacker_dir"
git clone --bare -q "$fixture_remote" "$attacker_remote"
run_immutable_side_effect_guard all "$fixture_tag_object" "$fixture_tag_commit" >/dev/null \
  || fail "combined side-effect guard must override poisoned prior-step state and accept one exact clean signed-source boundary"

# Privileged Bash rejects imported functions, but it deliberately preserves
# PATH. Prove the current vulnerable outer-step pattern reaches all five fake
# release tools after a valid immutable side-effect guard before testing the
# trusted-path resolver that must exclude the GITHUB_PATH injection.
if ! PATH="$poison_tool_bin:$PATH" \
  POISONED_TOOL_MARKER="$poisoned_tool_marker" \
  /bin/bash --noprofile --norc -p -c 'cargo; npm; node; bash -c :; tar --version' \
  >/dev/null 2>&1; then
  fail "poisoned PATH regression fixture must provide executable fake release tools"
fi
[ -e "$poisoned_tool_marker" ] \
  || fail "poisoned PATH regression fixture must demonstrate the prior outer-shell bypass"
rm "$poisoned_tool_marker"
[[ -f "$tool_path_resolver" ]] \
  || fail "$tool_path_resolver is required to exclude GITHUB_PATH from release side effects"
trusted_release_path="$(
  PATH="$poison_tool_bin:$PATH" \
    RUNNER_TEMP="$fixture_root" \
    RELEASE_TRUSTED_CARGO_HOME="$trusted_cargo_home" \
    RELEASE_TRUSTED_RUSTUP_HOME="$trusted_rustup_home" \
    RELEASE_TRUSTED_RUST_TOOLCHAIN=1.97.1 \
    RELEASE_TRUSTED_NODE_ROOT="$trusted_node_root" \
    RELEASE_TRUSTED_NODE_VERSION=22.14.0 \
    /bin/bash --noprofile --norc -p "$repo_root/$tool_path_resolver" cargo npm node bash tar
)"
trusted_release_identity="$(
  PATH="$poison_tool_bin:$PATH" \
    RUNNER_TEMP="$fixture_root" \
    RELEASE_TRUSTED_CARGO_HOME="$trusted_cargo_home" \
    RELEASE_TRUSTED_RUSTUP_HOME="$trusted_rustup_home" \
    RELEASE_TRUSTED_RUST_TOOLCHAIN=1.97.1 \
    RELEASE_TRUSTED_NODE_ROOT="$trusted_node_root" \
    RELEASE_TRUSTED_NODE_VERSION=22.14.0 \
    /bin/bash --noprofile --norc -p "$repo_root/$tool_path_resolver" --identity cargo npm node bash tar
)"
[[ "$trusted_release_identity" =~ ^[0-9a-f]{64}$ ]] \
  || fail "trusted release tool resolver must emit one SHA-256 identity"
case ":$trusted_release_path:" in
  *":$poison_tool_bin:"*) fail "trusted release PATH must exclude prior GITHUB_PATH entries" ;;
esac
PATH="$trusted_release_path" \
  POISONED_TOOL_MARKER="$poisoned_tool_marker" \
  TRUSTED_TOOL_MARKER="$trusted_tool_marker" \
  /bin/bash --noprofile --norc -p -c 'cargo; npm; node; bash -c :; tar --version' \
  >/dev/null 2>&1 \
  || fail "trusted release PATH must resolve validated cargo, npm, node, Bash, and tar executables"
[ ! -e "$poisoned_tool_marker" ] \
  || fail "GITHUB_PATH binaries must never run after trusted release-tool resolution"
[ "$(wc -l < "$trusted_tool_marker" | tr -d ' ')" -eq 3 ] \
  || fail "trusted cargo, npm, and node fixtures must run exactly once"

# Aggregate identity binds the trusted backing distributions, not a writable
# RUNNER_TEMP symlink view. Prove a stale view can be replaced without changing
# that identity, then prove consumers get a newly materialized exact-entry view.
trusted_view="${trusted_release_path%%:*}"
/bin/rm -f -- "$trusted_view/bash"
/bin/ln -s -- "$poison_tool_bin/bash" "$trusted_view/bash"
view_mutation_identity="$(
  RUNNER_TEMP="$fixture_root" \
    RELEASE_TRUSTED_CARGO_HOME="$trusted_cargo_home" \
    RELEASE_TRUSTED_RUSTUP_HOME="$trusted_rustup_home" \
    RELEASE_TRUSTED_RUST_TOOLCHAIN=1.97.1 \
    RELEASE_TRUSTED_NODE_ROOT="$trusted_node_root" \
    RELEASE_TRUSTED_NODE_VERSION=22.14.0 \
    /bin/bash --noprofile --norc -p "$repo_root/$tool_path_resolver" \
      --identity cargo npm node bash tar
)"
[ "$view_mutation_identity" = "$trusted_release_identity" ] \
  || fail "view-only mutation fixture must leave backing-tool identity unchanged"
POISONED_TOOL_MARKER="$poisoned_tool_marker" "$trusted_view/bash" >/dev/null 2>&1
[ -e "$poisoned_tool_marker" ] \
  || fail "view-only mutation fixture must demonstrate execution through a stale replaced view"
/bin/rm -f -- "$poisoned_tool_marker"
fresh_release_path="$(
  RUNNER_TEMP="$fixture_root" \
    RELEASE_TRUSTED_CARGO_HOME="$trusted_cargo_home" \
    RELEASE_TRUSTED_RUSTUP_HOME="$trusted_rustup_home" \
    RELEASE_TRUSTED_RUST_TOOLCHAIN=1.97.1 \
    RELEASE_TRUSTED_NODE_ROOT="$trusted_node_root" \
    RELEASE_TRUSTED_NODE_VERSION=22.14.0 \
    /bin/bash --noprofile --norc -p "$repo_root/$tool_path_resolver" \
      cargo npm node bash tar
)"
fresh_release_view="${fresh_release_path%%:*}"
[ "$fresh_release_view" != "$trusted_view" ] \
  || fail "each trusted tool consumer must receive a distinct fresh view"
[ "$(/bin/cat "$fresh_release_view/.release-tool-identity")" = "$trusted_release_identity" ] \
  || fail "fresh tool view must carry the reviewed backing identity"
POISONED_TOOL_MARKER="$poisoned_tool_marker" "$fresh_release_view/bash" -c :
[ ! -e "$poisoned_tool_marker" ] \
  || fail "fresh tool view must not reuse a mutated prior symlink view"

printf '#!/bin/sh\nprintf "changed\\n"\n' > "$trusted_rust_sysroot/bin/cargo"
chmod +x "$trusted_rust_sysroot/bin/cargo"
changed_release_identity="$(
  RUNNER_TEMP="$fixture_root" \
    RELEASE_TRUSTED_CARGO_HOME="$trusted_cargo_home" \
    RELEASE_TRUSTED_RUSTUP_HOME="$trusted_rustup_home" \
    RELEASE_TRUSTED_RUST_TOOLCHAIN=1.97.1 \
    RELEASE_TRUSTED_NODE_ROOT="$trusted_node_root" \
    RELEASE_TRUSTED_NODE_VERSION=22.14.0 \
    /bin/bash --noprofile --norc -p "$repo_root/$tool_path_resolver" --identity cargo npm node bash tar
)"
[ "$changed_release_identity" != "$trusted_release_identity" ] \
  || fail "trusted release tool identity must detect same-path executable replacement"

# Cargo searches .cargo/config{,.toml} above a project independently of
# CARGO_HOME. Prove the immutable guard rejects an injected ancestor config.
mkdir "$fixture_root/.cargo"
printf '%s\n' '[build]' 'rustc-wrapper = "/attacker/wrapper"' > "$fixture_root/.cargo/config.toml"
if GITHUB_WORKSPACE="$fixture_dir" \
  /bin/bash --noprofile --norc -p "$repo_root/$cargo_config_guard" >/dev/null 2>&1; then
  fail "Cargo configuration guard must reject config.toml above GITHUB_WORKSPACE"
fi
rm "$fixture_root/.cargo/config.toml"
rmdir "$fixture_root/.cargo"
GITHUB_WORKSPACE="$fixture_dir" \
  /bin/bash --noprofile --norc -p "$repo_root/$cargo_config_guard" >/dev/null \
  || fail "Cargo configuration guard must accept a checkout with no external ancestor config"

# Cargo discovers a committed workspace .cargo/config.toml relative to the
# invocation cwd even when --manifest-path is absolute. Reproduce the exact
# token-bearing rustc-wrapper exposure, then prove the release invocation
# pattern prevents the wrapper from running by moving to /, isolating homes,
# clearing both wrapper variables, and binding real compiler paths.
cargo_boundary_root="$fixture_root/cargo-boundary"
cargo_boundary_crate="$cargo_boundary_root/token-probe"
cargo_boundary_home="$fixture_root/cargo-boundary-home"
cargo_boundary_target="$fixture_root/cargo-boundary-target"
cargo_wrapper_marker="$fixture_root/cargo-wrapper-token"
mkdir -p "$cargo_boundary_crate/.cargo" "$cargo_boundary_crate/src" \
  "$cargo_boundary_home" "$cargo_boundary_target"
printf '%s\n' \
  '[package]' \
  'name = "exochain-release-token-probe"' \
  'version = "0.2.6"' \
  'edition = "2024"' \
  'license = "Apache-2.0"' \
  'description = "release-boundary fixture"' \
  'repository = "https://example.invalid/exochain-release-token-probe"' \
  > "$cargo_boundary_crate/Cargo.toml"
printf 'pub fn probe() {}\n' > "$cargo_boundary_crate/src/lib.rs"
cat > "$cargo_boundary_crate/wrapper.sh" <<'WRAPPER'
#!/bin/sh
if [ -n "${CARGO_REGISTRY_TOKEN:-}" ]; then
  printf 'token-present\n' > "$CARGO_WRAPPER_MARKER"
fi
exec "$@"
WRAPPER
chmod +x "$cargo_boundary_crate/wrapper.sh"
printf '%s\n' \
  '[build]' \
  "rustc-wrapper = \"$cargo_boundary_crate/wrapper.sh\"" \
  '[registry]' \
  'global-credential-providers = ["cargo:token"]' \
  > "$cargo_boundary_crate/.cargo/config.toml"
(
  cd "$cargo_boundary_crate"
  cargo generate-lockfile >/dev/null
  git init -q
  git config user.name EXOCHAIN
  git config user.email release-test@example.invalid
  git add .
  git commit -qm fixture
  CARGO_REGISTRY_TOKEN=do-not-disclose \
    CARGO_WRAPPER_MARKER="$cargo_wrapper_marker" \
    cargo publish --dry-run --no-verify --locked >/dev/null
)
[ -e "$cargo_wrapper_marker" ] \
  || fail "workspace Cargo configuration fixture must expose the registry token to rustc-wrapper before hardening"
rm "$cargo_wrapper_marker"
real_cargo="$(rustup which cargo)"
real_rustc="$(rustup which rustc)"
real_rustdoc="$(rustup which rustdoc)"
(
  cd /
  /usr/bin/env -i \
    PATH="$(/usr/bin/dirname "$real_cargo"):/usr/bin:/bin" \
    HOME="$cargo_boundary_home" \
    CARGO_HOME="$cargo_boundary_home" \
    CARGO_TARGET_DIR="$cargo_boundary_target" \
    CARGO_REGISTRY_TOKEN=do-not-disclose \
    CARGO_WRAPPER_MARKER="$cargo_wrapper_marker" \
    RUSTC="$real_rustc" \
    RUSTDOC="$real_rustdoc" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    "$real_cargo" publish \
      --manifest-path "$cargo_boundary_crate/Cargo.toml" \
      --dry-run --no-verify --locked >/dev/null
)
[ ! -e "$cargo_wrapper_marker" ] \
  || fail "config-free Cargo release invocation must not execute the workspace rustc-wrapper or expose the token"
for hardened_cargo_script in "$crate_preflight" "$crate_publisher"; do
  grep -F 'cd /' "$hardened_cargo_script" >/dev/null \
    || fail "$hardened_cargo_script must invoke Cargo from the verified config-free root"
  grep -F 'RUSTC="$trusted_rustc"' "$hardened_cargo_script" >/dev/null \
    || fail "$hardened_cargo_script must bind the exact trusted rustc"
  grep -F 'RUSTDOC="$trusted_rustdoc"' "$hardened_cargo_script" >/dev/null \
    || fail "$hardened_cargo_script must bind the exact trusted rustdoc"
  grep -F 'RUSTC_WRAPPER=' "$hardened_cargo_script" >/dev/null \
    || fail "$hardened_cargo_script must clear rustc-wrapper discovery"
  grep -F -- '--manifest-path "$GITHUB_WORKSPACE/Cargo.toml"' "$hardened_cargo_script" >/dev/null \
    || fail "$hardened_cargo_script must use the absolute immutable workspace manifest"
done

# `tracked` mode intentionally permits generated artifacts. It therefore must
# be paired with a package policy guard before npm is allowed to inspect a
# generated package directory.
generated_wasm_package="$fixture_dir/generated-wasm-package"
mkdir "$generated_wasm_package"
printf '%s\n' \
  '{' \
  '  "name": "@exochain/exochain-wasm",' \
  '  "version": "0.2.6",' \
  '  "license": "Apache-2.0",' \
  '  "main": "exochain_wasm.js",' \
  '  "types": "exochain_wasm.d.ts",' \
  '  "files": ["LICENSE", "exochain_wasm.d.ts", "exochain_wasm.js", "exochain_wasm_bg.wasm"]' \
  '}' > "$generated_wasm_package/package.json"
for generated_file in LICENSE exochain_wasm.d.ts exochain_wasm.js exochain_wasm_bg.wasm; do
  printf 'fixture\n' > "$generated_wasm_package/$generated_file"
done
printf 'registry=https://attacker.invalid/\n' > "$generated_wasm_package/.npmrc"
run_immutable_side_effect_guard tracked "$fixture_tag_object" "$fixture_tag_commit" generated-wasm-package >/dev/null \
  || fail "tracked-source mode must preserve generated package artifacts for a dedicated policy guard"
resolved_fixture_registry="$(cd "$generated_wasm_package" && npm config get registry)"
[ "$resolved_fixture_registry" = "https://attacker.invalid/" ] \
  || fail "generated-package regression fixture must redirect npm through its untracked .npmrc"
[[ -f "$npm_package_guard" ]] \
  || fail "$npm_package_guard is required before npm reads generated release packages"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject a staged .npmrc"
fi
rm "$generated_wasm_package/.npmrc"
RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null \
  || fail "npm package guard must accept the expected generated WASM package"
printf '%s\n' \
  '{"name":"@exochain/exochain-wasm","version":"0.2.6","license":"Apache-2.0","main":"exochain_wasm.js","types":"exochain_wasm.d.ts","files":["LICENSE","exochain_wasm.d.ts","exochain_wasm.js","exochain_wasm_bg.wasm"],"publishConfig":{"registry":"https://attacker.invalid/"}}' \
  > "$generated_wasm_package/package.json"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject publishConfig overrides"
fi
printf '%s\n' \
  '{"name":"@exochain/exochain-wasm","version":"0.2.6","license":"Apache-2.0","main":"exochain_wasm.js","types":"exochain_wasm.d.ts","files":["LICENSE","exochain_wasm.d.ts","exochain_wasm.js","exochain_wasm_bg.wasm"],"scripts":{"prepublishOnly":"node attacker.js"}}' \
  > "$generated_wasm_package/package.json"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject generated-package scripts"
fi
printf '%s\n' \
  '{"name":"@attacker/pkg","name":"@exochain/exochain-wasm","version":"0.2.6","license":"Apache-2.0","files":["LICENSE","exochain_wasm.d.ts","exochain_wasm.js","exochain_wasm_bg.wasm"]}' \
  > "$generated_wasm_package/package.json"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject duplicate package identity keys"
fi
printf '%s\n' \
  '{"name":"@exochain/exochain-wasm","version":"0.2.6","license":"Apache-2.0","files":["LICENSE","exochain_wasm.d.ts","exochain_wasm.js","exochain_wasm_bg.wasm"],"scripts":{"prepublishOnly":"node attacker.js"},"scripts":{}}' \
  > "$generated_wasm_package/package.json"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject duplicate scripts keys"
fi
printf '%s\n' \
  '{"name":"@exochain/exochain-wasm","version":"0.2.6","license":"Apache-2.0","files":["LICENSE","exochain_wasm.d.ts","exochain_wasm.js","exochain_wasm_bg.wasm"]}' \
  > "$generated_wasm_package/package.json"
package_json_hardlink="$fixture_root/package-json-hardlink"
/bin/ln "$generated_wasm_package/package.json" "$package_json_hardlink"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_package" >/dev/null 2>&1; then
  fail "npm package guard must reject a hard-linked package manifest"
fi
/bin/rm "$package_json_hardlink"
generated_wasm_symlink="$fixture_root/generated-wasm-package-symlink"
/bin/ln -s "$generated_wasm_package" "$generated_wasm_symlink"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$repo_root/$npm_package_guard" wasm "$generated_wasm_symlink" >/dev/null 2>&1; then
  fail "npm package guard must reject a symlinked requested package root"
fi
/bin/rm "$generated_wasm_symlink"
rm \
  "$generated_wasm_package/package.json" \
  "$generated_wasm_package/LICENSE" \
  "$generated_wasm_package/exochain_wasm.d.ts" \
  "$generated_wasm_package/exochain_wasm.js" \
  "$generated_wasm_package/exochain_wasm_bg.wasm"
rmdir "$generated_wasm_package"

poisoned_side_effect_marker="$fixture_root/poisoned-side-effect-ran"
if /usr/bin/env \
  'BASH_FUNC_cargo%%=() { /usr/bin/touch "$POISONED_SIDE_EFFECT_MARKER"; return 0; }' \
  'BASH_FUNC_npm%%=() { /usr/bin/touch "$POISONED_SIDE_EFFECT_MARKER"; return 0; }' \
  'BASH_FUNC_set%%=() { return 0; }' \
  BASH_ENV=/dev/null \
  POISONED_SIDE_EFFECT_MARKER="$poisoned_side_effect_marker" \
  RELEASE_SOURCE_CLEAN_MODE=all \
  DRY_RUN=false \
  RELEASE_TAG="$release_tag" \
  EXPECTED_TAG_OBJECT_SHA="$fixture_tag_object" \
  EXPECTED_TAG_COMMIT_SHA="$fixture_tag_commit" \
  EXPECTED_COMMIT_SHA="$fixture_sha" \
  TRUSTED_RELEASE_REF="$fixture_sha" \
  GITHUB_SHA="$fixture_sha" \
  GITHUB_WORKSPACE="$fixture_dir" \
  GITHUB_ACTIONS=false \
  GITHUB_SERVER_URL="file://$fixture_root" \
  GITHUB_REPOSITORY=remote \
  /bin/bash --noprofile --norc -p -c \
    'set -euo pipefail; /usr/bin/git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" | BASH_ENV=/dev/null /bin/bash --noprofile --norc -p; cargo; npm; /usr/bin/touch "$POISONED_SIDE_EFFECT_MARKER"' \
    >/dev/null 2>&1; then
  fail "immutable guard must reject inherited cargo, npm, or shell-builtin functions before a release side effect"
fi
[ ! -e "$poisoned_side_effect_marker" ] \
  || fail "inherited release functions must be rejected before the outer publish shell reaches a side effect"

printf 'lifecycle-poisoned source\n' >> "$fixture_dir/tracked.txt"
if (
  cd "$fixture_dir"
  PATH="$fake_bin_dir:$PATH" \
    HOME="$poison_home" \
    GIT_DIR="$attacker_dir/.git" \
    GIT_COMMON_DIR="$attacker_dir/.git" \
    GIT_WORK_TREE="$attacker_dir" \
    GIT_INDEX_FILE="$attacker_dir/.git/index" \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=core.fsmonitor \
    GIT_CONFIG_VALUE_0="$poison_fsmonitor" \
    RELEASE_SOURCE_CLEAN_MODE=all \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    BASH_ENV=/dev/null \
    /bin/bash --noprofile --norc -p "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "source guard must inspect GITHUB_WORKSPACE instead of a clean checkout selected through poisoned Git controls"
fi
if run_immutable_side_effect_guard all "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "immutable guard must reject dirty source despite poisoned PATH and Git repository, index, and fsmonitor controls"
fi
git -C "$fixture_dir" restore tracked.txt

for mutable_guard in "$source_guard" "$tag_guard" "$side_effect_guard"; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$fixture_dir/$mutable_guard"
done
if run_immutable_side_effect_guard all "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "immutable guard bootstrap must reject dirty source even when all checkout guards are replaced by no-ops"
fi
git -C "$fixture_dir" restore tools

# A Git replacement ref can otherwise make `git show GITHUB_SHA:path` resolve
# to attacker-controlled committed content while retaining the requested object
# name. The bootstrap and both child guards must disable replacement objects.
replacement_index="$fixture_root/replacement.index"
GIT_INDEX_FILE="$replacement_index" git -C "$fixture_dir" read-tree "$fixture_sha"
noop_blob="$(printf '#!/usr/bin/env bash\nexit 0\n' | git -C "$fixture_dir" hash-object -w --stdin)"
for mutable_guard in "$source_guard" "$tag_guard" "$side_effect_guard"; do
  GIT_INDEX_FILE="$replacement_index" git -C "$fixture_dir" update-index \
    --add --cacheinfo "100755,$noop_blob,$mutable_guard"
done
replacement_tree="$(GIT_INDEX_FILE="$replacement_index" git -C "$fixture_dir" write-tree)"
replacement_commit="$(printf 'malicious replacement guards\n' | git -C "$fixture_dir" commit-tree "$replacement_tree" -p "$fixture_sha")"
git -C "$fixture_dir" replace "$fixture_sha" "$replacement_commit"
printf 'replacement-ref attack\n' >> "$fixture_dir/tracked.txt"
if run_immutable_side_effect_guard all "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "immutable guard bootstrap must reject dirty source despite a no-op replacement commit for GITHUB_SHA"
fi
git -C "$fixture_dir" replace -d "$fixture_sha" >/dev/null
GIT_NO_REPLACE_OBJECTS=1 git -C "$fixture_dir" restore tracked.txt

git -C "$fixture_dir" tag -f -a "$release_tag" -m "retargeted object" "$fixture_sha" >/dev/null
git -C "$fixture_dir" push -q --force origin "refs/tags/$release_tag"
canonical_fixture_url="file://${fixture_root}/remote.git"
attacker_fixture_url="file://${attacker_remote}"
git -C "$fixture_dir" remote set-url origin "$attacker_remote"
git -C "$fixture_dir" config "url.${attacker_fixture_url}.insteadOf" "$canonical_fixture_url"
if run_tag_guard false "$fixture_tag_object" "$fixture_tag_commit" >/dev/null 2>&1; then
  fail "tag guard must reject canonical tag retargeting despite malicious origin and insteadOf configuration serving the old tag"
fi
git -C "$fixture_dir" remote set-url origin "$fixture_remote"
git -C "$fixture_dir" config --unset-all "url.${attacker_fixture_url}.insteadOf"
for mutable_guard in "$source_guard" "$tag_guard" "$side_effect_guard"; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$fixture_dir/$mutable_guard"
done
tag_mismatch_output=""
if tag_mismatch_output="$(
  cd "$fixture_dir"
  /usr/bin/git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false -C "$fixture_dir" show "${fixture_sha}:tools/verify_release_tag.sh" | \
    BASH_ENV=/dev/null \
    DRY_RUN=false \
    RELEASE_TAG="$release_tag" \
    EXPECTED_TAG_OBJECT_SHA="$fixture_tag_object" \
    EXPECTED_TAG_COMMIT_SHA="$fixture_tag_commit" \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    GITHUB_ACTIONS=false \
    GITHUB_SERVER_URL="file://$fixture_root" \
    GITHUB_REPOSITORY=remote \
    /bin/bash --noprofile --norc -p 2>&1
)"; then
  fail "immutable guard bootstrap must reject a remote tag mismatch despite no-op checkout guards"
fi
grep -F 'authoritative release tag object changed' <<<"$tag_mismatch_output" >/dev/null \
  || fail "immutable tag guard must reject the remote tag mismatch after checkout guards are no-ops"
git -C "$fixture_dir" restore tools
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
if (
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "tracked-source mode must reject untracked artifacts without an explicit generated-output allowlist"
fi
(
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    RELEASE_ALLOWED_UNTRACKED_PATHS=untracked.txt \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null || fail "tracked-source mode must permit intentionally generated untracked artifacts"
printf 'mutated\n' >> "$fixture_dir/tracked.txt"
if (
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "tracked-source mode must reject a modified tracked source file"
fi
git -C "$fixture_dir" restore tracked.txt
git -C "$fixture_dir" update-index --assume-unchanged tracked.txt
printf 'hidden tracked mutation\n' >> "$fixture_dir/tracked.txt"
if (
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "source guard must reject assume-unchanged index flags that can hide tracked-source mutations"
fi
git -C "$fixture_dir" update-index --no-assume-unchanged tracked.txt
git -C "$fixture_dir" restore tracked.txt
if (
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=invalid \
    EXPECTED_COMMIT_SHA="$fixture_sha" \
    GITHUB_SHA="$fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$fixture_sha" \
    bash "$repo_root/$source_guard"
) >/dev/null 2>&1; then
  fail "source guard must reject an unknown cleanliness mode"
fi

git -C "$fixture_dir" update-index --add --cacheinfo "160000,$fixture_sha,unsupported-submodule"
git -C "$fixture_dir" commit -qm "unsupported gitlink fixture"
gitlink_fixture_sha="$(git -C "$fixture_dir" rev-parse HEAD)"
gitlink_guard_output=""
if gitlink_guard_output="$(
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
    EXPECTED_COMMIT_SHA="$gitlink_fixture_sha" \
    GITHUB_SHA="$gitlink_fixture_sha" \
    GITHUB_WORKSPACE="$fixture_dir" \
    TRUSTED_RELEASE_REF="$gitlink_fixture_sha" \
    bash "$repo_root/$source_guard" 2>&1
)"; then
  fail "source guard must fail closed when immutable release source contains a gitlink"
fi
grep -F 'release source cannot contain Git submodules: unsupported-submodule' <<<"$gitlink_guard_output" >/dev/null \
  || fail "source guard must report the rejected gitlink path"

job_block() {
  local job="$1"
  awk -v job="  ${job}:" '
    $0 == job { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
}

protected_jobs=(
  release-build
  package-release
  generate-sbom
  validate-sbom
  attest-release
  preflight-crates
  reproduce-crates
  publish
  build-wasm-npm
  prepare-wasm-npm
  test-llm-proxy-npm
  prepare-llm-proxy-npm
  publish-wasm-npm
  publish-llm-proxy-npm
  github-release
)
for job in "${protected_jobs[@]}"; do
  block=$(job_block "$job")
  [[ -n "$block" ]] || fail "job $job is missing"
  grep -F 'ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" >/dev/null \
    || fail "job $job checkout must use the validated immutable trusted ref"
  grep -E 'name: Verify (checked-out release|fresh publisher) source' <<<"$block" >/dev/null \
    || fail "job $job must verify the checked-out release source before work begins"
  grep -F 'EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job source check must consume the validated commit SHA"
  grep -F 'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" >/dev/null \
    || fail "job $job source check must consume the validated trusted ref"
  grep -F 'run: /bin/bash --noprofile --norc -p tools/verify_release_source.sh' <<<"$block" >/dev/null \
    || fail "job $job must execute the shared source-identity guard"
  if [[ "$job" =~ ^(reproduce-crates|publish|publish-wasm-npm|publish-llm-proxy-npm|github-release)$ ]]; then
    grep -F 'DRY_RUN: false' <<<"$block" >/dev/null \
      || fail "live job $job must fail closed outside the dry-run branch"
  else
    grep -F 'DRY_RUN: ${{ inputs.dry_run }}' <<<"$block" >/dev/null \
      || fail "job $job tag check must preserve the tag-free dry-run branch"
  fi
  grep -F 'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' <<<"$block" >/dev/null \
    || fail "job $job must revalidate the sanitized release tag"
  grep -F 'EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify-signed-tag.outputs.tag_object_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified signed-tag object ID"
  grep -F 'EXPECTED_TAG_COMMIT_SHA: ${{ needs.verify-signed-tag.outputs.tag_commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified tag's peeled commit"
  grep -F 'run: /bin/bash --noprofile --norc -p tools/verify_release_tag.sh' <<<"$block" >/dev/null \
    || fail "job $job must re-fetch and compare the current remote tag before side effects"

  checkout_line=$(grep -nF 'ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$block" | head -n 1 | cut -d: -f1)
  verify_line=$(grep -nF 'run: /bin/bash --noprofile --norc -p tools/verify_release_source.sh' <<<"$block" | head -n 1 | cut -d: -f1)
  if [ "$verify_line" -le "$checkout_line" ]; then
    fail "job $job must verify source identity after checkout"
  fi
  tag_verify_line=$(grep -nF 'run: /bin/bash --noprofile --norc -p tools/verify_release_tag.sh' <<<"$block" | head -n 1 | cut -d: -f1)
  if [ "$tag_verify_line" -le "$verify_line" ]; then
    fail "job $job must revalidate remote tag identity after verifying the checked-out source"
  fi

  if grep -F 'id: release-ref' <<<"$block" >/dev/null; then
    fail "job $job must not recompute a mutable release ref locally"
  fi
done

assert_side_effect_guard_count() {
  local job="$1"
  local expected_count="$2"
  local block
  local actual_count
  block=$(job_block "$job")
  actual_count=$(grep -cF 'verify_release_side_effect.sh' <<<"$block" || true)
  if [ "$actual_count" -ne "$expected_count" ]; then
    fail "job $job must run the final side-effect guard $expected_count times, got $actual_count"
  fi
}

assert_guard_immediately_before_step() {
  local job="$1"
  local guard_name="$2"
  local side_effect_name="$3"
  local clean_mode="$4"
  local expected_untracked_binding="$5"
  local block
  local guard_line
  local side_effect_line
  local between
  block=$(job_block "$job")
  guard_line=$(grep -nF "name: $guard_name" <<<"$block" | cut -d: -f1)
  side_effect_line=$(grep -nF "name: $side_effect_name" <<<"$block" | cut -d: -f1)
  [[ -n "$guard_line" ]] || fail "job $job is missing boundary step $guard_name"
  [[ -n "$side_effect_line" ]] || fail "job $job is missing side-effect step $side_effect_name"
  if [ "$guard_line" -ge "$side_effect_line" ]; then
    fail "job $job must run $guard_name before $side_effect_name"
  fi
  between=$(sed -n "$((guard_line + 1)),$((side_effect_line - 1))p" <<<"$block")
  grep -F '/usr/bin/git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" | BASH_ENV=/dev/null /bin/bash --noprofile --norc -p' <<<"$between" >/dev/null \
    || fail "job $job boundary $guard_name must execute the final guard from the immutable dispatch commit"
  grep -F 'unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR' <<<"$between" >/dev/null \
    || fail "job $job boundary $guard_name must scrub persisted Git control variables before the immutable bootstrap"
  grep -F 'export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1' <<<"$between" >/dev/null \
    || fail "job $job boundary $guard_name must isolate Git from inherited global and system configuration"
  for binding in \
    'BASH_ENV: /dev/null' \
    "RELEASE_SOURCE_CLEAN_MODE: $clean_mode" \
    'RELEASE_ALLOWED_UNTRACKED_PATHS:' \
    'DRY_RUN: ${{ inputs.dry_run }}' \
    'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' \
    'EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify-signed-tag.outputs.tag_object_sha }}' \
    'EXPECTED_TAG_COMMIT_SHA: ${{ needs.verify-signed-tag.outputs.tag_commit_sha }}' \
    'EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' \
    'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' \
    'RELEASE_GITHUB_TOKEN: ${{ github.token }}'; do
    grep -F "$binding" <<<"$between" >/dev/null \
      || fail "job $job boundary $guard_name must rebind $binding at step scope"
  done
  grep -F "$expected_untracked_binding" <<<"$between" >/dev/null \
    || fail "job $job boundary $guard_name must hard-code its exact generated-output allowlist"
  if grep -E '^[[:space:]]+- (name:|uses:)' <<<"$between" >/dev/null; then
    fail "job $job must run no other step between $guard_name and $side_effect_name"
  fi
}

assert_step_uses_trusted_path() {
  local job="$1"
  local step_name="$2"
  local block
  local step_line
  local next_step_line
  local step
  block=$(job_block "$job")
  step_line=$(grep -nF "name: $step_name" <<<"$block" | cut -d: -f1)
  [[ -n "$step_line" ]] || fail "job $job is missing trusted-tool step $step_name"
  next_step_line=$(awk -v start="$step_line" 'NR > start && /^[[:space:]]+- (name:|uses:)/ { print NR; exit }' <<<"$block")
  if [ -z "$next_step_line" ]; then
    next_step_line=$(($(wc -l <<<"$block") + 1))
  fi
  step=$(sed -n "${step_line},$((next_step_line - 1))p" <<<"$block")
  grep -F 'TRUSTED_RELEASE_PATH: ${{ steps.trusted-tools.outputs.path }}' <<<"$step" >/dev/null \
    || grep -F 'TRUSTED_RELEASE_PATH: ${{ steps.trusted-wasm-tools.outputs.path }}' <<<"$step" >/dev/null \
    || fail "job $job step $step_name must bind a resolver output instead of inherited PATH"
  grep -F 'export PATH="$TRUSTED_RELEASE_PATH"' <<<"$step" >/dev/null \
    || fail "job $job step $step_name must replace GITHUB_PATH before resolving commands"
}

ruby - "$workflow" <<'RUBY'
require "psych"

workflow_path = ARGV.fetch(0)
workflow = Psych.load_file(workflow_path)
jobs = workflow.fetch("jobs")

expected_needs = {
  "validate-release-inputs" => [],
  "approve" => %w[ci validate-release-inputs],
  "approve-second" => %w[ci validate-release-inputs],
  "verify-signed-tag" => %w[approve approve-second validate-release-inputs],
  "release-build" => %w[approve approve-second verify-signed-tag validate-release-inputs],
  "package-release" => %w[release-build verify-signed-tag validate-release-inputs],
  "install-cargo-cyclonedx" => %w[approve approve-second verify-signed-tag validate-release-inputs],
  "generate-sbom" => %w[install-cargo-cyclonedx verify-signed-tag validate-release-inputs],
  "validate-sbom" => %w[generate-sbom verify-signed-tag validate-release-inputs],
  "attest-release" => %w[package-release validate-sbom verify-signed-tag validate-release-inputs],
  "preflight-crates" => %w[package-release verify-signed-tag validate-release-inputs],
  "reproduce-crates" => %w[preflight-crates verify-signed-tag validate-release-inputs],
  "publish" => %w[reproduce-crates prepare-wasm-npm prepare-llm-proxy-npm attest-release verify-signed-tag validate-release-inputs],
  "install-wasm-pack" => %w[approve approve-second verify-signed-tag validate-release-inputs],
  "build-wasm-npm" => %w[install-wasm-pack verify-signed-tag validate-release-inputs],
  "prepare-wasm-npm" => %w[build-wasm-npm verify-signed-tag validate-release-inputs],
  "test-llm-proxy-npm" => %w[approve approve-second verify-signed-tag validate-release-inputs],
  "prepare-llm-proxy-npm" => %w[test-llm-proxy-npm verify-signed-tag validate-release-inputs],
  "publish-wasm-npm" => %w[publish prepare-wasm-npm prepare-llm-proxy-npm verify-signed-tag validate-release-inputs],
  "publish-llm-proxy-npm" => %w[publish-wasm-npm publish prepare-wasm-npm prepare-llm-proxy-npm verify-signed-tag validate-release-inputs],
  "github-release" => %w[package-release validate-sbom attest-release publish publish-wasm-npm publish-llm-proxy-npm verify-signed-tag validate-release-inputs]
}

expected_job_names = ["ci", *expected_needs.keys]
unless jobs.keys.sort == expected_job_names.sort
  raise "#{workflow_path}: release job graph differs from reviewed inventory: #{jobs.keys.sort.inspect}"
end
expected_needs.each do |job_name, expected|
  actual = Array(jobs.fetch(job_name)["needs"])
  raise "#{workflow_path}: #{job_name} needs #{actual.inspect}, expected #{expected.inspect}" unless actual == expected
end

loader_env = {
  "LD_PRELOAD" => "",
  "LD_AUDIT" => "",
  "LD_LIBRARY_PATH" => "",
  "GLIBC_TUNABLES" => "",
  "GCONV_PATH" => "",
  "LOCPATH" => ""
}
shell_env = { "BASH_ENV" => "/dev/null", "ENV" => "/dev/null", "CDPATH" => "" }

jobs.each do |job_name, job|
  Array(job["steps"]).each do |step|
    next unless step["run"] || step["uses"]
    next if %w[approve approve-second].include?(job_name)

    step_label = step["name"] || step["uses"]
    step_env = step.fetch("env", {})
    loader_env.each do |name, value|
      unless step_env.key?(name) && step_env[name] == value
        raise "#{workflow_path}: #{job_name} step #{step_label.inspect} must bind #{name} to an empty value"
      end
    end
    if step["run"]
      shell_env.each do |name, value|
        unless step_env.key?(name) && step_env[name] == value
          raise "#{workflow_path}: #{job_name} run step #{step_label.inspect} must bind #{name}=#{value.inspect}"
        end
      end
    end
    if step["uses"] && step["uses"] !~ /\A[^@]+@[0-9a-f]{40}\z/
      raise "#{workflow_path}: #{job_name} action #{step["uses"]} must be pinned to a full commit SHA"
    end
  end
end

guard_pairs = {
  "release-build" => [
    ["Reverify source and tag immediately before release build", "Build and transport exact legacy libexo_* native ABI scope"]
  ],
  "package-release" => [
    ["Reverify source and tag immediately before fresh artifact packaging", "Validate transport and package exact release archive"]
  ],
  "generate-sbom" => [
    ["Reverify source and tag immediately before SBOM lifecycle", "Generate strict raw CycloneDX transport with isolated tool bytes"]
  ],
  "validate-sbom" => [
    ["Reverify source and tag immediately before SBOM validation", "Strictly validate and canonicalize raw SBOMs"]
  ],
  "attest-release" => [
    ["Reverify source and tag immediately before provenance attestation", "Attest build provenance (SLSA Level 2)"]
  ],
  "build-wasm-npm" => [
    ["Reverify source and tag immediately before WASM lifecycle", "Build and transport WASM output with isolated wasm-pack bytes"]
  ],
  "prepare-wasm-npm" => [
    ["Reverify source and tag immediately before fresh WASM packaging", "Validate output and pack exact WASM npm package"]
  ],
  "test-llm-proxy-npm" => [
    ["Reverify source and tag immediately before LYNK lifecycle", "Install, test, and build LYNK package from captured source"]
  ],
  "prepare-llm-proxy-npm" => [
    ["Reverify source and tag immediately before immutable LYNK packaging", "Reconstruct and pack exact LYNK npm package"]
  ],
  "github-release" => [
    ["Reverify source and tag immediately before release creation", "Create release"]
  ]
}

guard_pairs.each do |job_name, pairs|
  steps = Array(jobs.fetch(job_name)["steps"])
  runs = steps.map { |step| step["run"].to_s }.join("\n")
  actual_guard_count = runs.scan("verify_release_side_effect.sh").length
  unless actual_guard_count == pairs.length
    raise "#{workflow_path}: #{job_name} has #{actual_guard_count} immutable side-effect guards, expected #{pairs.length}"
  end
  pairs.each do |guard_name, effect_name|
    guard_index = steps.index { |step| step["name"] == guard_name }
    effect_index = steps.index { |step| step["name"] == effect_name }
    raise "#{workflow_path}: #{job_name} is missing #{guard_name.inspect}" unless guard_index
    raise "#{workflow_path}: #{job_name} is missing #{effect_name.inspect}" unless effect_index
    unless effect_index == guard_index + 1
      raise "#{workflow_path}: #{job_name} must place #{guard_name.inspect} immediately before #{effect_name.inspect}"
    end
    guard = steps.fetch(guard_index)
    guard_run = guard.fetch("run", "")
    %w[/usr/bin/env\ -i /usr/bin/git --no-replace-objects verify_release_side_effect.sh /bin/bash\ --noprofile\ --norc\ -p].each do |fragment|
      decoded = fragment.gsub("\\ ", " ")
      raise "#{workflow_path}: #{job_name} guard #{guard_name.inspect} lacks #{decoded.inspect}" unless guard_run.include?(decoded)
    end
    guard_env = guard.fetch("env", {})
    {
      "RELEASE_SOURCE_CLEAN_MODE" => nil,
      "RELEASE_ALLOWED_UNTRACKED_PATHS" => nil,
      "DRY_RUN" => nil,
      "RELEASE_TAG" => "${{ needs.validate-release-inputs.outputs.tag }}",
      "EXPECTED_TAG_OBJECT_SHA" => "${{ needs.verify-signed-tag.outputs.tag_object_sha }}",
      "EXPECTED_TAG_COMMIT_SHA" => "${{ needs.verify-signed-tag.outputs.tag_commit_sha }}",
      "EXPECTED_COMMIT_SHA" => "${{ needs.validate-release-inputs.outputs.commit_sha }}",
      "TRUSTED_RELEASE_REF" => "${{ needs.validate-release-inputs.outputs.trusted_ref }}"
    }.each do |name, value|
      raise "#{workflow_path}: #{job_name} guard #{guard_name.inspect} must bind #{name}" unless guard_env.key?(name)
      if value && guard_env[name] != value
        raise "#{workflow_path}: #{job_name} guard #{guard_name.inspect} has untrusted #{name}"
      end
    end
  end
end

lifecycle_boundaries = {
  "release-build" => ["Build and transport exact legacy libexo_* native ABI scope", '"$cargo_path" build'],
  "generate-sbom" => ["Generate strict raw CycloneDX transport with isolated tool bytes", 'SOURCE_DATE_EPOCH=0 release_cargo "$cargo_path" cyclonedx'],
  "build-wasm-npm" => ["Build and transport WASM output with isolated wasm-pack bytes", '"$wasm_pack_path" build'],
  "prepare-wasm-npm" => ["Validate output and pack exact WASM npm package", '"$npm_path" pack'],
  "test-llm-proxy-npm" => ["Install, test, and build LYNK package from captured source", '"$npm_path" ci --ignore-scripts'],
  "prepare-llm-proxy-npm" => ["Reconstruct and pack exact LYNK npm package", '"$npm_path" pack']
}
lifecycle_boundaries.each do |job_name, (lifecycle_step_name, lifecycle_marker)|
  steps = Array(jobs.fetch(job_name)["steps"])
  lifecycle_index = steps.index { |step| step["name"] == lifecycle_step_name }
  raise "#{workflow_path}: #{job_name} is missing lifecycle boundary #{lifecycle_step_name.inspect}" unless lifecycle_index

  lifecycle_step = steps.fetch(lifecycle_index)
  lifecycle_run = lifecycle_step["run"].to_s
  marker_index = lifecycle_run.index(lifecycle_marker)
  raise "#{workflow_path}: #{job_name} lifecycle command marker is missing" unless marker_index
  lifecycle_tail = lifecycle_run[(marker_index + lifecycle_marker.length)..]
  forbidden_tail_fragments = [
    "git --no-replace-objects", "git show", "${GITHUB_SHA}:",
    "source_guard_program", "verify_release_source", "verify_release_tag",
    "verify_release_side_effect", "RELEASE_GITHUB_TOKEN", "${{ github.token }}"
  ]
  forbidden_tail_fragments.each do |fragment|
    if lifecycle_tail.include?(fragment)
      raise "#{workflow_path}: #{job_name} uses #{fragment.inspect} after its lifecycle starts"
    end
  end

  steps[lifecycle_index..].each do |step|
    step_label = step["name"] || step["uses"]
    step_text = [step["run"], step.fetch("env", {}).inspect, step.fetch("with", {}).inspect].join("\n")
    if step_text.include?("${{ github.token }}") || step_text.include?("RELEASE_GITHUB_TOKEN")
      raise "#{workflow_path}: #{job_name} exposes the repository token at or after lifecycle step #{step_label.inspect}"
    end
  end
  steps[(lifecycle_index + 1)..].to_a.each do |step|
    step_label = step["name"] || step["uses"]
    run = step["run"].to_s
    if run.include?("git --no-replace-objects") || run.include?("git show") || run.include?("${GITHUB_SHA}:") ||
       run.include?("source_guard_program") || run.include?("verify_release_side_effect")
      raise "#{workflow_path}: #{job_name} loads mutable Git object/helper bytes after lifecycle in #{step_label.inspect}"
    end
  end
end
RUBY

for trusted_tool_job in release-build generate-sbom preflight-crates publish build-wasm-npm prepare-wasm-npm test-llm-proxy-npm prepare-llm-proxy-npm publish-wasm-npm publish-llm-proxy-npm; do
  trusted_tool_block=$(job_block "$trusted_tool_job")
  grep -F 'tools/resolve_release_tool_path.sh' <<<"$trusted_tool_block" >/dev/null \
    || fail "job $trusted_tool_job must load its trusted PATH resolver from the immutable dispatch commit"
  resolver_load_count=$(grep -cF 'tools/resolve_release_tool_path.sh' <<<"$trusted_tool_block" || true)
  protected_resolver_load_count=$(grep -cF '/usr/bin/git --no-replace-objects' <<<"$trusted_tool_block" || true)
  if [ "$protected_resolver_load_count" -eq 0 ]; then
    grep -F 'source "$GITHUB_WORKSPACE/tools/capture_release_helper.sh"' <<<"$trusted_tool_block" >/dev/null \
      && grep -F 'capture_release_helper tools/resolve_release_tool_path.sh resolver_program' <<<"$trusted_tool_block" >/dev/null \
      || fail "job $trusted_tool_job must use the replacement-disabled capture helper before loading the trusted PATH resolver"
  fi
  [ "$resolver_load_count" -gt 0 ] \
    || fail "job $trusted_tool_job has no trusted PATH resolver load"
done

node_pin_count=$(grep -cF 'node-version: 22.14.0' "$workflow" || true)
[ "$node_pin_count" -eq 8 ] \
  || fail "all eight Node.js release jobs must pin exact Node.js 22.14.0, got $node_pin_count"
rust_pin_count=$(grep -cF 'toolchain: 1.97.1' "$workflow" || true)
[ "$rust_pin_count" -eq 9 ] \
  || fail "all nine Rust release jobs must pin exact Rust 1.97.1, got $rust_pin_count"
python_pin_count=$(grep -cF 'python-version: 3.13.7' "$workflow" || true)
[ "$python_pin_count" -eq 16 ] \
  || fail "all sixteen Python release jobs must pin exact Python 3.13.7, got $python_pin_count"
if grep -F 'ubuntu-latest' "$workflow" >/dev/null; then
  fail "release jobs must use the explicit ubuntu-24.04 runner image"
fi

release_build_block=$(job_block "release-build")
package_release_block=$(job_block "package-release")
build_wasm_block=$(job_block "build-wasm-npm")
prepare_wasm_block=$(job_block "prepare-wasm-npm")
test_llm_block=$(job_block "test-llm-proxy-npm")
prepare_llm_block=$(job_block "prepare-llm-proxy-npm")
github_release_block=$(job_block "github-release")

grep -F 'build --manifest-path "$GITHUB_WORKSPACE/Cargo.toml" --workspace --release --locked --target ${{ matrix.target }}' <<<"$release_build_block" >/dev/null \
  || fail "release-build must refuse lockfile refresh while producing raw outputs"
grep -F 'capture_release_helper tools/transport_release_build_output.py transport_program' <<<"$release_build_block" >/dev/null \
  && grep -F '"$python_path" -I -B - create' <<<"$release_build_block" >/dev/null \
  || fail "release-build must upload only a strict raw-output transport"
if grep -F '.tar.gz' <<<"$release_build_block" >/dev/null; then
  fail "release-build lifecycle job must not create final release archives"
fi
grep -F '${GITHUB_SHA}:tools/transport_release_build_output.py' <<<"$package_release_block" >/dev/null \
  && grep -F '"$python_path" -I -B - extract' <<<"$package_release_block" >/dev/null \
  || fail "fresh package-release must validate and extract the strict native transport"
grep -F 'exochain-${{ needs.validate-release-inputs.outputs.version }}-${{ matrix.target }}.tar.gz' <<<"$package_release_block" >/dev/null \
  || fail "fresh package-release must create the exact versioned native archive"

grep -F 'capture_release_helper tools/transport_wasm_release_output.py transport_program' <<<"$build_wasm_block" >/dev/null \
  && grep -F '"$python_path" -I -B - create' <<<"$build_wasm_block" >/dev/null \
  || fail "WASM lifecycle job must upload only a strict generated-output transport"
if grep -F '"$npm_path" pack' <<<"$build_wasm_block" >/dev/null; then
  fail "WASM lifecycle job must not create the npm publication tarball"
fi
grep -F '${GITHUB_SHA}:tools/transport_wasm_release_output.py' <<<"$prepare_wasm_block" >/dev/null \
  && grep -F '"$python_path" -I -B - extract' <<<"$prepare_wasm_block" >/dev/null \
  || fail "fresh WASM packaging job must validate and extract the strict output transport"
grep -F '${GITHUB_SHA}:packages/exochain-wasm/wasm/package.json' <<<"$prepare_wasm_block" >/dev/null \
  || fail "fresh WASM packaging must reconstruct package metadata from the immutable commit"
grep -F '${GITHUB_SHA}:packages/exochain-wasm/wasm/LICENSE' <<<"$prepare_wasm_block" >/dev/null \
  || fail "fresh WASM packaging must reconstruct the license from the immutable commit"

if grep -F '"$npm_path" pack' <<<"$test_llm_block" >/dev/null; then
  fail "LYNK lifecycle job must not pack publication bytes"
fi
grep -F 'capture_release_helper tools/transport_release_file_set.py transport_program' <<<"$test_llm_block" >/dev/null \
  && grep -F -- '--profile llm-dist' <<<"$test_llm_block" >/dev/null \
  && grep -F 'Upload untrusted LYNK tested-dist transport' <<<"$test_llm_block" >/dev/null \
  || fail "LYNK lifecycle job must transport only its exact tested dist file set"
[ "$(grep -cF '"$RELEASE_LLM_PACKAGE_DIR/dist"' <<<"$test_llm_block" || true)" -ge 2 ] \
  || fail "LYNK lifecycle job must clean dist before tests and again immediately before the release build"
grep -F 'tools/stage_llm_release_package.sh' <<<"$prepare_llm_block" >/dev/null \
  || fail "fresh LYNK packaging job must reconstruct the package from immutable source"
grep -F 'RELEASE_LLM_BUILD_DIR:' <<<"$prepare_llm_block" >/dev/null \
  && grep -F 'needs.test-llm-proxy-npm.outputs.transport_sha256' <<<"$prepare_llm_block" >/dev/null \
  && grep -F -- '--profile llm-dist' <<<"$prepare_llm_block" >/dev/null \
  && grep -F 'RELEASE_LLM_BUILD_DIR="$RELEASE_LLM_BUILD_DIR"' <<<"$prepare_llm_block" >/dev/null \
  || fail "fresh LYNK packaging must validate and compare the independently digested tested dist transport"

grep -F 'install cargo-cyclonedx --version 0.5.9 --locked' "$workflow" >/dev/null \
  || fail "SBOM generation must use the reviewed locked cargo-cyclonedx installation"
grep -F 'metadata --manifest-path "$GITHUB_WORKSPACE/Cargo.toml"' "$workflow" >/dev/null \
  && grep -F -- '--format-version 1 --locked' "$workflow" >/dev/null \
  && grep -F 'SOURCE_DATE_EPOCH=0 release_cargo "$cargo_path" cyclonedx' "$workflow" >/dev/null \
  && grep -F -- '-f json --all --target all --spec-version 1.5' "$workflow" >/dev/null \
  || fail "SBOM generation must bracket tooling with locked workspace metadata"
[ "$(grep -cF 'tools/publish_release_crates.sh' "$workflow" || true)" -eq 1 ] \
  || fail "workflow must expose exactly one live Cargo publication route"
[ "$(grep -cF 'tools/publish_release_npm_package.sh' "$workflow" || true)" -eq 2 ] \
  || fail "workflow must expose exactly two serialized npm publication routes"
[ "$(grep -cF 'actions/attest-build-provenance@' "$workflow" || true)" -eq 1 ] \
  || fail "workflow must expose exactly one provenance attestation route"
[ "$(grep -cF 'softprops/action-gh-release@' "$workflow" || true)" -eq 1 ] \
  || fail "workflow must expose exactly one GitHub release route"
if grep -E '^[[:space:]]+(cargo publish|npm publish)' "$workflow" >/dev/null; then
  fail "workflow must route registry publication only through reviewed immutable helpers"
fi
if grep -F -- '--allow-dirty' "$workflow" >/dev/null; then
  fail "release workflow must reject dirty Cargo publication inputs"
fi

if grep -F '/usr/bin/python3' "$workflow" >/dev/null; then
  fail "release workflow must use only the exact setup-python interpreter"
fi

grep -F 'name: Download exact x86_64 release archive' <<<"$github_release_block" >/dev/null \
  || fail "GitHub release must download the exact x86_64 archive artifact"
grep -F 'name: Download exact aarch64 release archive' <<<"$github_release_block" >/dev/null \
  || fail "GitHub release must download the exact aarch64 archive artifact"
grep -F 'name: Download exact versioned release SBOM set' <<<"$github_release_block" >/dev/null \
  || fail "GitHub release must download the exact versioned SBOM artifact"
grep -F 'Validate exact GitHub release asset inventory' <<<"$github_release_block" >/dev/null \
  || fail "GitHub release must validate its exact two-archive and SBOM inventory"
grep -F 'target_commitish: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$github_release_block" >/dev/null \
  || fail "GitHub release must bind tag auto-creation fallback to the validated commit"
if grep -F 'Download all artifacts' <<<"$github_release_block" >/dev/null || grep -F 'sbom-ci-' <<<"$github_release_block" >/dev/null; then
  fail "GitHub release must not consume broad or CI-only artifacts"
fi

printf 'release workflow ref-binding test passed\n'
