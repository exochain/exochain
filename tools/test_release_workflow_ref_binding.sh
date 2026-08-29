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
side_effect_guard="tools/verify_release_side_effect.sh"
[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$source_guard" ]] || fail "$source_guard is missing"
[[ -f "$tag_guard" ]] || fail "$tag_guard is missing"
[[ -f "$side_effect_guard" ]] || fail "$side_effect_guard is missing"
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
grep -F 'ls-tree -r -t -z --full-tree "$expected_commit_sha"' "$source_guard" >/dev/null \
  || fail "$source_guard must derive a NUL-safe manifest from the immutable commit tree"
grep -F 'hash-object --no-filters' "$source_guard" >/dev/null \
  || fail "$source_guard must hash raw tracked bytes without clean filters"
grep -F 'release source cannot contain Git submodules' "$source_guard" >/dev/null \
  || fail "$source_guard must fail closed when the commit tree contains a gitlink"
grep -F 'ls-files --others --exclude-per-directory=.gitignore -z' "$source_guard" >/dev/null \
  || fail "$source_guard all mode must not trust local exclude files when finding untracked inputs"

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
  "validate-release-inputs" => { "contents" => "read" },
  "verify-signed-tag" => { "contents" => "read" },
  "release-build" => { "contents" => "read" },
  "sbom-and-attest" => {
    "contents" => "read",
    "attestations" => "write",
    "id-token" => "write"
  },
  "publish" => { "contents" => "read" },
  "publish-wasm-npm" => { "contents" => "read", "id-token" => "write" },
  "publish-llm-proxy-npm" => { "contents" => "read", "id-token" => "write" },
  "github-release" => { "contents" => "write" }
}

jobs.children.each_slice(2) do |job_key, job|
  next unless job_key.is_a?(Psych::Nodes::Scalar) && job.is_a?(Psych::Nodes::Mapping)

  job_name = job_key.value
  steps = mapping_value(job, "steps")
  has_checkout = steps.is_a?(Psych::Nodes::Sequence) && steps.children.any? do |step|
    uses = mapping_value(step, "uses")
    uses.is_a?(Psych::Nodes::Scalar) && uses.value.start_with?("actions/checkout@")
  end
  permissions = mapping_value(job, "permissions")

  if has_checkout
    raise "#{workflow_path}: #{job_name} checkout job needs an explicit least-privilege permissions block" unless permissions
    actual = scalar_mapping(permissions)
    expected = expected_permissions.fetch(job_name) do
      raise "#{workflow_path}: no reviewed least-privilege permission set for checkout job #{job_name}"
    end
    unless actual == expected
      raise "#{workflow_path}: #{job_name} permissions #{actual.inspect} must equal #{expected.inspect}"
    end
  elsif permissions
    raise "#{workflow_path}: unexpected unreviewed permissions block on #{job_name}" unless expected_permissions.key?(job_name)
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
mkdir -p "$fake_bin_dir" "$poison_home"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fake_git"
printf '#!/usr/bin/env bash\nprintf "poison-clock\\n"\n' > "$poison_fsmonitor"
printf '[core]\n\tworktree = %s\n\tfsmonitor = %s\n' "$attacker_dir" "$poison_fsmonitor" > "$poison_home/.gitconfig"
chmod +x "$fake_git" "$poison_fsmonitor"
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
git -C "$fixture_dir" update-index --refresh

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
(
  cd "$fixture_dir"
  RELEASE_SOURCE_CLEAN_MODE=tracked \
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
  grep -F 'run: /bin/bash --noprofile --norc -p tools/verify_release_source.sh' <<<"$block" >/dev/null \
    || fail "job $job must execute the shared source-identity guard"
  grep -F 'DRY_RUN: ${{ inputs.dry_run }}' <<<"$block" >/dev/null \
    || fail "job $job tag check must preserve the tag-free dry-run branch"
  grep -F 'RELEASE_TAG: ${{ needs.validate-release-inputs.outputs.tag }}' <<<"$block" >/dev/null \
    || fail "job $job must revalidate the sanitized release tag"
  grep -F 'EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify-signed-tag.outputs.tag_object_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified signed-tag object ID"
  grep -F 'EXPECTED_TAG_COMMIT_SHA: ${{ needs.verify-signed-tag.outputs.tag_commit_sha }}' <<<"$block" >/dev/null \
    || fail "job $job must consume the verified tag's peeled commit"
  grep -F 'RELEASE_GITHUB_TOKEN: ${{ github.token }}' <<<"$block" >/dev/null \
    || fail "job $job must bind the repository token for authoritative tag lookup"
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
  if grep -E '^[[:space:]]+- (name:|uses:)' <<<"$between" >/dev/null; then
    fail "job $job must run no other step between $guard_name and $side_effect_name"
  fi
}

assert_side_effect_guard_count release-build 3
assert_guard_immediately_before_step release-build \
  "Reverify source and tag immediately before release build" "Build release" all
assert_guard_immediately_before_step release-build \
  "Reverify source and tag immediately before artifact packaging" "Package artifacts" tracked
assert_guard_immediately_before_step release-build \
  "Reverify source and tag immediately before artifact upload" "Upload artifacts" tracked

assert_side_effect_guard_count sbom-and-attest 4
assert_guard_immediately_before_step sbom-and-attest \
  "Reverify source and tag immediately before archive collection" "Collect release archives" tracked
assert_guard_immediately_before_step sbom-and-attest \
  "Reverify source and tag immediately before SBOM generation" "Generate CycloneDX SBOM" tracked
assert_guard_immediately_before_step sbom-and-attest \
  "Reverify source and tag immediately before SBOM upload" "Upload SBOM artifacts" tracked
assert_guard_immediately_before_step sbom-and-attest \
  "Reverify source and tag immediately before provenance attestation" "Attest build provenance (SLSA Level 2)" tracked

assert_side_effect_guard_count publish 2

assert_side_effect_guard_count publish-wasm-npm 4
assert_guard_immediately_before_step publish-wasm-npm \
  "Reverify source and tag immediately before WASM build" "Build scoped WASM npm package" all
assert_guard_immediately_before_step publish-wasm-npm \
  "Reverify source and tag immediately before WASM package preparation" "Prepare scoped WASM npm package" tracked
assert_guard_immediately_before_step publish-wasm-npm \
  "Reverify source and tag immediately before WASM dry-pack" "Dry-pack WASM npm package" tracked

assert_side_effect_guard_count publish-llm-proxy-npm 4
assert_guard_immediately_before_step publish-llm-proxy-npm \
  "Reverify source and tag immediately before LYNK coverage" "Run LYNK package coverage gate" all
assert_guard_immediately_before_step publish-llm-proxy-npm \
  "Reverify source and tag immediately before LYNK build" "Build LYNK npm package" all
assert_guard_immediately_before_step publish-llm-proxy-npm \
  "Reverify source and tag immediately before LYNK dry-pack" "Dry-pack LYNK npm package" all

assert_side_effect_guard_count github-release 1
assert_guard_immediately_before_step github-release \
  "Reverify source and tag immediately before release creation" "Create release" tracked

github_release_block=$(job_block "github-release")
github_initial_tag_verify_count=$(grep -cF 'run: /bin/bash --noprofile --norc -p tools/verify_release_tag.sh' <<<"$github_release_block")
if [ "$github_initial_tag_verify_count" -ne 1 ]; then
  fail "github-release must validate the remote tag after checkout before running job work"
fi
last_tag_verify_line=$(grep -nF 'verify_release_side_effect.sh' <<<"$github_release_block" | tail -n 1 | cut -d: -f1)
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
