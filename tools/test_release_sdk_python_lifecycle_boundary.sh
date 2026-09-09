#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'SDK/Python release lifecycle test failed: %s\n' "$1" >&2
  exit 1
}

workflow=.github/workflows/release.yml
ci_workflow=.github/workflows/ci.yml
npm_publisher=tools/publish_release_npm_package.sh
python_guard=tools/verify_python_release_package.py

for required in "$workflow" "$ci_workflow" "$npm_publisher" "$python_guard"; do
  [[ -f "$required" ]] || fail "$required is missing"
done

grep -F "sdk) package_name='@exochain/sdk'" "$npm_publisher" >/dev/null \
  || fail "the hardened npm publisher has no @exochain/sdk profile"
grep -F "sdk) registry_path='%40exochain%2Fsdk'" "$npm_publisher" >/dev/null \
  || fail "the SDK registry path is not fixed by the publisher"
grep -F -- '--provenance' "$npm_publisher" >/dev/null \
  || fail "npm publication must emit registry provenance"
for npm_invocation in \
  'run_authenticated_npm audit signatures --json --include-attestations > "$audit_response"' \
  'run_authenticated_npm whoami --registry=https://registry.npmjs.org' \
  'run_authenticated_npm owner ls "$package_name" --registry=https://registry.npmjs.org' \
  '"$registry_verifier" audit' \
  '"$registry_verifier" registry'; do
  grep -F "$npm_invocation" "$npm_publisher" >/dev/null \
    || fail "npm publication is missing executable invocation: $npm_invocation"
done
if grep -Eq '(^|[[:space:];])exit[[:space:]]+0([[:space:];]|$)' "$npm_publisher"; then
  fail "npm publisher must converge through one final proof path, not early successful exits"
fi
grep -F 'show "${GITHUB_SHA}:tools/verify_release_side_effect.sh"' "$npm_publisher" >/dev/null \
  || fail "npm publisher does not load the final rebind helper from the immutable commit"
[[ $(grep -Ec '^  verify_release_binding$|^verify_release_binding$' "$npm_publisher") -eq 2 ]] \
  || fail "npm publisher must invoke release binding before mutation and again before success"

ruby - "$workflow" "$ci_workflow" <<'RUBY'
require "psych"
require "shellwords"

def value(mapping, key)
  return nil unless mapping.is_a?(Psych::Nodes::Mapping)
  mapping.children.each_slice(2) do |candidate, child|
    return child if candidate.is_a?(Psych::Nodes::Scalar) && candidate.value == key
  end
  nil
end

def job(jobs, name)
  value(jobs, name) or raise "missing job #{name}"
end

def scalar(node)
  node.is_a?(Psych::Nodes::Scalar) ? node.value : nil
end

def step_label(step)
  scalar(value(step, "name")) || scalar(value(step, "uses")) || "unnamed"
end

def step_text(step)
  [scalar(value(step, "name")), scalar(value(step, "uses")), scalar(value(step, "run"))]
    .compact.join("\n")
end

def step_run(step)
  scalar(value(step, "run")) || ""
end

def node_text(node)
  return node.value if node.is_a?(Psych::Nodes::Scalar)
  return "" unless node.respond_to?(:children) && node.children
  node.children.map { |child| node_text(child) }.join("\n")
end

document = Psych.parse_file(ARGV.fetch(0))
jobs = value(document.root, "jobs")
raise "jobs mapping missing" unless jobs.is_a?(Psych::Nodes::Mapping)

ci_document = Psych.parse_file(ARGV.fetch(1))
ci_jobs = value(ci_document.root, "jobs")
raise "CI jobs mapping missing" unless ci_jobs.is_a?(Psych::Nodes::Mapping)
hygiene_steps = value(job(ci_jobs, "hygiene"), "steps")
guard_command = "bash tools/test_release_sdk_python_lifecycle_boundary.sh"
guard_runs = hygiene_steps.children.count do |step|
  scalar(value(step, "run"))&.lines&.map(&:strip)&.include?(guard_command)
end
raise "CI must invoke this guard exactly once through a run command" unless guard_runs == 1

%w[prepare-sdk-npm prepare-python-package publish-sdk-npm publish-python-package].each do |name|
  job(jobs, name)
end

prepare_sdk = job(jobs, "prepare-sdk-npm")
prepare_python = job(jobs, "prepare-python-package")
publish_sdk = job(jobs, "publish-sdk-npm")
publish_python = job(jobs, "publish-python-package")
github_release = job(jobs, "github-release")
raise "Python trusted publisher must be bound to the release environment" \
  unless scalar(value(publish_python, "environment")) == "release"

{
  "prepare-sdk-npm" => prepare_sdk,
  "prepare-python-package" => prepare_python,
}.each do |name, definition|
  permissions = value(definition, "permissions")
  actual = permissions.children.each_slice(2).to_h { |key, val| [key.value, val.value] }
  raise "#{name} must have only contents: read" unless actual == { "contents" => "read" }
  source = node_text(definition)
  %w[NODE_AUTH_TOKEN NPM_TOKEN PYPI_API_TOKEN id-token].each do |secret_marker|
    raise "#{name} contains credential authority #{secret_marker}" if source.include?(secret_marker)
  end
end

sdk_text = value(prepare_sdk, "steps").children.map { |step| step_run(step) }.join("\n")
['"$npm_path" ci', '"$npm_path" run "$command"', '"$npm_path" run build',
 'sdk-source', '"$npm_path" pack'].each do |needle|
  raise "SDK token-free lane is missing #{needle}" unless sdk_text.include?(needle)
end
raise "SDK lane does not publish a SHA-256 output" unless sdk_text.include?("tarball_sha256")

sdk_pack_step = value(prepare_sdk, "steps").children.find do |step|
  step_run(step).include?('"$npm_path" pack')
end
raise "SDK package step is missing" unless sdk_pack_step
sdk_pack_run = step_run(sdk_pack_step)
sdk_directory_loop = sdk_pack_run.match(/^for directory in ([^\n]+); do$/)
raise "SDK package directory initialization is missing" unless sdk_directory_loop
sdk_created_directories = Shellwords.split(sdk_directory_loop[1])
raise "SDK tarball verifier requires extract_dir to remain absent during directory initialization" \
  unless sdk_created_directories == %w[$source_root $pack_dir $npm_home]

python_text = value(prepare_python, "steps").children.map { |step| step_run(step) }.join("\n")
%w[-m\ pytest -m\ ruff -m\ mypy -m\ build verify_python_release_package.py].each do |needle|
  raise "Python token-free lane is missing #{needle}" unless python_text.include?(needle)
end
raise "Python lane does not create a digest manifest" unless python_text.include?("artifact-manifest")
%w[python-release-requirements.lock --require-hashes --only-binary=:all:].each do |needle|
  raise "Python lane does not enforce locked tools through #{needle}" unless python_text.include?(needle)
end
raise "Python lane still executes an editable/open-resolver install" \
  if python_text.include?("pip install") && python_text.match?(/pip install[^\n]*(?:\s-e\s|\[dev\])/)
package_step = value(prepare_python, "steps").children.find do |step|
  step_run(step).include?("-m build")
end
package_run = scalar(value(package_step, "run"))
raise "Python package step is missing" unless package_run
test_position = package_run.index('-m pytest')
reconstruct_position = package_run.index('tar -xf "$sealed_source" -C "$build_source_root"')
raise "Python publishable source must be freshly reconstructed after mutable tests" \
  unless test_position && reconstruct_position && reconstruct_position > test_position
raise "Python source archive must be hash-sealed across mutable test execution" \
  unless package_run.include?("source_archive_sha256") && package_run.include?("sha256sum")

{
  "publish-sdk-npm" => publish_sdk,
  "publish-python-package" => publish_python,
}.each do |name, definition|
  condition = scalar(value(definition, "if"))
  raise "#{name} must be disabled in dry runs" unless condition&.include?("!inputs.dry_run")
  permissions = value(definition, "permissions")
  actual = permissions.children.each_slice(2).to_h { |key, val| [key.value, val.value] }
  raise "#{name} needs contents read and OIDC only" unless actual == {
    "contents" => "read", "id-token" => "write"
  }
end

sdk_publish_text = value(publish_sdk, "steps").children.map { |step| step_run(step) }.join("\n")
%w[publish_release_npm_package.sh RELEASE_EXPECTED_TARBALL_SHA256].each do |needle|
  raise "SDK publisher is missing #{needle}" unless sdk_publish_text.include?(needle)
end

python_steps = value(publish_python, "steps").children
action_index = python_steps.index do |step|
  scalar(value(step, "uses"))&.start_with?("pypa/gh-action-pypi-publish@")
end
raise "Python publisher does not use the PyPA trusted-publishing action" unless action_index
action = python_steps.fetch(action_index)
action_ref = scalar(value(action, "uses"))
expected_action = "pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b"
raise "PyPA publisher action differs from the reviewed immutable release" unless action_ref == expected_action
inputs = value(action, "with")
input_map = inputs.children.each_slice(2).to_h { |key, val| [key.value, val.value] }
raise "PyPI attestations must be enabled" unless input_map["attestations"] == "true"
raise "PyPI package directory must be explicit" unless input_map.key?("packages-dir")
raise "PyPI publication must reject pre-existing mismatched files" unless input_map["skip-existing"] == "false"
prior = python_steps.fetch(action_index - 1)
raise "live source/tag rebind must be immediately before PyPI mutation" \
  unless step_run(prior).include?("verify_release_side_effect.sh")
raise "PyPI guard and mutation must share the same publish-needed condition" \
  unless scalar(value(prior, "if")) == scalar(value(action, "if"))
post_text = python_steps[(action_index + 1)..].map { |step| step_run(step) }.join("\n")
%w[registry-response verify_python_release_package.py pypi-attestations verify\ pypi \
   /integrity/exochain/ provenance application/vnd.pypi.integrity.v1+json].each do |needle|
  raise "Python publisher has no strict per-file provenance proof through #{needle}" \
    unless post_text.include?(needle)
end
raise "Python publisher does not execute the official PEP 740 verifier" \
  unless post_text.include?('"$attestation_cli" verify pypi')
raise "Python publisher does not execute the exact identity/digest verifier for each provenance" \
  unless post_text.include?('"$tool_python" -I -B "$verifier" provenance')
readback = python_steps[(action_index + 1)..].find { |step| step_run(step).include?("registry-response") }
raise "Python publisher readback may bypass final binding with exit 0" \
  if scalar(value(readback, "run"))&.match?(/(^|[;\s])exit\s+0([;\s]|$)/)
readback_env = value(readback, "env")
expected_manifest_sha = scalar(value(readback_env, "RELEASE_EXPECTED_MANIFEST_SHA256"))
raise "Python readback must bind the manifest to the token-free producer output" \
  unless expected_manifest_sha == "${{ needs.prepare-python-package.outputs.manifest_sha256 }}"
readback_run = step_run(readback)
raise "Python readback must verify the trusted manifest after the publisher action" \
  unless readback_run.include?('sha256sum "$manifest"') &&
         readback_run.include?('RELEASE_EXPECTED_MANIFEST_SHA256')
final_step = python_steps.last
raise "every PyPI success path must end in a final live source/tag rebind" \
  unless step_run(final_step).include?("verify_release_side_effect.sh")
raise "final PyPI source/tag rebind must run for both existing and newly published versions" \
  if value(final_step, "if")

needs = value(github_release, "needs")
dependency_names = needs.children.map(&:value)
%w[publish-sdk-npm publish-python-package].each do |required|
  raise "GitHub Release does not depend on #{required}" unless dependency_names.include?(required)
end
RUBY

printf 'SDK/Python release lifecycle test passed\n'
