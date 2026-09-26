#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Regression firewall for the fixed recovery DAG and dispatch boundary."""
from pathlib import Path
import copy
import ast
import json
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NORMAL = (
    "release-build package-release install-cargo-cyclonedx generate-sbom "
    "validate-sbom attest-release preflight-crates reproduce-crates publish "
    "install-wasm-pack build-wasm-npm prepare-wasm-npm test-llm-proxy-npm "
    "prepare-llm-proxy-npm prepare-sdk-npm prepare-python-package "
    "publish-wasm-npm publish-llm-proxy-npm publish-sdk-npm "
    "publish-python-package github-release"
).split()
RECOVERY = "recovery-import recovery-wasm recovery-llm recovery-sdk recovery-python recovery-github".split()
RETAINED = ['retained-acceptance', 'retained-github']


def parsed_workflow(source):
    # Audit Psych's lossless tree before constructing objects: never let a
    # duplicate/alias/tag or YAML 1.1 key reinterpretation hide authority.
    ruby = r'''
require 'yaml'; require 'json'
walk = nil
walk = lambda do |n|
  raise 'alias or tag' if n.is_a?(Psych::Nodes::Alias) ||
    (n.respond_to?(:anchor) && n.anchor) || (n.respond_to?(:tag) && n.tag)
  if n.is_a?(Psych::Nodes::Mapping)
    keys = {}
    n.children.each_slice(2) do |k,v|
      raise 'key type' unless k.is_a?(Psych::Nodes::Scalar)
      raise 'duplicate/merge' if keys[k.value] || k.value == '<<'
      raise 'ambiguous key' if k.plain && !YAML.safe_load(k.value).is_a?(String)
      keys[k.value] = true
    end
  end
  (n.children || []).each { |c| walk.call(c) } if n.respond_to?(:children)
end
source = STDIN.read
walk.call(Psych.parse_stream(source))
puts JSON.generate(YAML.safe_load(source))
'''
    result = subprocess.run(['ruby', '-e', ruby], input=source, text=True, capture_output=True)
    if result.returncode:
        raise ValueError('workflow YAML rejected')
    return json.loads(result.stdout)


def retained_policy(value):
    def require(condition):
        if not condition:
            raise ValueError('retained workflow boundary rejected')
    jobs = value['jobs']
    require(value['permissions'] == {'contents':'read'})
    require(all(term not in json.dumps(value.get('env',{})) for term in
                ('secrets.','TOKEN','PASSWORD','ACTIONS_ID_TOKEN','GITHUB_')))
    require(value['on']['workflow_dispatch']['inputs']['operation']['options'] ==
            ['release', 'recover-0.2.7', 'recover-0.2.7-retained', 'recover-0.2.7-retained-404'])
    for names, operation in ((NORMAL, 'release'), (RECOVERY, 'recover-0.2.7')):
        for name in names:
            condition = jobs[name]['if']
            require(condition in ("${{ needs.validate-release-inputs.outputs.operation == '" + operation + "' }}",
                                  "${{ needs.validate-release-inputs.outputs.operation == '" + operation + "' && !inputs.dry_run }}"))
    acceptance, writer = (jobs[name] for name in RETAINED)
    prerequisites = ['ci', 'approve', 'approve-second', 'verify-signed-tag', 'validate-release-inputs']
    require(acceptance['needs'] == prerequisites)
    require(writer['needs'] == prerequisites + ['retained-acceptance'])
    require(jobs['ci']['uses'] == './.github/workflows/ci.yml')
    for name, environment in [('approve', 'release'), ('approve-second', 'release-second')]:
        require(jobs[name]['environment'] == environment and jobs[name]['needs'] == ['ci', 'validate-release-inputs'])
    require(jobs['verify-signed-tag']['needs'] == ['approve', 'approve-second', 'validate-release-inputs'])
    require(acceptance['permissions'] == {'contents':'read', 'actions':'read', 'attestations':'read'})
    require(writer['permissions'] == {'contents':'write', 'actions':'read'})
    require(writer['environment'] == 'release')
    retained_condition = "(needs.validate-release-inputs.outputs.operation == 'recover-0.2.7-retained' || needs.validate-release-inputs.outputs.operation == 'recover-0.2.7-retained-404')"
    require(acceptance['if'] == '${{ ' + retained_condition + ' }}')
    require(writer['if'] == '${{ ' + retained_condition + ' && !inputs.dry_run }}')
    require(acceptance['name'] == 'Verify Retained 0.2.7 Custody and Publications')
    for job, operation in [(acceptance, 'retained-acceptance'), (writer, 'retained-github')]:
        encoded = json.dumps(job)
        require(all(term not in encoded for term in ('secrets.', 'id-token', 'download-artifact', 'pypa/', 'NODE_AUTH_TOKEN', 'NPM_TOKEN', 'CARGO_REGISTRY_TOKEN')))
        require(job['runs-on'] == 'ubuntu-24.04')
        checkout, python, node, execute = job['steps'][:4]
        require(checkout['uses'] == 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5')
        require(checkout['with'] == {'ref':'${{ needs.validate-release-inputs.outputs.trusted_ref }}', 'fetch-depth':0, 'persist-credentials':False})
        require(python['uses'] == 'actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548' and python['with'] == {'python-version':'3.13.7', 'cache':''})
        require(node['uses'] == 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020' and node['with'] == {'node-version':'24.15.0', 'check-latest':False})
        require(execute['run'].endswith('/bin/bash --noprofile --norc -p -s -- ' + operation + '\n'))
        env = execute['env']
        require(not any(key.startswith('GITHUB_') for key in env))
        require(env['RELEASE_OPERATION'] == '${{ needs.validate-release-inputs.outputs.operation }}')
        require(env['RELEASE_WORKFLOW_DRY_RUN'] == '${{ inputs.dry_run }}')
        require('GITHUB_SHA' not in env and 'GITHUB_REF' not in env and 'DRY_RUN' not in env)
    upload, = acceptance['steps'][4:]
    require(upload['name'] == 'Upload Current Retained Acceptance Receipt' and upload['id'] == 'receipt')
    require(upload.get('if', '${{ success() }}') == '${{ success() }}')
    require(upload['uses'] == 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')
    require(upload['with'] == {'name':'exochain-027-retained-acceptance-receipt',
        'path':'${{ steps.acceptance.outputs.receipt_directory }}/custody-receipt.json\n${{ steps.acceptance.outputs.receipt_directory }}/acceptance-receipt.json\n',
        'if-no-files-found':'error', 'retention-days':30, 'compression-level':6, 'overwrite':False, 'include-hidden-files':False})
    outputs = {'artifact_id':'${{ steps.receipt.outputs.artifact-id }}', 'artifact_digest':'${{ steps.receipt.outputs.artifact-digest }}'}
    outputs.update({name:'${{ steps.acceptance.outputs.' + name + ' }}' for name in ['producer_job_id','receipt_members','receipt_context']})
    require(acceptance['outputs'] == outputs)
    require(len(writer['steps']) == 5)
    journal = writer['steps'][4]
    require(journal['if'] == '${{ always() }}')
    require(journal['uses'] == 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')
    require(journal['with'] == {'name':'exochain-027-retained-github-receipts',
        'path':'${{ runner.temp }}/exochain-retained-github.*/mutation-journal.jsonl\n${{ runner.temp }}/exochain-retained-github.*/evidence/release-result.json\n',
        'if-no-files-found':'warn','retention-days':30,'compression-level':6,'overwrite':False,'include-hidden-files':False})
    for name in outputs:
        require(writer['steps'][3]['env']['RELEASE_RECEIPT_' + name.upper()] == '${{ needs.retained-acceptance.outputs.' + name + ' }}')


class RecoveryWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / ".github/workflows/release.yml").read_text()
        cls.jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", cls.text.split("jobs:\n", 1)[1], re.M | re.S))

    def test_modes_are_mutually_exclusive_at_job_level(self):
        for name in NORMAL:
            with self.subTest(job=name):
                self.assertTrue(re.search(r"^    if:.*outputs.operation == 'release'", self.jobs[name], re.M), name)
        for name in RECOVERY:
            with self.subTest(job=name):
                self.assertTrue(name in self.jobs, name)
                self.assertTrue(re.search(r"^    if:.*outputs.operation == 'recover-0.2.7'", self.jobs[name], re.M), name)

    def test_retained_parsed_workflow_boundaries(self):
        retained_policy(parsed_workflow(self.text))

    def test_new_operation_reuses_retained_dag_and_dry_skips_writer(self):
        workflow = parsed_workflow(self.text)
        retained_policy(workflow)
        jobs = workflow['jobs']
        self.assertEqual([name for name in jobs if name.startswith('retained-')], RETAINED)
        self.assertEqual(jobs['retained-github']['needs'][-1], 'retained-acceptance')
        self.assertIn('&& !inputs.dry_run', jobs['retained-github']['if'])
        self.assertNotIn('dry_run', jobs['retained-acceptance']['if'])
        for name in NORMAL + RECOVERY:
            self.assertNotIn('recover-0.2.7-retained-404', jobs[name]['if'])

    def test_new_mode_preserves_permissions_direct_outputs_and_source_capture(self):
        workflow = parsed_workflow(self.text)
        retained_policy(workflow)
        producer, writer = (workflow['jobs'][name] for name in RETAINED)
        self.assertEqual(producer['permissions'], {'contents':'read','actions':'read','attestations':'read'})
        self.assertEqual(writer['permissions'], {'contents':'write','actions':'read'})
        self.assertEqual(writer['environment'], 'release')
        for name in ('artifact_id','artifact_digest','producer_job_id','receipt_members','receipt_context'):
            self.assertEqual(writer['steps'][3]['env']['RELEASE_RECEIPT_' + name.upper()],
                             '${{ needs.retained-acceptance.outputs.' + name + ' }}')
        self.assertIn('show "${GITHUB_SHA}:tools/run_release_recovery_027.sh"',
                      writer['steps'][3]['run'])

    def test_retained_yaml_ambiguity_is_rejected(self):
        for text in ('jobs: {}\njobs: {}', 'jobs: &jobs {}\nother: *jobs', 'on: {}', 'jobs: !!map {}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parsed_workflow(text)

    def test_real_cargo_guard_fixtures_preserve_resource_bounds_in_clean_environment(self):
        source=(ROOT/'tools/test_release_workflow_ref_binding.sh').read_text()
        generate=source.split('  cd "$cargo_boundary_crate"\n',1)[1].split('  git init -q',1)[0]
        control=source.split('  CARGO_CACHE_RUSTC_INFO=0 \\\n',1)[1].split('cargo publish --dry-run --no-verify --locked',1)[0]
        isolated=source.split('    PATH="$(/usr/bin/dirname "$real_cargo"):/usr/bin:/bin"',1)[1].split('    "$real_cargo" publish',1)[0]
        for name,block in [('generate',generate),('control',control),('env-i',isolated)]:
            for setting in ['CARGO_BUILD_JOBS=2','CARGO_INCREMENTAL=0','CARGO_PROFILE_DEV_DEBUG=0',
                            'CARGO_PROFILE_TEST_DEBUG=0','CARGO_PROFILE_RELEASE_DEBUG=0']:
                with self.subTest(command=name,setting=setting): self.assertIn(setting,block)

    def test_cargo_parity_fixture_constructed_environment_has_resource_bounds(self):
        tree=ast.parse((ROOT/'tools/test_publish_sealed_crate_cargo_parity.py').read_text())
        assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign)
                     and any(isinstance(t,ast.Name) and t.id=='environment' for t in n.targets)]
        self.assertEqual(len(assignments),1)
        value=assignments[0].value
        self.assertIsInstance(value,ast.Dict)
        constants={k.value:v.value for k,v in zip(value.keys,value.values)
                   if isinstance(k,ast.Constant) and isinstance(v,ast.Constant)}
        for key,expected in {'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0',
                             'CARGO_PROFILE_TEST_DEBUG':'0','CARGO_PROFILE_RELEASE_DEBUG':'0'}.items():
            with self.subTest(setting=key): self.assertEqual(constants.get(key),expected)

    def test_retained_policy_rejects_authority_dag_and_receipt_mutations(self):
        original = parsed_workflow(self.text)
        retained_policy(original)
        mutations = []
        for name in RETAINED:
            for prerequisite in original['jobs'][name]['needs']:
                mutations.append(lambda v,n=name,p=prerequisite:v['jobs'][n]['needs'].remove(p))
            for permission, access in [('id-token','write'),('packages','write'),('contents','write'),('actions','write')]:
                if original['jobs'][name]['permissions'].get(permission) != access:
                    mutations.append(lambda v,n=name,p=permission,a=access:v['jobs'][n]['permissions'].__setitem__(p,a))
            mutations.append(lambda v,n=name:v['jobs'][n].__setitem__('if', '${{ always() }}'))
            mutations.append(lambda v,n=name:v['jobs'][n]['steps'][3]['env'].__setitem__('RELEASE_WORKFLOW_DRY_RUN','false'))
            mutations.append(lambda v,n=name:v['jobs'][n]['steps'][3]['env'].__setitem__('NODE_AUTH_TOKEN','${{ secrets.NPM_TOKEN }}'))
            mutations.append(lambda v,n=name:v['jobs'][n]['steps'][3]['env'].__setitem__('GITHUB_RUN_ATTEMPT','1'))
        for name in ['artifact_id','artifact_digest','producer_job_id','receipt_members','receipt_context']:
            mutations.append(lambda v,n=name:v['jobs']['retained-acceptance']['outputs'].__setitem__(n,'previous-attempt'))
            mutations.append(lambda v,n=name:v['jobs']['retained-github']['steps'][3]['env'].__setitem__('RELEASE_RECEIPT_'+n.upper(),'name-lookup'))
        mutations += [
            lambda v:v['jobs']['retained-acceptance']['steps'][4].__setitem__('if','${{ always() }}'),
            lambda v:v['jobs']['retained-acceptance']['steps'][4]['with'].__setitem__('path','payload/'),
            lambda v:v['jobs']['retained-acceptance'].__setitem__('name','Other producer'),
            lambda v:v['jobs']['retained-github'].__setitem__('environment','unprotected'),
            lambda v:v['env'].__setitem__('NPM_TOKEN','${{ secrets.NPM_TOKEN }}'),
            lambda v:v['jobs']['recovery-sdk'].__setitem__('if',"${{ inputs.operation != 'release' }}"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(original); mutation(changed)
                with self.assertRaises(ValueError): retained_policy(changed)

    def test_actual_input_boundary(self):
        code = self.jobs["validate-release-inputs"].split("# BEGIN RELEASE OPERATION VALIDATION\n", 1)[1].split("# END RELEASE OPERATION VALIDATION", 1)[0]
        code = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in code.splitlines())
        cases = [
            ('recover-0.2.7-retained-404', '0.2.7', 'refs/tags/v0.2.7-recover.3', True, 'v0.2.7-recover.3'),
            ('recover-0.2.7-retained-404', '0.2.8', 'refs/tags/v0.2.7-recover.3', False, ''),
            ('recover-0.2.7-retained-404', '0.2.7', 'refs/tags/v0.2.7-recover.0', False, ''),
            ('recover-0.2.7-retained-404', '0.2.7', 'refs/heads/main', False, ''),
            ('recover-0.2.7-retained-404-extra', '0.2.7', 'refs/tags/v0.2.7-recover.3', False, ''),
            ('recover-0.2.7-retained', '0.2.7', 'refs/tags/v0.2.7-recover.3', True, 'v0.2.7-recover.3'),
            ('recover-0.2.7-retained', '0.2.8', 'refs/tags/v0.2.7-recover.3', False, ''),
            ('recover-0.2.7-retained', '0.2.7', 'refs/tags/v0.2.7-recover.0', False, ''),
            ('recover-0.2.7-retained', '0.2.7', 'refs/heads/main', False, ''),
            ("release", "0.2.7", "refs/heads/main", True, "v0.2.7"),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.1", True, "v0.2.7-recover.1"),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.25", True, "v0.2.7-recover.25"),
            ("recover-0.2.7", "0.2.8", "refs/tags/v0.2.7-recover.1", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/heads/v0.2.7-recover.1", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.0", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.01", False, ""),
            ("release", "0.2.7", "refs/tags/v0.2.7-recover.1", False, ""),
            ("bad\nrelease", "0.2.7", "refs/tags/v0.2.7-recover.1", False, ""),
        ]
        for operation, version, ref, success, tag in cases:
            with self.subTest(operation=operation, version=version, ref=ref), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-e", "-u", "-o", "pipefail", "-c", 'version="$RELEASE_VERSION_INPUT"\n' + code], env={"PATH":"/usr/bin:/bin", "RELEASE_VERSION_INPUT":version, "RELEASE_OPERATION_INPUT":operation, "GITHUB_REF":ref, "GITHUB_OUTPUT":str(output)}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertEqual(output.read_text(), f"tag={tag}\noperation={operation}\n")
                else:
                    self.assertFalse(output.exists(), "invalid dispatch wrote accepted outputs")

    def test_recovery_authority_and_dry_run_boundaries(self):
        imported = self.jobs["recovery-import"]
        self.assertIn("needs: [ci, approve, approve-second, verify-signed-tag, validate-release-inputs]", imported)
        for name in ("recovery-import", "recovery-wasm"):
            block = self.jobs[name]
            self.assertNotIn("id-token:", block)
            self.assertNotIn("secrets.", block)
            self.assertNotIn("contents: write", block)
        for name in ("recovery-llm", "recovery-sdk", "recovery-python", "recovery-github"):
            block = self.jobs[name]
            self.assertTrue(re.search(r"^    if:.*!inputs.dry_run", block, re.M), name)
            self.assertIn("    environment: release\n", block)
        self.assertIn("recovery-wasm", self.jobs["recovery-llm"].split("    steps:")[0])
        self.assertIn("recovery-llm", self.jobs["recovery-sdk"].split("    steps:")[0])
        self.assertIn("recovery-sdk", self.jobs["recovery-python"].split("    steps:")[0])
        for name in ("recovery-import", "recovery-wasm", "recovery-llm", "recovery-sdk", "recovery-python"):
            self.assertIn(name, self.jobs["recovery-github"].split("    steps:")[0])
        self.assertIn('if [ "$DRY_RUN" = "true" ] && [ "$RELEASE_OPERATION" = release ]; then', self.jobs["verify-signed-tag"])

    def test_npm_receipts_require_initialized_validated_output(self):
        for name in ("recovery-wasm", "recovery-llm", "recovery-sdk"):
            block = self.jobs[name]
            self.assertEqual(block.count("id: npm-publication"), 1)
            receipt = block.split("- name: Retain Bounded Public Recovery Receipts", 1)[1]
            self.assertIn("if: ${{ always() && steps.npm-publication.outputs.receipts_ready == 'true' }}", receipt)
            profile = name.removeprefix("recovery-")
            self.assertIn("${{ runner.temp }}/exochain-recovery-receipts/npm-" + profile + "/", receipt)

    def test_python_orchestration_uses_declared_hash_locked_test_environment(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", text.split("jobs:\n", 1)[1], re.M | re.S))
        command = "bash tools/test_recover_release_python_027.sh"
        owners = [name for name, body in jobs.items() if command in body]
        self.assertEqual(owners, ["python-sdk"])
        block = jobs["python-sdk"]
        self.assertLess(block.index("--require-hashes"), block.index(command))
        self.assertLess(block.index("tools/python-release-requirements.lock"), block.index(command))

    def test_hosted_token_contract_is_read_only_and_excluded_from_pr_execution(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", text.split("jobs:\n", 1)[1], re.M | re.S))
        command = "python3 -I -B tools/test_import_release_recovery_027.py --token-contract"
        owners = [name for name, body in jobs.items() if command in body]
        self.assertEqual(owners, ["hygiene"])
        block = jobs["hygiene"]
        self.assertIn("    permissions:\n      contents: read\n", block.split("    steps:", 1)[0])
        steps = re.split(r"^      - ", block.split("    steps:\n", 1)[1], flags=re.M)
        contract = next(step for step in steps if command in step)
        # Source guard: removing this restriction hands a real credential to
        # PR-controlled Python instead of running credential-free fixtures.
        self.assertIn("if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'\n", contract)
        self.assertIn("RELEASE_GITHUB_TOKEN: ${{ github.token }}", contract)
        self.assertNotIn("secrets.", contract)
        fixtures = next(step for step in steps if "name: Fixed recovery custody and workflow boundaries\n" in step)
        self.assertNotIn("RELEASE_GITHUB_TOKEN", fixtures)

    def test_exact_source_artifacts_and_direct_python_publisher(self):
        for name in RECOVERY:
            block = self.jobs[name]
            self.assertIn("ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}", block)
            self.assertIn("persist-credentials: false", block)
            self.assertIn("EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}", block)
            self.assertNotIn("GITHUB_SHA:", block, "must use the genuine runner dispatch identity")
            if name != "recovery-import":
                self.assertIn("artifact-ids: ${{ needs.recovery-import.outputs.artifact_id }}", block)
                self.assertIn("merge-multiple: true", block)
        python = self.jobs["recovery-python"]
        self.assertIn("pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b", python)
        self.assertIn("skip-existing: false", python)
        self.assertIn("attestations: true", python)
        self.assertIn("packages-dir: ${{ steps.python-preflight.outputs.packages_dir }}", python)
        self.assertIn("steps.python-preflight.outputs.publish_needed == 'true'", python)
        self.assertNotIn("--clobber", self.jobs["recovery-github"])

    def test_actual_launcher_commands_form_one_safe_pipeline(self):
        for name in RECOVERY + RETAINED:
            scripts = re.findall(r"^        run: \|\n((?:^          .*\n|^\n)+)", self.jobs[name], re.M)
            self.assertTrue(scripts, name)
            for script in scripts:
                lines = [line[10:] for line in script.splitlines()]
                # A literal pair of backslashes is not a shell continuation.
                # Parse the resulting logical command using shell tokenization,
                # then execute an instrumented pipeline with no Git/network I/O.
                self.assertTrue(all(not line.endswith("\\\\") for line in lines), name)
                logical = "\n".join(lines).replace("\\\n", "")
                command = logical.split("\n", 1)[1]
                import shlex
                tokens = shlex.split(command)
                self.assertEqual(tokens[:2], ["/usr/bin/env", "-i"])
                self.assertEqual(tokens.count("|"), 1)
                divider = tokens.index("|")
                self.assertEqual(tokens[divider + 1:divider + 7], ["/bin/bash", "--noprofile", "--norc", "-p", "-s", "--"])
                self.assertEqual(tokens[divider - 2:divider], ["show", "${GITHUB_SHA}:tools/run_release_recovery_027.sh"])
                self.assertEqual(len(tokens), divider + 8)
                with tempfile.TemporaryDirectory() as tmp:
                    probe = Path(tmp) / "git-probe"
                    probe.write_text('#!/bin/bash\n[ "$1" = --no-replace-objects ] && [ "$2" = -C ] && [ "$4" = show ] || exit 2\nprintf \'%s\\n\' \'printf "dispatch:%s\\n" "$1"\'\n')
                    probe.chmod(0o500)
                    executable = "\n".join(lines).replace("/usr/bin/git", shlex.quote(str(probe)))
                    environment = {"PATH":"/usr/bin:/bin", "GITHUB_SHA":"a" * 40, "GITHUB_WORKSPACE":tmp}
                    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-c", executable], env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "dispatch:" + tokens[-1] + "\n")
                    broken = executable.replace("\\\n", "\\\\\n", 1)
                    rejected = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-c", broken], env=environment, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0, "doubled continuation regression accepted")


if __name__ == "__main__":
    unittest.main()
