#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ $# -le 1 ]] || { printf 'usage: %s [original-wasm-tarball]\n' "$0" >&2; exit 2; }
python3 - "$repo_root" "$@" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(sys.argv[1])
PUBLISHER = ROOT / "tools/publish_release_npm_package.sh"
SOURCE = PUBLISHER.read_text()
PREFIX = SOURCE.split("\nfor required_name in ", 1)[0]
PRODUCT = "666c578f719d1e54fce95d6831a3af92ea80df93"
CONTROLLER = "1234567890abcdef1234567890abcdef12345678"
ORIGINAL_WASM = Path(sys.argv[2]).resolve(strict=True) if len(sys.argv) == 3 else None


def function(name):
    start = SOURCE.index("\n" + name + "() {\n")
    end = SOURCE.index("\n}\n", start) + 3
    return SOURCE[start:end] + "\n"


class RecoveryNpmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="exochain-recovery-npm-test.")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        self.events = self.path / "events"
        (self.path / "github-output").write_text("")
        self.env = dict(os.environ)
        for name in list(self.env):
            if name.startswith(("RELEASE_", "GITHUB_", "ACTIONS_", "NPM_", "NODE_")):
                del self.env[name]
        for name in ("CARGO_REGISTRY_TOKEN", "TWINE_PASSWORD", "PYPI_TOKEN", "PYPI_API_TOKEN"):
            self.env.pop(name, None)
        self.env.update({
            "RELEASE_OPERATION": "recover-0.2.7", "RELEASE_VERSION": "0.2.7",
            "RELEASE_TAG": "v0.2.7-recover.1", "GITHUB_REF": "refs/tags/v0.2.7-recover.1",
            "GITHUB_SHA": CONTROLLER, "EXPECTED_COMMIT_SHA": CONTROLLER,
            "RUNNER_TEMP": str(self.path), "RELEASE_RECOVERY_DIRECTORY": str(self.path / "transport"),
            "GNUPGHOME": str(self.path / "gnupg"), "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT": "A" * 40,
            "TEST_EVENTS": str(self.events),
            "GITHUB_OUTPUT": str(self.path / "github-output"),
        })

    def run_shell(self, body, *, env=None):
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", PREFIX + "\n" + body],
                              env=self.env if env is None else env, text=True, capture_output=True)

    def succeeds(self, body):
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def rejected(self, body, message):
        result = self.run_shell(body)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_context_derives_original_wasm_identity_without_credentials(self):
        output = self.succeeds("""
declare -F validate_npm_release_context >/dev/null || fail 'recovery context validation is missing'
profile=wasm
validate_npm_release_context
printf '%s\\n' "$acceptance_only" "$provenance_commit" "$provenance_ref"
""")
        self.assertEqual(output.splitlines(), ["true", PRODUCT, "refs/tags/v0.2.7"])

    def test_new_packages_use_controller_identity_and_require_actor_credential(self):
        for profile in ("llm", "sdk"):
            with self.subTest(profile=profile):
                self.rejected(f"profile={profile}; validate_npm_release_context", "NODE_AUTH_TOKEN is required")
                self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
                result = self.succeeds(f"profile={profile}; validate_npm_release_context; "
                                       "printf '%s\\n' \"$acceptance_only\" \"$provenance_commit\" \"$provenance_ref\"")
                self.assertEqual(result.splitlines(), ["false", CONTROLLER, "refs/tags/v0.2.7-recover.1"])
                del self.env["NODE_AUTH_TOKEN"]

    def test_recovery_rejects_wrong_mode_version_ref_tag_source_and_override(self):
        cases = [("RELEASE_OPERATION", "other"), ("RELEASE_VERSION", "0.2.8"),
                 ("GITHUB_REF", "refs/tags/v0.2.7"), ("GITHUB_REF", "refs/heads/main"),
                 ("GITHUB_REF", "refs/tags/v0.2.7-recover.0"),
                 ("RELEASE_TAG", "v0.2.7-recover.2"), ("GITHUB_SHA", PRODUCT),
                 ("EXPECTED_COMMIT_SHA", PRODUCT), ("RELEASE_EXPECTED_PROVENANCE_REF", "refs/tags/v0.2.7")]
        for name, value in cases:
            with self.subTest(name=name, value=value):
                old = self.env.get(name)
                self.env[name] = value
                self.rejected("profile=wasm; validate_npm_release_context", "npm release publication failed:")
                if old is None:
                    del self.env[name]
                else:
                    self.env[name] = old

    def test_normal_mode_rejects_recovery_context_and_keeps_dispatch_identity(self):
        self.env["RELEASE_OPERATION"] = "release"
        self.rejected("profile=wasm; validate_npm_release_context", "normal release")
        self.env.update(RELEASE_TAG="v0.2.7", GITHUB_REF="refs/tags/v0.2.7", NODE_AUTH_TOKEN="unit-test-only-token",
                        RELEASE_GITHUB_TOKEN="unit-test-only-read-token")
        self.rejected("profile=wasm; validate_npm_release_context", "normal release")
        del self.env["RELEASE_RECOVERY_DIRECTORY"]
        del self.env["RELEASE_OPERATION"]
        output = self.succeeds("profile=wasm; validate_npm_release_context; "
                              "printf '%s\\n' \"$acceptance_only\" \"$provenance_commit\" \"$provenance_ref\"")
        self.assertEqual(output.splitlines(), ["false", CONTROLLER, "refs/tags/v0.2.7"])

    def test_wasm_rejects_each_publishing_credential(self):
        for name in ("NODE_AUTH_TOKEN", "NPM_TOKEN", "CARGO_REGISTRY_TOKEN", "TWINE_PASSWORD",
                     "PYPI_TOKEN", "PYPI_API_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
            with self.subTest(name=name):
                self.env[name] = "unit-test-only-forbidden"
                self.rejected("profile=wasm; validate_npm_release_context", "acceptance-only")
                del self.env[name]

    def orchestration(self, profile, registry_status):
        # Only external authority/registry/mutation boundaries are replaced here.
        # This tests real controller sequencing, not cryptographic acceptance.
        self.case_number = getattr(self, "case_number", 0) + 1
        scratch = self.path / f"orchestration-{self.case_number}"
        scratch.mkdir()
        self.private = scratch / "private"
        self.private.mkdir()
        (self.private / "registry.json").write_text('{"public":"registry fixture"}\n')
        (self.private / "audit.json").write_text('{"public":"audit fixture"}\n')
        (self.private / "user.npmrc").write_text("unit-test-only-credential-must-not-survive")
        self.receipt_path = scratch / "exochain-recovery-receipts" / f"npm-{profile}"
        self.github_output = scratch / "github-output"
        self.github_output.write_text("")
        package = {"wasm": "@exochain/exochain-wasm", "sdk": "@exochain/sdk", "llm": "@exochain/llm-proxy"}[profile]
        return f"""
profile={profile}
validate_npm_release_context
RELEASE_NPM_TARBALL=/unit-test/exact-package.tgz
RELEASE_EXPECTED_TARBALL_SHA256={'b' * 64}
package_name={package}
python_path={json.dumps(str(Path(sys.executable).resolve()))}
RUNNER_TEMP={json.dumps(str(scratch))}
GITHUB_OUTPUT={json.dumps(str(self.github_output))}
publish_root={json.dumps(str(self.private))}
registry_response="$publish_root/registry.json"
audit_response="$publish_root/audit.json"
initialize_npm_recovery_receipts
trap 'finish_npm_publication "$?"' EXIT
record() {{ printf '%s\\n' "$*" >> "$TEST_EVENTS"; }}
verify_credentialed_npm_actor() {{ record actor; }}
verify_release_binding() {{ record binding; }}
verify_recovery_npm_files() {{ record custody; }}
verify_prepublication_npm_authority() {{ record authority; }}
registry_has_exact_tarball() {{ record registry; return {registry_status}; }}
verify_registry_acceptance() {{ record "acceptance:$provenance_commit:$provenance_ref"; }}
run_authenticated_npm() {{ record "authenticated:$*"; }}
wait_for_npm_registry_visibility() {{ record "visibility:$*"; }}
publish_or_accept_npm
"""

    def test_existing_wasm_never_calls_authenticated_or_upload_boundary(self):
        self.succeeds(self.orchestration("wasm", 0))
        self.assertEqual(self.events.read_text().splitlines(), ["custody", "registry",
                         f"acceptance:{PRODUCT}:refs/tags/v0.2.7", "custody", "binding"])
        result = json.loads((self.receipt_path / "result.json").read_text())
        self.assertIs(result["acceptance_verified"], True)
        self.assertIs(result["mutation_attempted"], False)
        self.assertEqual(result["provenance_commit"], PRODUCT)
        self.assertEqual(result["controller_commit"], CONTROLLER)
        self.assertFalse((self.receipt_path / "intent.json").exists())

    def test_missing_wasm_stops_without_actor_authority_upload_or_acceptance(self):
        self.rejected(self.orchestration("wasm", 1), "acceptance-only WASM version is absent")
        self.assertEqual(self.events.read_text().splitlines(), ["custody", "registry"])

    def test_non_absence_registry_failure_cannot_trigger_upload(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        self.rejected(self.orchestration("sdk", 2), "npm registry probe failed")
        self.assertEqual(self.events.read_text().splitlines(), ["actor", "custody", "registry"])

    def test_missing_new_package_has_one_authorized_upload_and_custody_rechecks(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        self.succeeds(self.orchestration("sdk", 1))
        self.assertEqual(self.events.read_text().splitlines(), ["actor", "custody", "registry", "binding",
            "authority", "custody", "authenticated:publish /unit-test/exact-package.tgz --access public --provenance --ignore-scripts --registry=https://registry.npmjs.org",
            "custody", "visibility:registry_has_exact_tarball /bin/sleep",
            f"acceptance:{CONTROLLER}:refs/tags/v0.2.7-recover.1", "custody", "binding"])

    def test_failed_actor_binding_authority_or_upload_stops_further_operations(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        cases = [("verify_credentialed_npm_actor", "actor", ["actor"]),
                 ("verify_release_binding", "binding", ["actor", "custody", "registry", "binding"]),
                 ("verify_prepublication_npm_authority", "authority", ["actor", "custody", "registry", "binding", "authority"]),
                 ("run_authenticated_npm", "upload-failed", ["actor", "custody", "registry", "binding", "authority", "custody", "upload-failed"])]
        for name, label, expected in cases:
            with self.subTest(boundary=name):
                self.events.unlink(missing_ok=True)
                body = self.orchestration("sdk", 1).rsplit("publish_or_accept_npm", 1)[0]
                result = self.run_shell(body + f"\n{name}() {{ record {label}; return 9; }}\npublish_or_accept_npm")
                self.assertEqual(result.returncode, 9)
                self.assertEqual(self.events.read_text().splitlines(), expected)

    def test_unknown_upload_keeps_only_bounded_public_receipts_and_never_retries(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        body = self.orchestration("sdk", 1).rsplit("publish_or_accept_npm", 1)[0]
        body += """
run_authenticated_npm() {
  [ -s "$recovery_receipt_root/intent.json" ] || return 99
  record 'upload-attempt'
  return 9
}
publish_or_accept_npm
"""
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(self.events.read_text().splitlines().count("upload-attempt"), 1)
        self.assertFalse(self.private.exists())
        self.assertEqual({item.name for item in self.receipt_path.iterdir()},
                         {"intent.json", "outcome.json", "result.json", "registry.json", "audit.json"})
        intent = json.loads((self.receipt_path / "intent.json").read_text())
        outcome = json.loads((self.receipt_path / "outcome.json").read_text())
        final = json.loads((self.receipt_path / "result.json").read_text())
        self.assertEqual(intent["phase"], "upload-intent")
        self.assertEqual(intent["mutation_outcome"], "unknown")
        self.assertEqual(outcome["upload_exit_code"], 9)
        self.assertEqual(outcome["mutation_outcome"], "uncertain")
        self.assertEqual(final["exit_code"], 9)
        self.assertIs(final["acceptance_verified"], False)
        self.assertIs(final["mutation_attempted"], True)
        for receipt in (intent, outcome, final):
            self.assertEqual(receipt["controller_commit"], CONTROLLER)
            self.assertEqual(receipt["controller_ref"], "refs/tags/v0.2.7-recover.1")
            self.assertEqual(receipt["provenance_commit"], CONTROLLER)
            self.assertEqual(receipt["tarball_sha256"], "b" * 64)
        for path in self.receipt_path.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            self.assertNotIn(b"unit-test-only-credential", path.read_bytes())
        self.assertEqual(self.github_output.read_text(), "receipts_ready=true\n")

    def test_existing_receipt_directory_fails_before_any_upload(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        body = self.orchestration("sdk", 1)
        self.receipt_path.mkdir(parents=True)
        self.receipt_path.parent.chmod(0o700)
        self.rejected(body, "recovery receipt directory cannot be initialized")
        self.assertFalse(self.events.exists())
        self.assertEqual(self.github_output.read_text(), "")

    def test_linked_receipt_parent_fails_without_touching_target(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        body = self.orchestration("sdk", 1)
        target = self.path / "unrelated"
        target.mkdir(mode=0o700)
        self.receipt_path.parent.symlink_to(target, target_is_directory=True)
        self.rejected(body, "recovery receipt directory cannot be initialized")
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse(self.events.exists())

    def test_failure_to_persist_intent_prevents_upload(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        body = self.orchestration("sdk", 1).rsplit("publish_or_accept_npm", 1)[0]
        body += '\nprintf existing > "$recovery_receipt_root/intent.json"\npublish_or_accept_npm\n'
        result = self.run_shell(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("authenticated:publish", self.events.read_text())
        self.assertFalse(self.private.exists())
        self.assertEqual((self.receipt_path / "intent.json").read_text(), "existing")
        final = json.loads((self.receipt_path / "result.json").read_text())
        self.assertIs(final["acceptance_verified"], False)
        self.assertIs(final["mutation_attempted"], False)
        self.assertEqual(self.github_output.read_text(), "")

    def test_linked_github_output_is_rejected_before_any_upload(self):
        self.env["NODE_AUTH_TOKEN"] = "unit-test-only-token"
        body = self.orchestration("sdk", 1)
        target = self.path / "unrelated-output"
        target.write_text("untouched")
        self.github_output.unlink()
        self.github_output.symlink_to(target)
        self.rejected(body, "recovery receipt directory cannot be initialized")
        self.assertEqual(target.read_text(), "untouched")
        self.assertFalse(self.events.exists())

    def test_receipt_copy_failure_is_not_reported_as_success(self):
        for corrupt in ("oversized", "symlink", "hardlink", "malformed", "duplicate", "nonfinite"):
            with self.subTest(corrupt=corrupt):
                self.events.unlink(missing_ok=True)
                body = self.orchestration("wasm", 0)
                audit = self.private / "audit.json"
                if corrupt == "oversized":
                    with audit.open("wb") as stream:
                        stream.truncate(8 * 1024 * 1024 + 1)
                elif corrupt == "symlink":
                    audit.unlink()
                    audit.symlink_to(self.private / "user.npmrc")
                elif corrupt == "hardlink":
                    os.link(audit, self.private / "audit-link.json")
                elif corrupt == "malformed":
                    audit.write_text("{")
                elif corrupt == "duplicate":
                    audit.write_text('{"invalid":[],"invalid":["conflict"]}')
                else:
                    audit.write_text('{"invalid":NaN}')
                result = self.run_shell(body)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.private.exists())
                self.assertFalse((self.receipt_path / "audit.json").exists())
                receipt = json.loads((self.receipt_path / "result.json").read_text())
                self.assertNotEqual(receipt["exit_code"], 0)
                self.assertEqual(self.github_output.read_text(), "receipts_ready=true\n")

    def test_extra_receipt_file_cannot_enable_artifact_upload(self):
        body = self.orchestration("wasm", 0).rsplit("publish_or_accept_npm", 1)[0]
        body += '\nprintf unit-test-only > "$recovery_receipt_root/user.npmrc"\npublish_or_accept_npm\n'
        result = self.run_shell(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.github_output.read_text(), "")

    def test_normal_cleanup_does_not_create_recovery_receipts(self):
        private = self.path / "normal-private"
        private.mkdir()
        self.succeeds(f"""
RELEASE_OPERATION=release
RUNNER_TEMP={json.dumps(str(self.path))}
publish_root={json.dumps(str(private))}
initialize_npm_recovery_receipts
trap 'finish_npm_publication "$?"' EXIT
""")
        self.assertFalse(private.exists())
        self.assertFalse((self.path / "exochain-recovery-receipts").exists())

    def test_public_subprocess_has_empty_distinct_configs_and_no_inherited_credentials(self):
        public = self.path / "public"
        public.mkdir(mode=0o700)
        audit = self.path / "audit"
        audit.mkdir(mode=0o700)
        for name in ("user.npmrc", "global.npmrc"):
            (public / name).write_text("")
            (public / name).chmod(0o600)
        probe = self.path / "npm-environment-probe.cjs"
        probe.write_text("process.stdout.write(JSON.stringify({env:process.env,args:process.argv.slice(2),cwd:process.cwd()}))")
        self.env.update({name: "unit-test-only-forbidden" for name in (
            "NODE_AUTH_TOKEN", "NPM_TOKEN", "GITHUB_TOKEN", "RELEASE_GITHUB_TOKEN", "GITHUB_SHA",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "NODE_OPTIONS", "NPM_CONFIG_PROVENANCE")})
        # NODE_OPTIONS is scrubbed by the wrapper, not by this test's launch.
        node = Path(shutil.which("node")).resolve()
        body = f"""
public_home_root={json.dumps(str(public))}
audit_root={json.dumps(str(audit))}
public_user_config="$public_home_root/user.npmrc"
public_global_config="$public_home_root/global.npmrc"
node_path={json.dumps(str(node))}
npm_cli_path={json.dumps(str(probe))}
TRUSTED_RELEASE_PATH=/usr/bin:/bin
run_public_npm audit signatures --json --include-attestations
"""
        value = json.loads(self.succeeds(body))
        self.assertEqual(value["args"], ["audit", "signatures", "--json", "--include-attestations"])
        self.assertEqual(value["cwd"], str(audit))
        env = value["env"]
        # macOS libc may inject this noncredential locale field after execve.
        if sys.platform == "darwin":
            env.pop("__CF_USER_TEXT_ENCODING", None)
        self.assertEqual(set(env), {"HOME", "NPM_CONFIG_CACHE", "NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_USERCONFIG",
                                  "NPM_CONFIG_IGNORE_SCRIPTS", "NPM_CONFIG_REGISTRY", "PATH"})
        self.assertEqual(env["NPM_CONFIG_IGNORE_SCRIPTS"], "true")
        self.assertEqual(env["NPM_CONFIG_REGISTRY"], "https://registry.npmjs.org/")
        self.assertNotEqual(env["NPM_CONFIG_GLOBALCONFIG"], env["NPM_CONFIG_USERCONFIG"])
        for field in ("NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_USERCONFIG"):
            self.assertEqual(Path(env[field]).read_bytes(), b"")
        owner = json.loads(self.succeeds(body.replace("run_public_npm audit signatures --json --include-attestations",
                                                    "run_public_npm owner ls @exochain/sdk")))
        self.assertEqual(owner["cwd"], str(public))
        self.rejected(body.replace("run_public_npm audit signatures --json --include-attestations",
                                   "run_public_npm publish /unit-test/package.tgz"), "public npm permits only")

    def test_recovery_rebind_preserves_controller_and_signer_but_strips_publish_credentials(self):
        probe = self.path / "identity-boundary.sh"
        probe.write_text('/usr/bin/env')
        self.env.update(NODE_AUTH_TOKEN="unit-test-only-token", NPM_TOKEN="unit-test-only-token",
                        ACTIONS_ID_TOKEN_REQUEST_TOKEN="unit-test-only-oidc", ACTIONS_ID_TOKEN_REQUEST_URL="https://unit.invalid",
                        RELEASE_GITHUB_TOKEN="unit-test-only-read-token", GITHUB_WORKSPACE=str(self.path / "workspace"),
                        GITHUB_REPOSITORY="exochain/exochain", GITHUB_SERVER_URL="https://github.com",
                        EXPECTED_TAG_COMMIT_SHA=CONTROLLER, EXPECTED_TAG_OBJECT_SHA="a" * 40,
                        TRUSTED_RELEASE_REF=CONTROLLER, RELEASE_TRUSTED_PYTHON_VERSION="3.13.7")
        body = function("verify_release_binding") + f"""
profile=sdk
validate_npm_release_context
python_path={json.dumps(str(Path(sys.executable).resolve()))}
python_root={json.dumps(str(Path(sys.executable).resolve().parent))}
recovery_binding_verifier={json.dumps(str(probe))}
verify_release_binding
"""
        env = dict(line.split("=", 1) for line in self.succeeds(body).splitlines())
        self.assertEqual(env["GITHUB_SHA"], CONTROLLER)
        self.assertEqual(env["GITHUB_REF"], "refs/tags/v0.2.7-recover.1")
        for name in ("RUNNER_TEMP", "GNUPGHOME", "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT", "RELEASE_GITHUB_TOKEN"):
            self.assertEqual(env[name], self.env[name])
        self.assertEqual(env["RELEASE_TRUSTED_PYTHON_VERSION"], "3.13.7")
        for name in ("NODE_AUTH_TOKEN", "NPM_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
            self.assertNotIn(name, env)

    def test_exact_owner_readback_is_public_and_rejects_additional_owners(self):
        base = function("verify_exact_npm_owners") + """
package_name=@exochain/exochain-wasm
expected_maintainer_name=bob-stewart
expected_maintainer_email=stewart@exochain.com
run_authenticated_npm() { fail 'owner readback used credentials'; }
run_public_npm() {
  [ "$*" = 'owner ls @exochain/exochain-wasm --registry=https://registry.npmjs.org' ] || fail 'wrong owner command'
  printf '%s\\n' "$TEST_OWNERS"
}
verify_exact_npm_owners
"""
        self.env["TEST_OWNERS"] = "bob-stewart <stewart@exochain.com>"
        self.succeeds(base)
        self.env["TEST_OWNERS"] += "\nattacker <attacker@example.invalid>"
        self.rejected(base, "owners differ from the exact canonical maintainer policy")

    def custody(self):
        directory = self.path / "transport"
        lane = directory / "npm-wasm"
        lane.mkdir(parents=True)
        tarball = lane / "exochain-exochain-wasm-0.2.7.tgz"
        tarball.write_bytes(b"not the original release bytes")
        manifest = self.path / "manifest.json"
        shutil.copyfile(ROOT / "governance/releases/v0.2.7/RECOVERY-MANIFEST.json", manifest)
        self.env.update(RELEASE_NPM_TARBALL=str(tarball), RELEASE_EXPECTED_TARBALL_SHA256=
                        "a9660cbf0241e8adde6be92cd7a13beea00c0fe258ea6c79ea527750f182d023")
        body = f"""
profile=wasm
validate_npm_release_context
python_path={json.dumps(str(Path(sys.executable).resolve()))}
recovery_manifest={json.dumps(str(manifest))}
recovery_verifier={json.dumps(str(ROOT / 'tools/verify_release_recovery_027.py'))}
verify_recovery_npm_files
"""
        return body, tarball, manifest

    def test_custody_rejects_wrong_digest_path_and_modified_manifest(self):
        body, tarball, manifest = self.custody()
        self.rejected(body, "recovery lane bytes do not match")
        self.env["RELEASE_EXPECTED_TARBALL_SHA256"] = "0" * 64
        self.rejected(body, "recovery tarball selection differs")
        self.env["RELEASE_EXPECTED_TARBALL_SHA256"] = "a9660cbf0241e8adde6be92cd7a13beea00c0fe258ea6c79ea527750f182d023"
        self.env["RELEASE_NPM_TARBALL"] = str(tarball.parent / "different.tgz")
        self.rejected(body, "recovery tarball selection differs")
        self.env["RELEASE_NPM_TARBALL"] = str(tarball)
        value = json.loads(manifest.read_text())
        value["product"]["commit"] = CONTROLLER
        manifest.write_text(json.dumps(value))
        self.rejected(body, "recovery manifest is not the fixed reviewed manifest")

    def test_custody_rejects_directory_outside_runner_temp_and_symlink_alias(self):
        body, tarball, _ = self.custody()
        self.env["RUNNER_TEMP"] = str(self.path / "other")
        (self.path / "other").mkdir()
        self.rejected(body, "recovery tarball selection differs")
        self.env["RUNNER_TEMP"] = str(self.path)
        alias = self.path / "alias"
        alias.symlink_to(tarball.parent.parent, target_is_directory=True)
        self.env["RELEASE_RECOVERY_DIRECTORY"] = str(alias)
        self.rejected(body, "recovery tarball selection differs")

    def test_capture_uses_actual_commit_not_mutable_workspace(self):
        source = self.path / "source"
        (source / "tools").mkdir(parents=True)
        (source / "governance/releases/v0.2.7").mkdir(parents=True)
        files = ["tools/verify_release_recovery_027.py", "tools/verify_release_recovery_027.sh",
                 "governance/releases/v0.2.7/RECOVERY-MANIFEST.json"]
        for name in files:
            shutil.copyfile(ROOT / name, source / name)
        subprocess.run(["git", "init", "-q", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "--", *files], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Recovery Unit Test",
                        "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"],
                       check=True, capture_output=True)
        sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        capture = self.path / "capture"
        capture.mkdir()
        (source / files[0]).write_text("invalid mutable helper")
        self.env.update(GITHUB_SHA=sha, EXPECTED_COMMIT_SHA=sha, GITHUB_WORKSPACE=str(source))
        self.succeeds(f"profile=wasm; validate_npm_release_context; publish_root={json.dumps(str(capture))}; "
                      "capture_npm_recovery_context")
        for name in files:
            target = capture / Path(name).name
            self.assertEqual(target.read_bytes(), (ROOT / name).read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o400)


if ORIGINAL_WASM is not None:
    # Optional real-artifact integration is explicit; ordinary unit tests never
    # manufacture a payload or change the fixed manifest to obtain a pass.
    def original_wasm_custody(self):
        body, tarball, _ = self.custody()
        shutil.copyfile(ORIGINAL_WASM, tarball)
        self.succeeds(body)
        extra = tarball.parent / "extra.txt"
        extra.write_text("unlisted")
        self.rejected(body, "recovery lane bytes do not match")
        extra.unlink()
        tarball.write_bytes(tarball.read_bytes() + b"changed")
        self.rejected(body, "recovery lane bytes do not match")
    RecoveryNpmTests.test_original_wasm_and_later_custody_mutation = original_wasm_custody


unittest.main(argv=[sys.argv[0]], verbosity=2)
PY
