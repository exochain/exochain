#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only import regression tests; mocked transport is not crypto evidence."""
from __future__ import annotations

import copy
import argparse
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/import_release_recovery_027.sh"
MANIFEST = ROOT / "governance/releases/v0.2.7/RECOVERY-MANIFEST.json"


def module_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def importer_module():
    source = SCRIPT.read_text().split("# BEGIN RECOVERY_IMPORT_PYTHON\n", 1)[1].split("# END RECOVERY_IMPORT_PYTHON", 1)[0]
    result = types.ModuleType("import_recovery027_test")
    exec(compile(source, str(SCRIPT), "exec"), result.__dict__)
    return result


class ImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.importer = None
        if SCRIPT.is_file():
            cls.importer = importer_module()
        cls.custody = module_file("import_test_custody", ROOT / "tools/verify_release_recovery_027.py")
        cls.fixture_class = module_file("import_test_fixtures", ROOT / "tools/test_release_recovery_027.py").RecoveryTests

    def setUp(self):
        self.assertIsNotNone(self.importer, "the fixed import helper has not been implemented")
        self.i = self.importer
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest = self.custody.load_manifest(MANIFEST)
        fixture = self.fixture_class()
        fixture.manifest = self.manifest
        self.run, self.jobs, metadata = fixture.fixtures()
        self.metadata = {a["id"]: a for a in metadata}

    def reject(self, function, *args):
        with self.assertRaises((self.i.ImportFailure, self.custody.RecoveryError)):
            function(*args)

    def test_endpoint_allowlist_is_fixed_to_attempt_one_and_reviewed_ids(self):
        urls = self.i.fixed_endpoints(self.manifest)
        self.assertIn("https://api.github.com/repos/exochain/exochain/actions/runs/35257955565/attempts/1", urls["run"])
        self.assertEqual(len(urls["metadata"]), 9)
        self.assertEqual(len(urls["archives"]), 7)
        self.assertEqual(len(urls["rust"]), 32)
        transport = self.i.Transport(self.root, "unit_test_readonly_token", self.manifest)
        for url in ["https://attacker.invalid/", urls["run"].replace("attempts/1", "attempts/2"),
                    urls["run"].replace("exochain/exochain", "attacker/exochain"),
                    "https://api.github.com/repos/exochain/exochain/actions/artifacts/1",
                    "https://crates.io/api/v1/crates/exochain-core/0.2.8"]:
            self.reject(transport.get, url, self.root / "rejected", 1024)
        self.assertFalse((self.root / "rejected").exists())

    def test_curl_github_auth_is_stdin_only_and_public_reads_have_no_credentials(self):
        transport = self.i.Transport(self.root, "unit_test_readonly_token", self.manifest)
        calls = []

        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            Path(argv[argv.index("--output") + 1]).write_bytes(b"{}")
            Path(argv[argv.index("--dump-header") + 1]).write_text("HTTP/2 200\r\n\r\n")
            return subprocess.CompletedProcess(argv, 0, b"200", b"")

        with patch.object(self.i.subprocess, "run", side_effect=process):
            transport.get(self.i.fixed_endpoints(self.manifest)["run"], self.root / "run.json", 1024)
            transport.get(self.i.fixed_endpoints(self.manifest)["rust"][0][1], self.root / "crate.json", 1024)
        self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[0], "/usr/bin/curl")
            self.assertEqual(argv[argv.index("--request") + 1], "GET")
            self.assertNotIn("--location", argv)
            self.assertNotIn("unit_test_readonly_token", " ".join(argv))
            self.assertNotIn("RELEASE_GITHUB_TOKEN", kwargs["env"])
            self.assertNotIn("GH_TOKEN", kwargs["env"])
        self.assertIn(b"Authorization: Bearer unit_test_readonly_token", calls[0][1]["input"])
        self.assertNotIn(b"Authorization", calls[1][1]["input"])

    def test_artifact_redirect_is_separate_unauthenticated_and_host_checked(self):
        transport = self.i.Transport(self.root, "unit_test_readonly_token", self.manifest)
        artifact = self.manifest["artifacts"][0]
        storage = "https://productionresultssa19.blob.core.windows.net/actions-results/a?sig=opaque"
        calls = []

        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            Path(argv[argv.index("--output") + 1]).write_bytes(b"zip")
            headers = "HTTP/2 200\r\n\r\n" if len(calls) == 2 else "HTTP/2 302\r\nLocation: " + storage + "\r\n\r\n"
            Path(argv[argv.index("--dump-header") + 1]).write_text(headers)
            return subprocess.CompletedProcess(argv, 0, b"200" if len(calls) == 2 else b"302", b"")

        with patch.object(self.i.subprocess, "run", side_effect=process):
            transport.archive(artifact, self.root / "result.zip")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0][-1], storage)
        self.assertNotIn(b"Authorization", calls[1][1]["input"])
        for bad in ["http://productionresultssa19.blob.core.windows.net/a", "https://blob.core.windows.net.attacker.invalid/a",
                    "https://user@productionresultssa19.blob.core.windows.net/a", "https://productionresultssa19.blob.core.windows.net:444/a",
                    "https://attacker.invalid/a", storage + "\nHeader: injected"]:
            self.reject(self.i.validate_storage_url, bad)

    def transport_fixture(self, jobs=None, run=None, metadata=None):
        endpoints = self.i.fixed_endpoints(self.manifest)
        data = {endpoints["run"]: self.run if run is None else run,
                endpoints["jobs"][0]: self.jobs if jobs is None else jobs}
        source = self.metadata if metadata is None else metadata
        data.update({url: source[ident] for ident, url in endpoints["metadata"]})
        calls = []

        def get(url, destination, limit):
            calls.append(url)
            if url not in data:
                raise AssertionError("unexpected endpoint: " + url)
            destination.write_text(json.dumps(data[url]))
        return types.SimpleNamespace(get=get), calls

    def test_origin_fetch_uses_terminal_attempt_page_and_exact_nine_metadata(self):
        transport, calls = self.transport_fixture()
        result = self.i.fetch_origin(self.manifest, self.custody, transport, self.root)
        self.assertEqual(result["run_attempt"], 1)
        self.assertEqual(len(calls), 11)
        self.assertEqual(sum("/jobs?per_page=100&page=1" in url for url in calls), 1)
        self.assertEqual(len(list((self.root / "artifact-metadata").glob("*.json"))), 9)

    def test_origin_rejects_truncated_pagination_second_attempt_and_wrong_producer(self):
        variants = []
        truncated = copy.deepcopy(self.jobs); truncated["jobs"].pop(); variants.append((None, truncated))
        later = copy.deepcopy(self.run); later["run_attempt"] = 2; variants.append((later, None))
        wrong = copy.deepcopy(self.jobs)
        next(j for j in wrong["jobs"] if j["id"] == 105363096810)["id"] = 9999999
        variants.append((None, wrong))
        failed = copy.deepcopy(self.jobs)
        next(j for j in failed["jobs"] if j["id"] == 105363096810)["conclusion"] = "failure"
        variants.append((None, failed))
        for index, (run, jobs) in enumerate(variants):
            directory = self.root / str(index); directory.mkdir()
            transport, calls = self.transport_fixture(jobs=jobs, run=run)
            self.reject(self.i.fetch_origin, self.manifest, self.custody, transport, directory)
            self.assertFalse(any(url.endswith("/zip") for url in calls))

    def test_rust_reads_exact_thirty_two_and_rejects_yanked_or_wrong_hash(self):
        for bad in [None, "yanked", "checksum"]:
            directory = self.root / str(bad); directory.mkdir()
            calls = []
            def get(url, destination, limit):
                calls.append(url)
                crate = next(c for c in self.manifest["rust_crates"] if "/" + c["name"] + "/" in url)
                record = {"version": {"id": 123, "crate": crate["name"], "num": "0.2.7", "yanked": False, "checksum": crate["sha256"]}}
                if bad == "yanked": record["version"]["yanked"] = True
                if bad == "checksum": record["version"]["checksum"] = "a" * 64
                destination.write_text(json.dumps(record))
            transport = types.SimpleNamespace(get=get)
            if bad:
                self.reject(self.i.fetch_rust, self.manifest, self.custody, transport, directory)
            else:
                self.assertEqual(self.i.fetch_rust(self.manifest, self.custody, transport, directory)["crates_verified"], 32)
            self.assertEqual(len(calls), 32)
            self.assertTrue(all(url.startswith("https://crates.io/api/v1/crates/") and url.endswith("/0.2.7") for url in calls))

    def attestation(self):
        artifact = next(a for a in self.manifest["artifacts"] if a["lane"] == "native-x86_64")
        invocation = self.manifest["origin"]["native_attestation_invocation"]
        sha = self.manifest["product"]["commit"]
        certificate = {"issuer":"https://token.actions.githubusercontent.com",
                       "sourceRepositoryURI":"https://github.com/exochain/exochain",
                       "sourceRepositoryDigest":sha,"sourceRepositoryRef":"refs/tags/v0.2.7",
                       "sourceRepositoryIdentifier":"1116455646","sourceRepositoryOwnerIdentifier":"129763194",
                       "buildSignerURI":"https://github.com/exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.7",
                       "buildSignerDigest":sha,"runnerEnvironment":"github-hosted",
                       "buildTrigger":"workflow_dispatch","runInvocationURI":invocation}
        proof = [{"verificationResult":{"mediaType":"application/vnd.dev.sigstore.verificationresult+json;version=0.1",
                 "signature":{"certificate":certificate},"verifiedTimestamps":[{"type":"Tlog","timestamp":"2026-09-17T23:00:00Z"}],
                 "statement":{"_type":"https://in-toto.io/Statement/v1", "predicateType":"https://slsa.dev/provenance/v1",
                 "subject":sorted([{"name":a["files"][0]["path"],"digest":{"sha256":a["files"][0]["sha256"]}}
                                   for a in self.manifest["artifacts"] if a["lane"].startswith("native-")], key=lambda s:s["name"]),
                 "predicate":{"runDetails":{"metadata":{"invocationId":invocation}}}}}}]
        return artifact, proof

    def test_verified_attestation_data_requires_original_certificate_invocation(self):
        artifact, proof = self.attestation()
        self.i.check_attestation(self.manifest, artifact, proof)
        for field, value in [("runInvocationURI", self.manifest["origin"]["native_attestation_invocation"].replace("attempts/1", "attempts/2")),
                             ("sourceRepositoryDigest", "a" * 40), ("runnerEnvironment", "self-hosted"),
                             ("sourceRepositoryURI", "https://github.com/attacker/exochain")]:
            changed = copy.deepcopy(proof)
            changed[0]["verificationResult"]["signature"]["certificate"][field] = value
            self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        changed = copy.deepcopy(proof); changed[0]["verificationResult"]["verifiedTimestamps"] = []
        self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        changed = copy.deepcopy(proof); changed[0]["verificationResult"]["statement"]["subject"].pop()
        self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        self.reject(self.i.check_attestation, self.manifest, artifact, [{"bundle":proof}])

    def test_attestation_process_must_succeed_before_its_output_is_accepted(self):
        artifact, proof = self.attestation()
        calls = []
        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 1, json.dumps(proof).encode(), b"fixture signature rejection")
        with patch.object(self.i.subprocess, "run", side_effect=process):
            self.reject(self.i.verify_attestation, self.manifest, artifact, self.root / "native.tar.gz", self.root,
                        "unit_test_readonly_token", self.custody)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:3], ["/usr/bin/gh", "attestation", "verify"])
        self.assertIn("--deny-self-hosted-runners", argv)
        self.assertIn("--source-digest", argv)
        self.assertIn("--signer-digest", argv)
        self.assertIn("--signer-workflow", argv)
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "unit_test_readonly_token")

    def test_final_directories_reject_reuse_links_and_outside_runner_temp(self):
        expected = self.root / "exochain-recovery-artifacts"
        self.i.check_destinations(self.root, expected)
        for bad in [self.root / "other", self.root.parent / "exochain-recovery-artifacts", self.root / "x/../exochain-recovery-artifacts"]:
            self.reject(self.i.check_destinations, self.root, bad)
        expected.symlink_to(self.root / "absent")
        self.reject(self.i.check_destinations, self.root, expected)
        expected.unlink(); expected.mkdir()
        self.reject(self.i.check_destinations, self.root, expected)

    def test_shell_rejects_publishing_authority_before_git_or_provider_reads(self):
        for credential in ["NPM_TOKEN", "NODE_AUTH_TOKEN", "CARGO_REGISTRY_TOKEN", "TWINE_PASSWORD", "PYPI_TOKEN",
                           "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"]:
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(SCRIPT)],
                                    env={credential:"unit-test-forbidden"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("publication credentials and OIDC", result.stderr)

    def test_import_rejects_wrong_producer_or_zip_without_exposing_outputs(self):
        for fault in ("producer", "zip"):
            runner = self.root / fault; runner.mkdir()
            capture = runner / "captured"; capture.mkdir()
            shutil.copyfile(ROOT / "tools/verify_release_recovery_027.py", capture / "verify_release_recovery_027.py")
            shutil.copyfile(MANIFEST, capture / "RECOVERY-MANIFEST.json")
            (capture / "identity-before.json").write_text(json.dumps({"controller_sha":"a" * 40, "controller_ref":"refs/tags/v0.2.7-recover.1"}))
            output = runner / "github-output"; output.touch()
            jobs = copy.deepcopy(self.jobs)
            if fault == "producer":
                next(j for j in jobs["jobs"] if j["id"] == 105363096810)["conclusion"] = "failure"
            transport, reads = self.transport_fixture(jobs=jobs)
            archives = []
            def archive(artifact, destination):
                archives.append(artifact["id"])
                destination.write_bytes(b"not the digest-pinned original ZIP")
            transport.archive = archive
            environment = {"RUNNER_TEMP":str(runner), "RELEASE_RECOVERY_DIRECTORY":str(runner / "exochain-recovery-artifacts"),
                           "RELEASE_GITHUB_TOKEN":"unit_test_readonly_token", "RELEASE_PYTHON":sys.executable,
                           "RELEASE_NODE":sys.executable, "GITHUB_OUTPUT":str(output)}
            commands = []
            actual_run = subprocess.run
            def recorded_run(argv, **kwargs):
                commands.append(argv)
                return actual_run(argv, **kwargs)
            with patch.dict(self.i.os.environ, environment, clear=True), patch.object(self.i.sys, "argv", ["importer", str(capture)]), \
                 patch.object(self.i, "Transport", return_value=transport), \
                 patch.object(self.i.shutil, "disk_usage", return_value=types.SimpleNamespace(free=8 * 1024**3)), \
                 patch.object(self.i.subprocess, "run", side_effect=recorded_run):
                with self.assertRaises(ValueError):
                    self.i.main()
            self.assertFalse((runner / "exochain-recovery-artifacts").exists())
            self.assertFalse((runner / "exochain-recovery-evidence").exists())
            self.assertEqual(output.read_bytes(), b"")
            self.assertEqual(archives, [] if fault == "producer" else [a["id"] for a in self.manifest["artifacts"]])
            self.assertEqual(len(reads), 11)
            for argv in commands:
                self.assertEqual(Path(argv[3]).name, "verify_release_recovery_027.py")
                self.assertIn(argv[4], ("origin", "artifacts"))

    def test_transport_rejects_status_duplicate_redirect_and_oversize(self):
        for status, headers, body in [(b"404", "HTTP/2 404\r\n\r\n", b"{}"),
                                      (b"302", "HTTP/2 302\r\nLocation: https://a.blob.core.windows.net/a\r\nLocation: https://a.blob.core.windows.net/b\r\n\r\n", b"{}"),
                                      (b"200", "HTTP/2 200\r\n\r\n", b"x" * 1025)]:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                directory = Path(scratch)
                transport = self.i.Transport(directory, "unit_test_readonly_token", self.manifest)
                def process(argv, **kwargs):
                    Path(argv[argv.index("--output") + 1]).write_bytes(body)
                    Path(argv[argv.index("--dump-header") + 1]).write_text(headers)
                    return subprocess.CompletedProcess(argv, 0, status, b"")
                with patch.object(self.i.subprocess, "run", side_effect=process):
                    self.reject(transport.get, self.i.fixed_endpoints(self.manifest)["run"], directory / "response", 1024)

    def test_verified_attestation_rejects_subject_checksum_substitution(self):
        artifact, proof = self.attestation()
        proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "a" * 64
        self.reject(self.i.check_attestation, self.manifest, artifact, proof)

    def test_native_canonical_boundary_accepts_libraries_and_rejects_links_extras_modes(self):
        native = module_file("import_test_native", ROOT / "tools/transport_release_build_output.py")
        for fault in (None, "link", "extra", "mode", "append"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                root = tarfile.TarInfo("./"); root.type = tarfile.DIRTYPE; root.mode = 0o700
                archive.addfile(root)
                for index, name in enumerate(native.EXPECTED_FILES):
                    member = tarfile.TarInfo("./" + name); member.mode = 0o644; member.size = 1
                    if index == 0 and fault == "mode": member.mode = 0o755
                    if index == 0 and fault == "link":
                        member.type = tarfile.SYMTYPE; member.linkname = "outside"; member.size = 0
                    archive.addfile(member, io.BytesIO(b"x"))
                if fault == "extra": archive.addfile(tarfile.TarInfo("./extra"), io.BytesIO())
            path = self.root / (str(fault) + ".tar.gz")
            payload = gzip.compress(stream.getvalue(), mtime=0)
            if fault == "append": payload += gzip.compress(b"extra", mtime=0)
            path.write_bytes(payload)
            if fault:
                with self.assertRaises((ValueError, SystemExit)):
                    self.i.validate_native(path, ROOT / "tools")
            else:
                self.assertEqual(self.i.validate_native(path, ROOT / "tools"), {"libraries":29,"executables":0})

    def test_sbom_canonical_boundary_rejects_duplicate_json_and_local_paths(self):
        validator = module_file("import_test_sbom", ROOT / "tools/verify_release_sbom.py")
        value = {"$schema":validator.SCHEMA_URI,"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
                 "components":[],"dependencies":[],"metadata":{"timestamp":validator.EXPECTED_TIMESTAMP,
                 "tools":[validator.EXPECTED_TOOL],"properties":[validator.EXPECTED_TARGET_PROPERTY],
                 "component":{"name":"exochain-core","version":"0.2.7"}}}
        name = "exochain-0.2.7-exochain-core.cdx.json"
        manifest = {"artifacts":[{"lane":"sbom","files":[{"path":name}]}]}
        path = self.root / name
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        path.write_bytes(canonical)
        self.assertEqual(self.i.validate_sboms(manifest, self.root, ROOT / "tools"), {"canonical_sboms":1})
        for bad in [canonical.replace(b'"version":1', b'"version":1,"version":1'),
                    canonical.replace(b'"components":[]', b'"components":["file:///home/runner/private"]'),
                    json.dumps(value, indent=2).encode()]:
            path.write_bytes(bad)
            with self.assertRaises((ValueError, SystemExit)):
                self.i.validate_sboms(manifest, self.root, ROOT / "tools")


def real_evidence_check():
    """Explicit local evidence checks, separate from mocked transport tests.

    This does not run the hosted signer wrapper or redo gh cryptography. It
    rechecks actual original bytes and the retained successful gh verify result.
    No flags are added to the production import helper.
    """
    parser = argparse.ArgumentParser(description=real_evidence_check.__doc__)
    parser.add_argument("--real-evidence", required=True, type=Path)
    parser.add_argument("--original-run-evidence", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    args = parser.parse_args()
    if args.evidence_directory.exists() or args.evidence_directory.is_symlink():
        parser.error("evidence directory must be absent")
    node = args.node.resolve(strict=True)
    result = subprocess.run([str(node), "--version"], env={}, capture_output=True, text=True, check=True)
    if result.stdout.strip() != "v24.15.0":
        parser.error("real npm package checks require Node 24.15.0")
    args.evidence_directory.mkdir(mode=0o700)
    importer = importer_module()
    custody = module_file("import_real_custody", ROOT / "tools/verify_release_recovery_027.py")
    manifest = custody.load_manifest(MANIFEST)
    metadata = [custody.load_json(args.real_evidence / "metadata" / f"{a['id']}.json", "real original metadata")
                for a in manifest["artifacts"] + manifest["rust_preparation"]]
    summary = {"origin":custody.verify_origin(manifest,
               custody.load_json(args.original_run_evidence / "run.json", "real original run"),
               custody.load_json(args.original_run_evidence / "jobs.json", "real original jobs"), metadata)}
    for artifact in manifest["artifacts"]:
        custody.verify_zip(args.real_evidence / "archives" / f"{artifact['id']}.zip", artifact)
    artifacts = args.real_evidence / "extracted"
    summary["files"] = custody.verify_files(manifest, artifacts)
    summary["rust"] = custody.verify_rust(manifest, {c["name"]:custody.load_json(
        args.real_evidence / "rust-responses" / (c["name"] + ".json"), "observed public Rust version") for c in manifest["rust_crates"]})
    summary["packages"] = importer.validate_packages(manifest, artifacts, ROOT / "tools", args.evidence_directory, sys.executable, str(node))
    summary["native_attestation_identities"] = [importer.check_attestation(manifest, a, custody.load_json(
        args.original_run_evidence / (a["lane"] + "-verified-attestations.json"), "retained actual gh verification result"))
        for a in manifest["artifacts"] if a["lane"].startswith("native-")]
    summary["limits"] = "Local canonical checks and retained gh-verified result identity recheck; not a hosted signed-controller execution or fresh cryptographic verification."
    importer.dump(args.evidence_directory / "positive-check.json", summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    if "--real-evidence" in sys.argv:
        real_evidence_check()
    else:
        unittest.main()
