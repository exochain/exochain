#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for the fixed, offline 0.2.7 recovery custody boundary."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import io
import shutil
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/verify_release_recovery_027.py"
MANIFEST = ROOT / "governance/releases/v0.2.7/RECOVERY-MANIFEST.json"
PUBLICATIONS = ROOT / "governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json"
PRODUCT_SHA = "666c578f719d1e54fce95d6831a3af92ea80df93"
PRODUCT_TAG = "be47589ec7dbefe821ada35ed0a89dedc9751953"
ABC_SHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HELPER.is_file():
            cls.v = None
            return
        spec = importlib.util.spec_from_file_location("recovery027", HELPER)
        cls.v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.v)

    def setUp(self):
        self.assertIsNotNone(self.v, "fixed recovery validator has not been implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest = self.v.load_manifest(MANIFEST)

    def reject(self, function, *args):
        with self.assertRaises(self.v.RecoveryError):
            function(*args)

    def test_manifest_cli_accepts_only_reviewed_product(self):
        result = subprocess.run([sys.executable, "-B", str(HELPER), "manifest", "--manifest", str(MANIFEST)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["product"]["version"], "0.2.7")
        self.assertEqual(value["product"]["commit"], PRODUCT_SHA)
        self.assertEqual(len(value["ci_jobs"]), 35)
        self.assertEqual(len(value["rust_crates"]), 32)
        self.assertEqual(value["rust_crates"][0]["sha256"], "b30534d84bbd92f01e81d720dc54fca0f8a498c97b326094ab21ada847f6d930")

    def test_publication_cli_returns_exact_prior_identity_and_preserves_manifest_pin(self):
        self.assertEqual(self.v.MANIFEST_SHA256, "17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4")
        for profile in ("wasm", "llm", "sdk", "python-wheel", "python-sdist"):
            result = subprocess.run([sys.executable, "-B", str(HELPER), "publication", "--manifest", str(MANIFEST),
                                     "--identities", str(PUBLICATIONS), "--publication", profile], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(result.stdout)
            expected = {"commit": PRODUCT_SHA, "ref": "refs/tags/v0.2.7"} if profile == "wasm" else {
                "commit": "2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1", "ref": "refs/tags/v0.2.7-recover.2"}
            self.assertEqual(record["source"], expected)
            self.assertEqual(record["id"], profile)
            self.assertEqual(record["observed_publication"]["attempt"], 2 if profile.startswith("python-") else 1)

    def test_publication_records_reject_every_identity_and_inventory_change(self):
        original = self.v.load_json(PUBLICATIONS, "publication fixture")
        mutations = [
            lambda p: p.update(schema="other"),
            lambda p: p.update(artifact_manifest_sha256="0" * 64),
            lambda p: p.update(override=True),
            lambda p: p["publications"].pop(),
            lambda p: p["publications"].append(p["publications"][0]),
            lambda p: p["publications"].reverse(),
        ]
        for index in range(5):
            mutations.extend([
                lambda p, i=index: p["publications"][i].update(id="other"),
                lambda p, i=index: p["publications"][i].update(package="other"),
                lambda p, i=index: p["publications"][i].update(version="0.2.8"),
                lambda p, i=index: p["publications"][i].update(lane="other"),
                lambda p, i=index: p["publications"][i]["file"].update(sha256="0" * 64),
                lambda p, i=index: p["publications"][i]["file"].update(size=True),
                lambda p, i=index: p["publications"][i]["file"].update(path="../other"),
                lambda p, i=index: p["publications"][i]["source"].update(commit="a" * 40),
                lambda p, i=index: p["publications"][i]["source"].update(ref="refs/tags/v0.2.7-recover.3"),
                lambda p, i=index: p["publications"][i]["observed_publication"].update(run_id=1),
                lambda p, i=index: p["publications"][i]["observed_publication"].update(attempt=3),
            ])
        for index, mutate in enumerate(mutations):
            value = copy.deepcopy(original)
            mutate(value)
            with self.subTest(mutation=index):
                self.reject(self.v.validate_publications, self.manifest, value)

    def test_publication_record_cannot_rebind_an_artifact_manifest(self):
        records = self.v.load_json(PUBLICATIONS, "publication fixture")
        manifest = copy.deepcopy(self.manifest)
        manifest["artifacts"][1]["files"][0]["sha256"] = "0" * 64
        self.reject(self.v.validate_publications, manifest, records)

    def test_json_rejects_duplicate_keys_nonfinite_and_oversize(self):
        for text in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1.0}', '[' * 2000]:
            with self.subTest(text=text[:20]):
                self.reject(self.v.parse_json, text.encode(), "fixture")
        self.reject(self.v.parse_json, b' ' * (self.v.MAX_JSON_BYTES + 1), "fixture")

    def test_manifest_rejects_scope_inventory_and_digest_substitution(self):
        mutations = [
            lambda m: m["product"].update(version="0.2.8"),
            lambda m: m["product"].update(commit="a" * 40),
            lambda m: m["product"].update(tag_object="b" * 40),
            lambda m: m["origin"].update(attempt=2),
            lambda m: m["origin"].update(repository_id=True),
            lambda m: m.update(command="curl attacker.invalid"),
            lambda m: m["artifacts"][0].update(url="https://attacker.invalid"),
            lambda m: m["artifacts"][0].update(producer_job_id=105361974338),
            lambda m: m["artifacts"][0]["files"][0].update(sha256="a" * 64),
            lambda m: m["artifacts"][0]["files"][0].update(path="../outside"),
            lambda m: m["ci_jobs"].pop(),
            lambda m: m["ci_jobs"].append(m["ci_jobs"][0]),
            lambda m: m["rust_crates"].pop(),
        ]
        for mutate in mutations:
            value = copy.deepcopy(self.manifest)
            mutate(value)
            with self.subTest(mutation=mutate):
                self.reject(self.v.validate_manifest, value)

    def fixtures(self):
        run = {"id":35257955565,"run_attempt":1,"workflow_id":248228578,"path":".github/workflows/release.yml","event":"workflow_dispatch","head_branch":"v0.2.7","head_sha":PRODUCT_SHA,"status":"completed","conclusion":"failure","repository":{"id":1116455646,"full_name":"exochain/exochain"},"head_repository":{"id":1116455646,"full_name":"exochain/exochain"}}
        jobs = [{"id":j["id"],"name":j["name"],"run_id":35257955565,"run_attempt":1,"head_sha":PRODUCT_SHA,"head_branch":"v0.2.7","status":"completed","conclusion":"success"} for j in self.manifest["ci_jobs"] + self.manifest["release_jobs"]]
        # The five original post-Rust publication jobs were failure/skipped.
        for number in [105451164443,105452576717,105452576899,105452577543,105452577735]:
            jobs.append({"id":number,"name":"non-required original publisher","run_id":35257955565,"run_attempt":1,"head_sha":PRODUCT_SHA,"head_branch":"v0.2.7","status":"completed","conclusion":"skipped"})
        metadata = [{"id":a["id"],"name":a["name"],"size_in_bytes":a["zip_size"],"digest":"sha256:"+a["zip_sha256"],"expired":False,"workflow_run":{"id":35257955565,"repository_id":1116455646,"head_repository_id":1116455646,"head_branch":"v0.2.7","head_sha":PRODUCT_SHA}} for a in self.manifest["artifacts"]+self.manifest["rust_preparation"]]
        return run, {"total_count":62,"jobs":jobs}, metadata

    def test_origin_accepts_failed_overall_run_with_all_successful_gates(self):
        result = self.v.verify_origin(self.manifest, *self.fixtures())
        self.assertEqual(result["run_id"], 35257955565)
        self.assertEqual(result["run_attempt"], 1)
        self.assertEqual(result["ci_jobs_verified"], 35)
        self.assertEqual(result["artifacts_verified"], 7)

    def test_origin_rejects_identity_job_and_artifact_boundary_changes(self):
        mutations = [
            lambda r,j,a:r.update(run_attempt=2),
            lambda r,j,a:r.update(event="pull_request"),
            lambda r,j,a:r.update(head_sha="a"*40),
            lambda r,j,a:r["repository"].update(id=True),
            lambda r,j,a:j["jobs"][0].update(name="unrelated passed job"),
            lambda r,j,a:j["jobs"][0].update(conclusion="skipped"),
            lambda r,j,a:j["jobs"][0].update(run_attempt=2),
            lambda r,j,a:j["jobs"][0].update(id=True),
            lambda r,j,a:j["jobs"].append(j["jobs"][0]),
            lambda r,j,a:j["jobs"].pop(),
            lambda r,j,a:a[0].update(id=True),
            lambda r,j,a:a[0].update(digest="sha256:"+"a"*64),
            lambda r,j,a:a[0].update(expired=True),
            lambda r,j,a:a[0]["workflow_run"].update(head_sha="b"*40),
            lambda r,j,a:a.append(a[0]),
        ]
        for mutate in mutations:
            fixture = self.fixtures()
            mutate(*fixture)
            with self.subTest(mutation=mutate):
                self.reject(self.v.verify_origin, self.manifest, *fixture)

    def test_wrong_producer_fails_even_with_correct_artifact_digests(self):
        run,jobs,metadata = self.fixtures()
        producer = next(j for j in jobs["jobs"] if j["id"] == 105363096810)
        producer["id"] = 90000000000
        self.reject(self.v.verify_origin,self.manifest,run,jobs,metadata)

    def test_product_tag_requires_two_exact_remote_refs_and_local_peel(self):
        refs=f"{PRODUCT_TAG}\trefs/tags/v0.2.7\n{PRODUCT_SHA}\trefs/tags/v0.2.7^{{}}\n"
        result=self.v.verify_product_tag(self.manifest,PRODUCT_TAG,PRODUCT_SHA,refs)
        self.assertEqual(result["commit"], PRODUCT_SHA)
        for obj,commit,remote in [("a"*40,PRODUCT_SHA,refs),(PRODUCT_TAG,"b"*40,refs),(PRODUCT_TAG,PRODUCT_SHA,refs+refs),(PRODUCT_TAG,PRODUCT_SHA,refs.replace("v0.2.7","v0.2.7-recover.1")),(PRODUCT_TAG,PRODUCT_SHA,refs.splitlines()[0]+"\n")]:
            self.reject(self.v.verify_product_tag,self.manifest,obj,commit,remote)

    def test_controller_rejects_product_sha_wrong_ref_and_substitution(self):
        self.v.verify_controller("a"*40,"refs/tags/v0.2.7-recover.1","v0.2.7-recover.1")
        for sha,ref,tag in [(PRODUCT_SHA,"refs/tags/v0.2.7-recover.1","v0.2.7-recover.1"),("a"*40,"refs/tags/v0.2.7","v0.2.7"),("a"*40,"refs/tags/v0.2.7-recover.0","v0.2.7-recover.0"),("a"*40,"refs/tags/v0.2.7-recover.01","v0.2.7-recover.01"),("a"*40,"refs/tags/v0.2.7-recover.1","v0.2.7-recover.2")]:
            self.reject(self.v.verify_controller,sha,ref,tag)

    def zip_fixture(self, names=("file.tgz",), mode=stat.S_IFREG|0o600, compression=zipfile.ZIP_STORED):
        path=self.root/"archive.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path,"w") as archive:
                for name in names:
                    info=zipfile.ZipInfo(name)
                    info.external_attr=mode<<16
                    info.compress_type=compression
                    archive.writestr(info,b"abc")
        data=path.read_bytes()
        record={"lane":"npm-wasm","id":10518086890,"zip_size":len(data),"zip_sha256":hashlib.sha256(data).hexdigest(),"files":[{"path":"file.tgz","size":3,"sha256":ABC_SHA}]}
        return path,record

    def test_zip_verifies_regular_payload_and_rejects_modified_payload(self):
        path,record=self.zip_fixture()
        self.v.verify_zip(path,record)
        record["files"][0]["sha256"]="f"*64
        self.reject(self.v.verify_zip,path,record)

    def test_zip_rejects_duplicate_extra_traversal_link_and_compression(self):
        for names,mode,compression in [(("file.tgz","file.tgz"),stat.S_IFREG|0o600,0),(("file.tgz","extra"),stat.S_IFREG|0o600,0),(("../file.tgz",),stat.S_IFREG|0o600,0),(("file.tgz",),stat.S_IFLNK|0o777,0),(("file.tgz",),stat.S_IFIFO|0o600,0),(("file.tgz",),stat.S_IFREG|0o600,zipfile.ZIP_BZIP2)]:
            path,record=self.zip_fixture(names,mode,compression)
            self.reject(self.v.verify_zip,path,record)

    def test_regular_input_rejects_symlink_hardlink_and_fifo(self):
        path,record=self.zip_fixture()
        link=self.root/"link.zip"; link.symlink_to(path)
        self.reject(self.v.verify_zip,link,record)
        hard=self.root/"hard.zip"; os.link(path,hard)
        self.reject(self.v.verify_zip,path,record)
        fifo=self.root/"fifo"; os.mkfifo(fifo)
        self.reject(self.v.read_regular,fifo,100,"fixture")

    def test_zip_rejects_encrypted_extra_fields_and_size_lies(self):
        for mutation in ("encrypted", "extra", "expanded", "compressed"):
            path,record=self.zip_fixture()
            data=bytearray(path.read_bytes())
            central=data.index(b"PK\x01\x02")
            if mutation == "encrypted":
                data[6] |= 1; data[central+8] |= 1
            elif mutation == "expanded":
                data[central+24:central+28]=(4).to_bytes(4,"little")
            elif mutation == "compressed":
                data[central+20:central+24]=(2).to_bytes(4,"little")
            else:
                with zipfile.ZipFile(path,"w") as archive:
                    info=zipfile.ZipInfo("file.tgz");info.external_attr=(stat.S_IFREG|0o600)<<16
                    info.extra=b"\x0d\x00\x00\x00"  # Unix link-capable extension.
                    archive.writestr(info,b"abc")
                data=bytearray(path.read_bytes())
            path.write_bytes(data)
            record.update(zip_size=len(data),zip_sha256=hashlib.sha256(data).hexdigest())
            self.reject(self.v.verify_zip,path,record)

    def test_artifacts_validate_every_zip_before_destination_creation(self):
        archives=self.root/"zips";archives.mkdir()
        path,record=self.zip_fixture()
        path.rename(archives/"10518086890.zip")
        missing=copy.deepcopy(record);missing.update(id=10517981432,lane="npm-llm")
        (archives/"10517981432.zip").write_bytes(b"broken")
        destination=self.root/"output"
        self.reject(self.v.extract_artifacts,{"artifacts":[record,missing]},archives,destination)
        self.assertFalse(destination.exists(),"invalid later archive must not materialize earlier payloads")

    def test_extraction_and_files_reject_extra_files_links_and_reuse(self):
        archives=self.root/"zips";archives.mkdir()
        path,record=self.zip_fixture()
        path.rename(archives/"10518086890.zip")
        manifest={"artifacts":[record]}
        destination=self.root/"output"
        self.v.extract_artifacts(manifest,archives,destination)
        self.assertEqual((destination/"npm-wasm/file.tgz").read_bytes(),b"abc")
        self.assertEqual(self.v.verify_files(manifest,destination,"npm-wasm")["files_verified"],1)
        self.reject(self.v.extract_artifacts,manifest,archives,destination)
        (destination/"npm-wasm/extra").write_bytes(b"x")
        self.reject(self.v.verify_files,manifest,destination,"npm-wasm")
        (destination/"npm-wasm/extra").unlink()
        (destination/"npm-wasm/file.tgz").unlink()
        (destination/"npm-wasm/file.tgz").symlink_to(archives/"10518086890.zip")
        self.reject(self.v.verify_files,manifest,destination,"npm-wasm")

    def test_wrapper_rejects_identity_substitution_before_git_or_network(self):
        wrapper=ROOT/"tools/verify_release_recovery_027.sh"
        for sha,tag,ref,want in [(PRODUCT_SHA,"v0.2.7-recover.1","refs/tags/v0.2.7-recover.1","distinct"),("a"*40,"v0.2.7-recover.0","refs/tags/v0.2.7-recover.0","maintenance"),("a"*40,"v0.2.7-recover.1","refs/tags/v0.2.7","dispatch ref")]:
            result=subprocess.run(["/bin/bash","--noprofile","--norc","-p",str(wrapper)],env={"GITHUB_SHA":sha,"RELEASE_TAG":tag,"GITHUB_REF":ref},capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(want,result.stderr)

    def test_wrapper_rejects_publication_credentials_at_capture_boundary(self):
        result=subprocess.run(["/bin/bash","--noprofile","--norc","-p",str(ROOT/"tools/verify_release_recovery_027.sh")],env={"NPM_TOKEN":"test-only-invalid-token"},capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("publication credentials",result.stderr)

    def test_rust_requires_all_32_unyanked_exact_archive_checksums(self):
        responses={r["name"]:{"version":{"crate":r["name"],"num":"0.2.7","id":3263319+i,"yanked":False,"checksum":r["sha256"]}} for i,r in enumerate(self.manifest["rust_crates"])}
        self.assertEqual(self.v.verify_rust(self.manifest,responses)["crates_verified"],32)
        for field,bad in [("yanked",True),("checksum","65c484748487ac1369be976f47f5e2502358a17e868a2f247a7a67276339fde7"),("num","0.2.6"),("id",True),("crate","attacker")]:
            value=copy.deepcopy(responses); value["exochain-core"]["version"][field]=bad
            self.reject(self.v.verify_rust,self.manifest,value)
        del responses["exochain-wasm"]
        self.reject(self.v.verify_rust,self.manifest,responses)


class RetainedTests(unittest.TestCase):
    setUpClass = classmethod(RecoveryTests.setUpClass.__func__)
    reject = RecoveryTests.reject
    fixtures = RecoveryTests.fixtures

    def setUp(self):
        RecoveryTests.setUp(self)
        self.record_path = ROOT / "governance/releases/v0.2.7/RETAINED-CUSTODY.json"

    def record(self):
        return self.v.load_retained_record(self.manifest, self.record_path)

    def metadata_policy_fixture(self):
        return {
            "schema": "exochain-retained-metadata-policy-027/v1",
            "operation": "recover-0.2.7-retained-404",
            "manifest_sha256": "17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4",
            "publications_sha256": "4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7",
            "retained_sha256": "7f2eac05d0fea00a29a1ea3ebf7605eee7ab66905a40d8e016ef50510c2c038a",
            "repository": {"name": "exochain/exochain", "id": 1116455646, "owner_id": 129763194},
            "original": {"run_id": 35257955565, "attempt": 1},
            "retaining": {"run_id": 35754493083, "attempt": 1},
            "retained_artifact_ids": [10779404529, 10780480598],
            "unavailable_originals": [
                {"id": 10518086890, "historical_member": "artifact-metadata/10518086890.json", "historical_sha256": "23a1d7f70d0da078e712fe0844f5c52101cd9b03e510941f6c758508a6e73245", "expires_at": "2026-09-24T20:09:34Z"},
                {"id": 10518128532, "historical_member": "artifact-metadata/10518128532.json", "historical_sha256": "d465cde79dd2ecd25a46cf065841a5d8eef5792f8a0d91bdf70c10a888caf93d", "expires_at": "2026-09-24T20:19:17Z"},
                {"id": 10517978596, "historical_member": "artifact-metadata/10517978596.json", "historical_sha256": "dcec5cb76b7875501c83c343957a4ccded7501142d009412e54ce82d517531ad", "expires_at": "2026-09-24T20:19:29Z"},
                {"id": 10517854663, "historical_member": "artifact-metadata/10517854663.json", "historical_sha256": "ea27bd26387b0335aa33a9931d432a749ed834222ffd085d370bd1d7d1a26bf9", "expires_at": "2026-09-24T20:24:33Z"},
            ],
        }

    def test_metadata_policy_rejects_nested_tampering_and_operation_confusion(self):
        validator = self.v
        record, policy = self.record(), self.metadata_policy_fixture()
        self.assertEqual(validator.validate_retained_metadata_policy(self.manifest, record, policy), policy)
        self.assertEqual([x["id"] for x in policy["unavailable_originals"]],
                         [10518086890, 10518128532, 10517978596, 10517854663])
        self.assertEqual(policy["retained_artifact_ids"], [10779404529, 10780480598])
        self.assertEqual(validator.load_retained_metadata_policy(
            self.manifest, record, ROOT / "governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json"), policy)
        with self.assertRaises(validator.RecoveryError):
            validator.validate_retained_metadata_policy(self.manifest, record, dict(policy, operation="recover-0.2.7-retained"))
        for path, replacement in (("schema", "other"), ("manifest_sha256", "0" * 64),
                                  ("publications_sha256", "0" * 64), ("retained_sha256", "0" * 64),
                                  ("repository.id", True), ("repository.owner_id", 1),
                                  ("original.attempt", 2), ("retaining.run_id", 1),
                                  ("retained_artifact_ids.0", True), ("retained_artifact_ids.1", 1),
                                  ("unavailable_originals.0.id", True),
                                  ("unavailable_originals.1.historical_member", "wrong"),
                                  ("unavailable_originals.2.historical_sha256", "0" * 64),
                                  ("unavailable_originals.3.expires_at", "2026-09-25T20:24:33Z")):
            changed = copy.deepcopy(policy)
            target = changed
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[int(part)] if part.isdigit() else target[part]
            last = parts[-1]
            target[int(last) if last.isdigit() else last] = replacement
            with self.subTest(path=path):
                self.reject(validator.validate_retained_metadata_policy, self.manifest, record, changed)
        for mutation in (lambda p: p.update(extra=1), lambda p: p.pop("repository"),
                         lambda p: p["repository"].update(extra=1),
                         lambda p: p["unavailable_originals"].append(copy.deepcopy(p["unavailable_originals"][0])),
                         lambda p: p["unavailable_originals"].reverse(),
                         lambda p: p["retained_artifact_ids"].reverse()):
            changed = copy.deepcopy(policy)
            mutation(changed)
            self.reject(validator.validate_retained_metadata_policy, self.manifest, record, changed)
        for index, item in enumerate(policy["unavailable_originals"]):
            for field, replacement in (("id", 1), ("historical_member", "artifact-metadata/1.json"),
                                       ("historical_sha256", "0" * 64), ("expires_at", "2026-09-25T20:00:00Z")):
                changed = copy.deepcopy(policy)
                changed["unavailable_originals"][index][field] = replacement
                with self.subTest(original=index, field=field):
                    self.reject(validator.validate_retained_metadata_policy, self.manifest, record, changed)
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        self.assertEqual(validator.load_retained_metadata_policy(self.manifest, record, policy_path), policy)
        policy_path.write_text(json.dumps(policy).replace('"schema":', '"schema": "other", "schema":', 1))
        self.reject(validator.load_retained_metadata_policy, self.manifest, record, policy_path)

    def test_retained_cli_interfaces_are_bounded_json(self):
        for mode in ("retained-record", "retained-origin", "retained-transport", "retained-receipts"):
            result = subprocess.run([sys.executable, "-B", str(HELPER), mode, "--manifest", str(MANIFEST),
                                     "--record", str(self.record_path)], capture_output=True, text=True)
            self.assertNotIn("invalid choice", result.stderr)
            if mode == "retained-record":
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["schema"], "exochain-retained-custody-027/v1")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stderr)["error"], "release_recovery_027_rejected")

    def test_retained_record_rejects_every_semantic_change(self):
        record = self.record()
        for key in record:
            changed = copy.deepcopy(record)
            changed[key] = None
            with self.subTest(key=key):
                self.reject(self.v.validate_retained_record, self.manifest, changed)
        changed = copy.deepcopy(record)
        changed["retaining"]["attempt"] = True
        self.reject(self.v.validate_retained_record, self.manifest, changed)
        changed = copy.deepcopy(record)
        changed["override"] = "arbitrary"
        self.reject(self.v.validate_retained_record, self.manifest, changed)
        self.assertEqual(self.v.MAX_ZIP_BYTES, 96 * 1024 * 1024)

    def streaming_zip(self, content=b"abc", name="receipt.json", compression=8, mode=0o100600):
        class NonSeekable(io.BytesIO):
            def seekable(self):
                return False
            def seek(self, *args):
                raise OSError("streaming fixture")
        buffer = NonSeekable()
        with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
            for member_name in ((name,) if type(name) is str else name):
                info = zipfile.ZipInfo(member_name)
                info.create_system = 3
                info.create_version = 45
                info.extract_version = 20
                info.external_attr = mode << 16 | 32
                info.compress_type = compression
                archive.writestr(info, content)
        return buffer.getvalue()

    def profile_fixture(self, data):
        path = self.root / "stream.zip"
        path.write_bytes(data)
        return path, {"zip_size": len(data), "zip_sha256": hashlib.sha256(data).hexdigest(),
                      "compression": 8, "mode": 0o100600, "dos_attributes": 32, "expanded_bytes": 3,
                      "files": [{"path": "receipt.json", "size": 3, "sha256": ABC_SHA}]}

    def test_retained_zip_profile_positive_and_complete_descriptor_rejections(self):
        data = self.streaming_zip()
        path, profile = self.profile_fixture(data)
        self.v.verify_retained_zip(path, profile)
        descriptor = data.index(b"PK\x07\x08")
        central = data.index(b"PK\x01\x02")
        mutations = {
            "prefix": b"x" + data,
            "trailing": data + b"x",
            "missing_descriptor": data[:descriptor] + data[descriptor + 16:],
            "truncated_descriptor": data[:descriptor + 12] + data[descriptor + 16:],
            "unsigned_descriptor": data[:descriptor] + data[descriptor + 4:],
        }
        for label, offset, replacement in [
            ("forged_crc", descriptor + 4, b"\0" * 4),
            ("overlap", central + 20, (15).to_bytes(4, "little")),
            ("descriptor_size", descriptor + 8, (999).to_bytes(4, "little")),
            ("local_crc", 14, (1).to_bytes(4, "little")),
            ("local_flags", 6, (0).to_bytes(2, "little")),
            ("central_flags", central + 8, (9).to_bytes(2, "little")),
            ("local_version", 4, (45).to_bytes(2, "little")),
            ("central_creator", central + 4, (20).to_bytes(2, "little")),
            ("symlink", central + 38, (0o120600 << 16).to_bytes(4, "little")),
            ("fifo", central + 38, (0o010600 << 16).to_bytes(4, "little")),
            ("dos_bits", central + 38, (0o100600 << 16).to_bytes(4, "little")),
            ("central_offset", central + 42, (1).to_bytes(4, "little")),
            ("disk", len(data) - 18, (1).to_bytes(2, "little")),
        ]:
            changed = bytearray(data)
            changed[offset:offset + len(replacement)] = replacement
            mutations[label] = bytes(changed)
        for label, changed in mutations.items():
            with self.subTest(label=label):
                path, profile = self.profile_fixture(changed)
                self.reject(self.v.verify_retained_zip, path, profile)

    def test_retained_zip_rejects_unsafe_names_types_streams_and_filesystem_inputs(self):
        for name in ("../receipt.json", "/receipt.json", "dir\\receipt.json", "./receipt.json", "receipt.json/", "extra.json"):
            path, profile = self.profile_fixture(self.streaming_zip(name=name))
            self.reject(self.v.verify_retained_zip, path, profile)
        for mode in (0o120600, 0o010600, 0o060600, 0o020600, 0o040600):
            path, profile = self.profile_fixture(self.streaming_zip(mode=mode))
            self.reject(self.v.verify_retained_zip, path, profile)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for names in (("receipt.json", "receipt.json"), ("receipt.json", "extra.json")):
                path, profile = self.profile_fixture(self.streaming_zip(name=names))
                self.reject(self.v.verify_retained_zip, path, profile)
        for compression in (0, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            path, profile = self.profile_fixture(self.streaming_zip(compression=compression))
            self.reject(self.v.verify_retained_zip, path, profile)
        data = bytearray(self.streaming_zip())
        data[30 + len("receipt.json")] = 255
        path, profile = self.profile_fixture(bytes(data))
        self.reject(self.v.verify_retained_zip, path, profile)

    def test_retained_zip_rejects_changed_descriptor_identity(self):
        path, profile = self.profile_fixture(self.streaming_zip())
        real_stat = self.v.os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            metadata = real_stat(fd)
            if calls == 3:
                fields = {key: getattr(metadata, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
                fields["st_mtime_ns"] += 1
                return SimpleNamespace(**fields)
            return metadata
        with mock.patch.object(self.v.os, "fstat", side_effect=changed):
            self.reject(self.v.verify_retained_zip, path, profile)
        path, profile = self.profile_fixture(self.streaming_zip())
        linked = self.root / "linked.zip"
        linked.symlink_to(path)
        self.reject(self.v.verify_retained_zip, linked, profile)
        hard = self.root / "hardlink.zip"
        os.link(path, hard)
        self.reject(self.v.verify_retained_zip, path, profile)

    def test_actual_retained_archives_when_explicitly_supplied(self):
        audit = os.environ.get("EXO_RETAINED_AUDIT_DIR")
        if not audit:
            self.skipTest("actual-byte check requires explicit read-only audit evidence directory")
        record = self.record()
        for kind in ("payload", "custody"):
            profile = self.v.retained_profile(self.manifest, record, kind)
            path = Path(audit) / (str(record[kind]["metadata"]["id"]) + ".zip")
            self.v.verify_retained_zip(path, profile)
            with path.open("rb") as raw:
                self.assertEqual(hashlib.file_digest(raw, "sha256").hexdigest(), profile["zip_sha256"])
            # Independent stdlib member readback; no extracted/imported bytes
            # replace release subjects and no package code is executed.
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(set(archive.namelist()), {f["path"] for f in profile["files"]})
                for file in profile["files"]:
                    with archive.open(file["path"]) as member:
                        self.assertEqual(hashlib.file_digest(member, "sha256").hexdigest(), file["sha256"])
                    self.assertEqual(archive.getinfo(file["path"]).file_size, file["size"])
        historical = self.v.read_historical_custody(self.manifest, record, Path(audit) / "10780480598.zip")
        self.assertEqual(historical["origin"]["artifacts_verified"], 7)
        self.assertEqual(historical["files_verified"], 40)
        self.assertFalse(historical["current_crypto_verified"])

    def origin_fixture(self):
        record = self.record()
        run, jobs, metadata = self.fixtures()
        for key in ("repository", "head_repository"):
            run[key]["owner"] = {"id": 129763194}
        for item in metadata:
            item.update(created_at="2026-09-17T20:00:00Z", updated_at="2026-09-17T20:00:00Z", expires_at="2026-09-24T20:00:00Z")
        expiries = {item["id"]: item["expires_at"] for item in self.metadata_policy_fixture()["unavailable_originals"]}
        for item in metadata:
            if item["id"] in expiries:
                item["expires_at"] = expiries[item["id"]]
        historical = {"origin": self.v.verify_origin(self.manifest, run, jobs, metadata), "metadata": metadata}
        retaining_run = copy.deepcopy(run)
        retaining_run.update(id=35754493083, head_sha=self.v.RETAINED_COMMIT, head_branch="v0.2.7-recover.2")
        for key in ("repository", "head_repository"):
            retaining_run[key]["owner"] = {"id": 129763194}
        mapping = record["retaining"]["producer"]
        producer = {**{k: v for k, v in mapping.items() if k != "steps"}, "run_id": 35754493083, "run_attempt": 1,
                    "head_sha": self.v.RETAINED_COMMIT, "head_branch": "v0.2.7-recover.2", "status": "completed", "conclusion": "success",
                    "steps": [{**s, "status": "completed", "conclusion": "success"} for s in mapping["steps"]]}
        retaining_jobs = [producer] + [{**producer, "id": i, "name": "fixture unrelated job"} for i in range(1, 68)]
        current = copy.deepcopy(metadata)
        for item in current:
            item["expired"] = True
        envelope = {"schema": "exochain-retained-origin-input-027/v1", "observed_at": "2026-09-24T23:00:00Z",
                    "retaining_run": retaining_run, "retaining_jobs": {"total_count": 68, "jobs": retaining_jobs},
                    "retaining_tag": {"object": record["retaining"]["tag_object"], "commit": self.v.RETAINED_COMMIT, "ref": self.v.RETAINED_REF},
                    "original_run": run, "original_jobs": jobs, "original_metadata": current,
                    "retained_before": [record["payload"]["metadata"], record["custody"]["metadata"]],
                    "retained_after": copy.deepcopy([record["payload"]["metadata"], record["custody"]["metadata"]])}
        self.enterContext(mock.patch.object(self.v, "read_historical_custody", return_value=historical))
        self.enterContext(mock.patch.object(self.v, "verify_retaining_workflow_source"))
        return record, envelope

    def observation_fixture(self, missing_ids=(), *, offset_seconds=0):
        from datetime import datetime, timedelta, timezone
        record, origin = self.origin_fixture()
        policy = self.metadata_policy_fixture()
        missing = set(missing_ids)
        policy_by_id = {item["id"]: item for item in policy["unavailable_originals"]}
        historical = {item["id"]: item for item in self.v.read_historical_custody(self.manifest, record, "fixture")["metadata"]}
        base = datetime(2026, 9, 25, 22, 1, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
        stamp = lambda seconds: (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = []
        for index, artifact_id in enumerate(sorted(historical)):
            member = f"artifact-metadata/{artifact_id}.json"
            item = {"id": artifact_id, "endpoint_role": "original-artifact-metadata",
                    "request_started_at": stamp(index * 2), "request_finished_at": stamp(index * 2 + 1),
                    "status": 404 if artifact_id in missing else 200,
                    "variant": "unavailable_404" if artifact_id in missing else "present",
                    "historical_member": member,
                    "historical_sha256": next(x["sha256"] for x in record["custody"]["files"] if x["path"] == member)}
            if artifact_id not in missing:
                item["metadata"] = dict(historical[artifact_id], expired=True)
            records.append(item)
        before = {"observed_at": stamp(20), "records": copy.deepcopy(records)}
        after = {"observed_at": stamp(40), "records": copy.deepcopy(records)}
        for index, item in enumerate(after["records"]):
            item["request_started_at"] = stamp(21 + index)
            item["request_finished_at"] = stamp(22 + index)
        return {"schema": "exochain-retained-original-observations-027/v1",
                "operation": "recover-0.2.7-retained-404", "policy_sha256": self.v.RETAINED_METADATA_POLICY_SHA256,
                "observer": {"run_id": 40000000000, "run_attempt": 2, "controller_sha": "a" * 40,
                             "controller_ref": "refs/tags/v0.2.7-recover.3", "controller_tag_object": "b" * 40,
                             "job_id": 110000000000, "job_name": self.v.RECEIPT_JOB,
                             "job_started_at": "2026-09-25T22:00:00Z"},
                "before": before, "after": after}

    def origin_v2_fixture(self, missing_ids=()):
        record, old = self.origin_fixture()
        observations = self.observation_fixture(missing_ids)
        controls = {"original_run": old["original_run"], "original_jobs": old["original_jobs"],
                    "retaining_run": old["retaining_run"], "retaining_jobs": old["retaining_jobs"],
                    "retained_metadata": copy.deepcopy(old["retained_before"]),
                    "observed_at": "2026-09-25T22:00:00Z"}
        after_controls = copy.deepcopy(controls)
        after_controls["observed_at"] = "2026-09-25T22:02:00Z"
        return record, {"schema": "exochain-retained-origin-027/v2", "operation": "recover-0.2.7-retained-404",
                        "policy_sha256": self.v.RETAINED_METADATA_POLICY_SHA256,
                        "observations": observations, "controls_before": copy.deepcopy(controls),
                        "controls_after": after_controls, "retaining_tag": old["retaining_tag"]}

    def test_observations_accept_all_200_and_each_eligible_404(self):
        validator = self.v
        record, old = self.origin_fixture()
        historical = validator.read_historical_custody(self.manifest, record, "fixture")
        policy = self.metadata_policy_fixture()
        for missing in ((), (10518086890,), (10518128532,), (10517978596,), (10517854663,),
                        (10518086890, 10518128532, 10517978596, 10517854663)):
            with self.subTest(missing=missing):
                vector = validator.validate_original_observations(
                    self.manifest, record, policy, historical, self.observation_fixture(missing), now="2026-09-25T22:03:00Z")
                self.assertEqual(len(vector), 9)
                self.assertEqual([x["id"] for x in vector if x["status"] == 404], sorted(missing))

    def test_normalized_vector_ignores_times_but_detects_transition(self):
        validator = self.v
        record, _ = self.origin_fixture()
        historical = validator.read_historical_custody(self.manifest, record, "fixture")
        policy = self.metadata_policy_fixture()
        validate = lambda observations: validator.validate_original_observations(
            self.manifest, record, policy, historical, observations, now="2026-09-25T22:04:00Z")
        first = self.observation_fixture((10518086890,))
        later = self.observation_fixture((10518086890,), offset_seconds=60)
        self.assertEqual(validate(first), validate(later))
        target = next(x for x in later["after"]["records"] if x["id"] == 10518086890)
        target.update(status=200, variant="present", metadata=next(dict(x, expired=True) for x in historical["metadata"] if x["id"] == 10518086890))
        with self.assertRaisesRegex(validator.RecoveryError, "original availability transition"):
            validate(later)
        reverse = self.observation_fixture()
        target = next(x for x in reverse["after"]["records"] if x["id"] == 10518086890)
        target.update(status=404, variant="unavailable_404")
        target.pop("metadata")
        with self.assertRaisesRegex(validator.RecoveryError, "original availability transition"):
            validate(reverse)

    def test_observations_reject_fifth_early_conflicting_or_fabricated_metadata(self):
        validator = self.v
        record, _ = self.origin_fixture()
        historical = validator.read_historical_custody(self.manifest, record, "fixture")
        policy = self.metadata_policy_fixture()
        validate = lambda observations: validator.validate_original_observations(
            self.manifest, record, policy, historical, observations, now="2026-09-25T22:04:00Z")
        for artifact_id in (10517981432, 10518080916, 10517457207, 10517966616, 10517459550):
            fifth = self.observation_fixture()
            for phase in ("before", "after"):
                target = next(x for x in fifth[phase]["records"] if x["id"] == artifact_id)
                target.update(status=404, variant="unavailable_404")
                target.pop("metadata")
            with self.subTest(non_policy_id=artifact_id):
                with self.assertRaisesRegex(validator.RecoveryError, "unselected original metadata unavailable"):
                    validate(fifth)
        early = self.observation_fixture((10518086890,))
        target = next(x for x in early["before"]["records"] if x["id"] == 10518086890)
        target["request_started_at"] = "2026-09-24T20:09:33Z"
        target["request_finished_at"] = "2026-09-24T20:09:34Z"
        with self.assertRaisesRegex(validator.RecoveryError, "original 404 precedes pinned expiry"):
            validator.validate_original_observation(self.manifest, record, policy, historical, target,
                                                    now="2026-09-24T20:09:34Z")
        for mutation in (lambda x: x["before"]["records"][0]["metadata"].update(digest="sha256:" + "0" * 64),
                         lambda x: x["before"]["records"][0]["metadata"].update(expired=1),
                         lambda x: x["before"]["records"][0].update(historical_sha256="0" * 64),
                         lambda x: x["before"]["records"].pop(),
                         lambda x: x["before"]["records"].reverse(),
                         lambda x: x["before"]["records"].append(copy.deepcopy(x["before"]["records"][0]))):
            changed = self.observation_fixture()
            mutation(changed)
            self.reject(validate, changed)
        fabricated = self.observation_fixture((10518086890,))
        target = next(x for x in fabricated["before"]["records"] if x["id"] == 10518086890)
        target["metadata"] = {"expired": True}
        self.reject(validate, fabricated)
        fabricated = self.observation_fixture((10518086890,))
        target = next(x for x in fabricated["before"]["records"] if x["id"] == 10518086890)
        target["expired"] = True
        self.reject(validate, fabricated)
        wrong_member = self.observation_fixture()
        wrong_member["before"]["records"][0]["historical_member"] = "artifact-metadata/1.json"
        self.reject(validate, wrong_member)

    def test_pure_observation_rejects_equal_nested_numeric_type_substitution(self):
        record, _ = self.origin_fixture()
        historical = self.v.read_historical_custody(self.manifest, record, "fixture")
        policy = self.metadata_policy_fixture()
        observations = self.observation_fixture()
        for phase in ("before", "after"):
            observations[phase]["records"][0]["metadata"]["workflow_run"]["id"] = float(35257955565)
        self.assertEqual(observations["before"]["records"][0]["metadata"]["workflow_run"]["id"], 35257955565)
        with self.assertRaises(self.v.RecoveryError):
            self.v.validate_original_observations(self.manifest, record, policy, historical, observations,
                                                  now="2026-09-25T22:03:00Z")

    def test_observation_chronology_binds_actual_job_and_checked_at(self):
        validator = self.v
        record, _ = self.origin_fixture()
        historical = validator.read_historical_custody(self.manifest, record, "fixture")
        policy = self.metadata_policy_fixture()
        validate = lambda observations: validator.validate_original_observations(
            self.manifest, record, policy, historical, observations, now="2026-09-25T22:03:00Z")
        self.assertEqual(len(validate(self.observation_fixture())), 9)
        for mutation in (lambda x: x["observer"].update(job_started_at="2026-09-25T22:02:00Z"),
                         lambda x: x["before"].update(observed_at="2026-09-25T22:00:00Z"),
                         lambda x: x["after"].update(observed_at="2026-09-25T22:04:00Z"),
                         lambda x: x["after"]["records"][0].update(request_started_at="2026-09-25T22:01:18Z", request_finished_at="2026-09-25T22:01:19Z"),
                         lambda x: x["after"]["records"][0].update(request_finished_at="2026-09-25T22:00:00Z"),
                         lambda x: x["observer"].update(run_id=35257955565)):
            changed = self.observation_fixture()
            mutation(changed)
            self.reject(validate, changed)

    def test_origin_v2_rejects_incomplete_controls_and_retained_drift(self):
        validator = self.v
        record, origin = self.origin_v2_fixture((10518086890,))
        policy = self.metadata_policy_fixture()
        result = validator.verify_retained_origin(self.manifest, record, origin, "fixture", "fixture", policy=policy)
        self.assertEqual(result["schema"], "exochain-retained-origin-result-027/v2")
        self.assertNotIn("current_original_origin", result)
        self.assertFalse(result["current_crypto_verified"])
        for mutation in (lambda x: x["controls_before"]["original_jobs"]["jobs"].pop(),
                         lambda x: x["controls_after"]["retaining_jobs"]["jobs"].pop(),
                         lambda x: x["controls_before"]["original_run"].update(run_attempt=2),
                         lambda x: x["controls_after"]["original_run"].update(head_sha="0" * 40),
                         lambda x: x["controls_before"]["original_run"].update(head_branch="wrong"),
                         lambda x: x["controls_before"]["original_jobs"]["jobs"][1].update(id=x["controls_before"]["original_jobs"]["jobs"][0]["id"]),
                         lambda x: x["controls_before"]["retaining_run"].update(head_sha="0" * 40),
                         lambda x: x["controls_after"]["retaining_run"].update(run_attempt=2),
                         lambda x: x["controls_before"]["retaining_jobs"]["jobs"][1].update(id=107409656991),
                         lambda x: x["controls_after"]["retaining_jobs"]["jobs"][0]["steps"][0].update(conclusion="failure"),
                         lambda x: x["controls_before"]["retaining_jobs"]["jobs"][0]["steps"].pop(),
                         lambda x: x["retaining_tag"].update(ref="refs/tags/wrong"),
                         lambda x: x["controls_after"]["retained_metadata"][0].update(expired=True),
                         lambda x: x["controls_after"]["retained_metadata"][0].update(expires_at="2026-09-25T22:02:00Z"),
                         lambda x: x["controls_before"]["retained_metadata"][1].update(digest="sha256:" + "0" * 64)):
            changed = copy.deepcopy(origin)
            mutation(changed)
            with self.subTest(mutation=mutation):
                with self.assertRaises(validator.RecoveryError):
                    validator.verify_retained_origin(self.manifest, record, changed, "fixture", "fixture", policy=policy)

    def test_origin_v2_rejects_wrong_retaining_workflow_and_post_expiry_import(self):
        original_workflow_validator = self.v.verify_retaining_workflow_source
        record, origin = self.origin_v2_fixture()
        policy = self.metadata_policy_fixture()
        bad_workflow = self.root / "wrong-retaining-workflow.yml"
        bad_workflow.write_bytes(b"changed workflow bytes")
        with mock.patch.object(self.v, "verify_retaining_workflow_source", original_workflow_validator):
            with self.assertRaises(self.v.RecoveryError):
                self.v.verify_retained_origin(self.manifest, record, origin, "fixture", bad_workflow, policy=policy)
        historical = copy.deepcopy(self.v.read_historical_custody(self.manifest, record, "fixture"))
        altered = next(x for x in historical["metadata"] if x["id"] == 10517457207)
        altered["expires_at"] = "2026-09-23T22:33:26Z"
        for phase in ("before", "after"):
            observed = next(x for x in origin["observations"][phase]["records"] if x["id"] == altered["id"])
            observed["metadata"]["expires_at"] = altered["expires_at"]
        with mock.patch.object(self.v, "read_historical_custody", return_value=historical):
            with self.assertRaisesRegex(self.v.RecoveryError, "historical import was not pre-expiry"):
                self.v.verify_retained_origin(self.manifest, record, origin, "fixture", "fixture", policy=policy)

    def test_origin_v2_requires_initial_controls_before_first_original_request(self):
        record, origin = self.origin_v2_fixture()
        policy = self.metadata_policy_fixture()
        first_start = origin["observations"]["before"]["records"][0]["request_started_at"]
        equal = copy.deepcopy(origin)
        equal["controls_before"]["observed_at"] = first_start
        result = self.v.verify_retained_origin(self.manifest, record, equal, "fixture", "fixture", policy=policy)
        self.assertEqual(result["schema"], "exochain-retained-origin-result-027/v2")
        inside = copy.deepcopy(origin)
        inside["controls_before"]["observed_at"] = "2026-09-25T22:01:10Z"
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_origin(self.manifest, record, inside, "fixture", "fixture", policy=policy)

    def test_retained_origin_preserves_actual_expiry_without_normalizing_original_mode(self):
        record, envelope = self.origin_fixture()
        result = self.v.verify_retained_origin(self.manifest, record, envelope, "fixture", "fixture")
        self.assertTrue(all(item["expired"] for item in result["original_expiry"]))
        self.assertFalse(result["current_crypto_verified"])
        self.reject(self.v.verify_origin, self.manifest, envelope["original_run"], envelope["original_jobs"], envelope["original_metadata"])

    def test_retained_origin_rejects_source_chronology_pagination_metadata_and_tag_changes(self):
        record, envelope = self.origin_fixture()
        mutations = [
            lambda e: e.update(schema="other"),
            lambda e: e.update(extra=True),
            lambda e: e.update(observed_at="2026-09-23T22:00:00Z"),
            lambda e: e.update(observed_at="2026-09-30T22:33:27Z"),
            lambda e: e["retaining_tag"].update(object="a" * 40),
            lambda e: e["retaining_run"].update(run_attempt=2),
            lambda e: e["retaining_run"].update(head_sha="a" * 40),
            lambda e: e["retaining_run"].update(conclusion="success"),
            lambda e: e["original_run"]["repository"]["owner"].update(id=1),
            lambda e: e["retaining_jobs"]["jobs"].pop(),
            lambda e: e["retaining_jobs"]["jobs"][0].update(conclusion="failure"),
            lambda e: e["retaining_jobs"]["jobs"][0].update(id=42),
            lambda e: e["retaining_jobs"]["jobs"][0]["steps"][0].update(completed_at="2026-09-24T22:33:27Z"),
            lambda e: e["retaining_jobs"]["jobs"][0]["steps"][0].update(completed_at="2026-09-22T22:33:27Z"),
            lambda e: e["retaining_jobs"]["jobs"][0]["steps"][1].update(conclusion="failure"),
            lambda e: e["retaining_jobs"]["jobs"][0]["steps"].pop(),
            lambda e: e["original_run"].update(run_attempt=2),
            lambda e: e["original_jobs"]["jobs"].pop(),
            lambda e: e["original_metadata"].pop(),
            lambda e: e["original_metadata"][0].update(digest="sha256:" + "0" * 64),
            lambda e: e["original_metadata"][0].update(expired=False),
            lambda e: e["original_metadata"][0].update(expired=1),
            lambda e: e["original_metadata"][0].update(expires_at="2026-09-25T20:00:00Z"),
            lambda e: e["retained_before"][0].update(expired=True),
            lambda e: e["retained_before"][0].update(expired=0),
            lambda e: e["retained_after"][0].update(size_in_bytes=1),
            lambda e: e["retained_after"][1]["workflow_run"].update(id=1),
            lambda e: e["retained_after"].reverse(),
        ]
        for index, mutation in enumerate(mutations):
            changed = copy.deepcopy(envelope)
            mutation(changed)
            with self.subTest(mutation=index):
                self.reject(self.v.verify_retained_origin, self.manifest, record, changed, "fixture", "fixture")

    def receipt_fixture(self):
        record, origin_input = self.origin_fixture()
        origin = self.v.verify_retained_origin(self.manifest, record, origin_input, "fixture", "fixture")
        context = {"controller_sha": "a" * 40, "controller_ref": "refs/tags/v0.2.7-recover.3", "controller_tag_object": "b" * 40,
                   "run_id": 40000000000, "run_attempt": 2, "producer_job_id": 110000000000, "checked_at": "2026-09-24T22:10:00Z",
                   "checker_sha256": "c" * 64, "runtime_versions": {"python": "3.13.7", "node": "24.15.0", "npm": "11.12.1", "gh": "2.80.0"},
                   "dry_run": True}
        bindings = self.v.retained_receipt_bindings(self.manifest, record, context, origin)
        publications = self.v.load_publications(self.manifest, PUBLICATIONS)
        receipts = {
            "custody-receipt.json": {"schema": "exochain-retained-custody-receipt-027/v1", **bindings,
                "results": {"payload_files_verified": 40, "retained_archives_verified": 2, "original_zip_envelopes_verified": 0,
                            "native_attestations_verified": 2, "native_libraries_per_archive": 29,
                            "product_signature_verified": True, "retaining_signature_verified": True, "controller_signature_verified": True}},
            "acceptance-receipt.json": {"schema": "exochain-retained-acceptance-receipt-027/v1", **bindings,
                "results": {"rust": {"crates_verified": 32, "checksum_verified": True, "version_verified": True, "unyanked_verified": True},
                            "publications": [{"id": p["id"], "package": p["package"], "version": p["version"], "file": p["file"],
                                              "source": p["source"], "public_bytes_verified": True, "crypto_verified": True} for p in publications["publications"]]}}}
        current_run = copy.deepcopy(origin_input["retaining_run"])
        current_run.update(id=context["run_id"], run_attempt=2, head_sha=context["controller_sha"], head_branch="v0.2.7-recover.3", status="in_progress", conclusion=None)
        producer = {"id": context["producer_job_id"], "name": self.v.RECEIPT_JOB, "run_id": context["run_id"], "run_attempt": 2,
                    "head_sha": context["controller_sha"], "head_branch": "v0.2.7-recover.3", "status": "completed", "conclusion": "success",
                    "started_at": "2026-09-24T22:00:00Z", "completed_at": "2026-09-24T22:11:00Z",
                    "steps": [{"name": self.v.RECEIPT_UPLOAD, "number": 8, "status": "completed", "conclusion": "success",
                               "started_at": "2026-09-24T22:10:01Z", "completed_at": "2026-09-24T22:10:03Z"}]}
        metadata = copy.deepcopy(record["custody"]["metadata"])
        metadata.update(id=12000000000, name=self.v.RECEIPT_ARTIFACT, created_at="2026-09-24T22:10:02Z", updated_at="2026-09-24T22:10:02Z",
                        expires_at="2026-10-24T22:10:02Z", workflow_run={"id": context["run_id"], "repository_id": 1116455646,
                            "head_repository_id": 1116455646, "head_sha": context["controller_sha"], "head_branch": "v0.2.7-recover.3"},
                        url="https://api.github.com/repos/exochain/exochain/actions/artifacts/12000000000",
                        archive_download_url="https://api.github.com/repos/exochain/exochain/actions/artifacts/12000000000/zip")
        envelope = {"schema": "exochain-retained-receipts-input-027/v1", "origin": origin_input, "context": context,
                    "current_run": current_run, "current_jobs": {"total_count": 1, "jobs": [producer]},
                    "upload_outputs": {"artifact_id": 12000000000, "artifact_digest": "", "producer_job_id": context["producer_job_id"]},
                    "metadata_before": metadata, "metadata_after": copy.deepcopy(metadata), "members": []}
        receipts["custody-receipt.json"]["results"]["native_attestations"] = [
            {"lane": artifact["lane"], "file": artifact["files"][0], "repository": "exochain/exochain",
             "source": {"commit": PRODUCT_SHA, "ref": "refs/tags/v0.2.7"},
             "signer_workflow": "exochain/exochain/.github/workflows/release.yml", "signer_digest": PRODUCT_SHA,
             "invocation": self.manifest["origin"]["native_attestation_invocation"], "crypto_verified": True}
            for artifact in self.manifest["artifacts"] if artifact["lane"].startswith("native-")]
        return record, publications, envelope, receipts

    def test_receipt_bindings_reject_each_wrong_pinned_runtime(self):
        record, _, envelope, _ = self.receipt_fixture()
        origin = self.v.verify_retained_origin(self.manifest, record, envelope["origin"], "fixture", "fixture")
        for runtime, value in (("python", "3.14.0"), ("node", "24.15.1"), ("npm", "11.12.0")):
            context = copy.deepcopy(envelope["context"])
            context["runtime_versions"][runtime] = value
            with self.subTest(runtime=runtime):
                self.reject(self.v.retained_receipt_bindings, self.manifest, record, context, origin)

    def test_receipt_predownload_profile_does_not_invent_after_observation(self):
        self.assertTrue(callable(getattr(self.v,'retained_receipt_profile',None)), 'pre-download provenance API absent')
        record, publications, envelope, receipts = self.receipt_fixture()
        path = self.write_receipt_fixture(envelope, receipts)
        before = copy.deepcopy(envelope); before.pop('metadata_after')
        bindings, profile = self.v.retained_receipt_profile(self.manifest,record,publications,before,'fixture','fixture')
        self.assertEqual(profile['zip_size'],path.stat().st_size)
        self.assertNotIn('receipts_verified',bindings)
        self.reject(self.v.verify_retained_receipts,self.manifest,record,publications,before,'fixture','fixture',path)
        for key,value in [('size_in_bytes',1048577),('id',1),('archive_download_url','https://attacker.invalid/receipt'),('digest','sha256:'+'e'*64)]:
            changed=copy.deepcopy(before); changed['metadata_before'][key]=value
            self.reject(self.v.retained_receipt_profile,self.manifest,record,publications,changed,'fixture','fixture')

    def write_receipt_fixture(self, envelope, receipts):
        class NonSeekable(io.BytesIO):
            def seek(self, *args):
                raise OSError("streaming fixture")
        buffer = NonSeekable()
        members = []
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, receipt in receipts.items():
                data = json.dumps(receipt, sort_keys=True).encode()
                info = zipfile.ZipInfo(name)
                info.create_system = 3; info.create_version = 45; info.extract_version = 20
                info.external_attr = 0o100600 << 16 | 32; info.compress_type = 8
                archive.writestr(info, data)
                members.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        data = buffer.getvalue()
        path = self.root / "receipt.zip"
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        envelope["upload_outputs"]["artifact_digest"] = digest
        for key in ("metadata_before", "metadata_after"):
            envelope[key].update(digest="sha256:" + digest, size_in_bytes=len(data))
        envelope["members"] = members
        return path

    def v2_receipt_fixture(self):
        record, publications, envelope, old_receipts = self.receipt_fixture()
        _, origin = self.origin_v2_fixture((10518086890,))
        origin["controls_before"]["observed_at"] = "2026-09-25T22:00:01Z"
        policy = self.metadata_policy_fixture()
        verified = self.v.verify_retained_origin(self.manifest, record, origin, "fixture", "fixture", policy=policy)
        context = envelope["context"]
        context["checked_at"] = "2026-09-25T22:02:00Z"
        producer = envelope["current_jobs"]["jobs"][0]
        producer["started_at"] = "2026-09-25T22:00:00Z"
        producer["completed_at"] = "2026-09-25T22:03:30Z"
        producer["steps"] = [
            {"name": "Verify Retained Custody, Publications and GitHub Inventory", "number": 7,
             "status": "completed", "conclusion": "success", "started_at": "2026-09-25T22:00:01Z", "completed_at": "2026-09-25T22:02:01Z"},
            {"name": self.v.RECEIPT_UPLOAD, "number": 8, "status": "completed", "conclusion": "success",
             "started_at": "2026-09-25T22:02:02Z", "completed_at": "2026-09-25T22:03:00Z"}]
        metadata = envelope["metadata_before"]
        metadata["created_at"] = metadata["updated_at"] = "2026-09-25T22:02:30Z"
        metadata["expires_at"] = "2026-10-25T22:02:30Z"
        envelope["metadata_after"] = copy.deepcopy(metadata)
        envelope["schema"] = "exochain-retained-receipts-input-027/v2"
        envelope["operation"] = "recover-0.2.7-retained-404"
        envelope["policy_sha256"] = self.v.RETAINED_METADATA_POLICY_SHA256
        envelope["observed_at"] = "2026-09-25T22:03:31Z"
        envelope["origin"] = origin
        bindings = {"mode": "recover-0.2.7-retained-404", **context, "checker_version": "retained-027/v2",
                    "retained_record_sha256": self.v.RETAINED_RECORD_SHA256,
                    "metadata_policy_sha256": self.v.RETAINED_METADATA_POLICY_SHA256,
                    "manifest_sha256": self.v.MANIFEST_SHA256, "publications_sha256": self.v.PUBLICATIONS_SHA256,
                    "product": self.manifest["product"], "historical_original_origin": verified["historical_original_origin"],
                    "original_vector": verified["original_vector"],
                    "transports": [{"id": record[k]["metadata"]["id"], "digest": record[k]["metadata"]["digest"]}
                                   for k in ("payload", "custody")], "mutation_attempted": False}
        receipts = {}
        for kind in ("custody", "acceptance"):
            old = old_receipts[f"{kind}-receipt.json"]
            receipts[f"{kind}-receipt.json"] = {"schema": f"exochain-retained-{kind}-receipt-027/v2", **bindings,
                                                 "original_observations": origin["observations"],
                                                 "results": old["results"]}
        return record, publications, policy, envelope, receipts

    def writer_origin_fixture(self, envelope):
        """A separate successful writer read with the same status/identity vector."""
        writer = copy.deepcopy(envelope["origin"])
        producer = envelope["current_jobs"]["jobs"][0]
        writer_job = {**copy.deepcopy(producer), "id": 110000000001, "name": self.v.RECEIPT_WRITER_JOB,
                      "status": "in_progress", "conclusion": None, "started_at": "2026-09-25T22:04:00Z",
                      "completed_at": None, "steps": []}
        if not any(job["id"] == writer_job["id"] for job in envelope["current_jobs"]["jobs"]):
            envelope["current_jobs"]["jobs"].append(writer_job)
            envelope["current_jobs"]["total_count"] = 2
        observations = writer["observations"]
        observations["observer"].update(job_id=110000000001, job_name=self.v.RECEIPT_WRITER_JOB,
                                        job_started_at="2026-09-25T22:04:00Z")
        for phase, base, observed in (("before", 0, "2026-09-25T22:05:20Z"),
                                      ("after", 21, "2026-09-25T22:05:40Z")):
            passage = observations[phase]
            passage["observed_at"] = observed
            for index, item in enumerate(passage["records"]):
                second = base + index * (2 if phase == "before" else 1)
                item["request_started_at"] = f"2026-09-25T22:05:{second:02d}Z"
                item["request_finished_at"] = f"2026-09-25T22:05:{second + 1:02d}Z"
        writer["controls_before"]["observed_at"] = "2026-09-25T22:04:59Z"
        writer["controls_after"]["observed_at"] = "2026-09-25T22:05:41Z"
        return writer

    def test_full_v2_accepts_independent_writer_origin_and_rejects_cross_job_transition(self):
        record, publications, policy, envelope, receipts = self.v2_receipt_fixture()
        producer_observations = copy.deepcopy(receipts["custody-receipt.json"]["original_observations"])
        writer = self.writer_origin_fixture(envelope)
        envelope["origin"] = writer
        envelope["observed_at"] = "2026-09-25T22:06:00Z"
        historical = self.v.read_historical_custody(self.manifest, record, "fixture")
        producer_vector = self.v.validate_original_observations(
            self.manifest, record, policy, historical, producer_observations, now="2026-09-25T22:02:00Z")
        writer_vector = self.v.verify_retained_origin(self.manifest, record, writer, "fixture", "fixture", policy=policy)["original_vector"]
        self.assertEqual(producer_vector, writer_vector)
        self.assertNotEqual(producer_observations, writer["observations"])
        path = self.write_receipt_fixture(envelope, receipts)
        result = self.v.verify_retained_receipts(self.manifest, record, publications, envelope,
                                                 "fixture", "fixture", path, policy=policy)
        self.assertEqual(result["original_vector"], writer_vector)
        premature_final = copy.deepcopy(envelope)
        premature_final["observed_at"] = "2026-09-25T22:05:40Z"
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, record, publications, premature_final,
                                            "fixture", "fixture", path, policy=policy)
        for field, wrong in (("run_id", 40000000001), ("run_attempt", 3),
                             ("controller_sha", "d" * 40), ("controller_ref", "refs/tags/v0.2.7-recover.4"),
                             ("controller_tag_object", "e" * 40)):
            changed_identity = copy.deepcopy(envelope)
            changed_identity["origin"]["observations"]["observer"][field] = wrong
            with self.subTest(writer_field=field):
                with self.assertRaises(self.v.RecoveryError):
                    self.v.verify_retained_receipts(self.manifest, record, publications, changed_identity,
                                                    "fixture", "fixture", path, policy=policy)
        changed = copy.deepcopy(envelope)
        changed["origin"] = self.writer_origin_fixture(envelope)
        for phase in ("before", "after"):
            target = next(x for x in changed["origin"]["observations"][phase]["records"] if x["id"] == 10518086890)
            target["status"] = 200
            target["variant"] = "present"
            target["metadata"] = copy.deepcopy(next(x for x in historical["metadata"] if x["id"] == 10518086890))
            target["metadata"]["expired"] = True
        changed_vector = self.v.verify_retained_origin(self.manifest, record, changed["origin"],
                                                       "fixture", "fixture", policy=policy)["original_vector"]
        self.assertNotEqual(producer_vector, changed_vector)
        with self.assertRaisesRegex(self.v.RecoveryError, "producer/writer original vector"):
            self.v.verify_retained_receipts(self.manifest, record, publications, changed,
                                            "fixture", "fixture", path, policy=policy)

    def test_full_v2_rejects_producer_raw_time_tampering_with_same_vector(self):
        record, publications, policy, envelope, receipts = self.v2_receipt_fixture()
        envelope["origin"] = self.writer_origin_fixture(envelope)
        envelope["observed_at"] = "2026-09-25T22:06:00Z"
        historical = self.v.read_historical_custody(self.manifest, record, "fixture")
        original_vector = self.v.validate_original_observations(
            self.manifest, record, policy, historical, receipts["custody-receipt.json"]["original_observations"],
            now="2026-09-25T22:02:00Z")
        for member in receipts.values():
            member["original_observations"]["before"]["records"][0]["request_started_at"] = "2026-09-25T22:00:00Z"
        tampered_vector = self.v.validate_original_observations(
            self.manifest, record, policy, historical, receipts["custody-receipt.json"]["original_observations"],
            now="2026-09-25T22:02:00Z")
        self.assertEqual(original_vector, tampered_vector)
        path = self.write_receipt_fixture(envelope, receipts)
        with self.assertRaisesRegex(self.v.RecoveryError, "outside import/check interval"):
            self.v.verify_retained_receipts(self.manifest, record, publications, envelope,
                                            "fixture", "fixture", path, policy=policy)

    def test_preliminary_receipt_profile_rejects_replay_without_historical_origin(self):
        record, publications, policy, envelope, receipts = self.v2_receipt_fixture()
        path = self.write_receipt_fixture(envelope, receipts)
        preliminary = copy.deepcopy(envelope)
        preliminary.pop("origin")
        preliminary.pop("metadata_after")
        result = self.v.retained_receipt_provenance(self.manifest, record, policy, preliminary)
        self.assertEqual(set(result), {"profile", "context", "upload_outputs", "observed_at"})
        self.assertEqual(result["profile"]["zip_sha256"], envelope["upload_outputs"]["artifact_digest"])
        self.assertNotIn("acceptance_verified", result)
        self.assertEqual(result["profile"]["zip_size"], path.stat().st_size)
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, record, publications, preliminary,
                                            "fixture", "fixture", path, policy=policy)
        for mutation in (lambda e: e.update(operation="recover-0.2.7-retained"),
                         lambda e: e.update(policy_sha256="0" * 64),
                         lambda e: e["context"].update(run_attempt=1),
                         lambda e: e["context"].update(run_id=35257955565),
                         lambda e: e["context"].update(controller_sha=PRODUCT_SHA),
                         lambda e: e["context"].update(controller_ref=self.v.RETAINED_REF),
                         lambda e: e["context"].update(controller_tag_object="wrong"),
                         lambda e: e["current_run"].update(run_attempt=1),
                         lambda e: e["current_jobs"].update(total_count=2),
                         lambda e: e["current_jobs"]["jobs"][0].update(run_attempt=1),
                         lambda e: e["current_jobs"]["jobs"][0].update(conclusion="failure"),
                         lambda e: e["current_jobs"]["jobs"][0]["steps"][0].update(conclusion="failure"),
                         lambda e: e["current_jobs"]["jobs"][0]["steps"][1].update(conclusion="failure"),
                         lambda e: e["metadata_before"].update(expired=True),
                         lambda e: e["metadata_before"].update(size_in_bytes=1048577),
                         lambda e: e["metadata_before"].update(digest="sha256:" + "0" * 64),
                         lambda e: e["metadata_before"].update(expires_at="2026-09-25T22:03:31Z"),
                         lambda e: e["upload_outputs"].update(artifact_id=1),
                         lambda e: e["upload_outputs"].pop("artifact_id"),
                         lambda e: e["members"][0].update(sha256="wrong"),
                         lambda e: e.update(observed_at="2026-10-25T22:02:30Z")):
            changed = copy.deepcopy(preliminary)
            mutation(changed)
            with self.subTest(mutation=mutation):
                with self.assertRaises(self.v.RecoveryError):
                    self.v.retained_receipt_provenance(self.manifest, record, policy, changed)

    def test_preliminary_receipt_provenance_enforces_each_chronology_inequality(self):
        record, _, policy, envelope, receipts = self.v2_receipt_fixture()
        self.write_receipt_fixture(envelope, receipts)
        preliminary = copy.deepcopy(envelope)
        preliminary.pop("origin")
        preliminary.pop("metadata_after")
        self.assertEqual(set(self.v.retained_receipt_provenance(self.manifest, record, policy, preliminary)),
                         {"profile", "context", "upload_outputs", "observed_at"})

        # Each case crosses one neighboring boundary in the required chronology.
        negative = (
            ("producer_start_after_import_start", lambda e: e["current_jobs"]["jobs"][0].update(started_at="2026-09-25T22:00:02Z")),
            ("checked_before_import_start", lambda e: e["context"].update(checked_at="2026-09-25T22:00:00Z")),
            ("checked_after_import_end", lambda e: e["context"].update(checked_at="2026-09-25T22:02:02Z")),
            ("import_end_after_upload_start", lambda e: e["current_jobs"]["jobs"][0]["steps"][0].update(completed_at="2026-09-25T22:02:03Z")),
            ("upload_start_after_upload_end", lambda e: e["current_jobs"]["jobs"][0]["steps"][1].update(started_at="2026-09-25T22:03:01Z")),
            ("producer_end_before_upload_end", lambda e: e["current_jobs"]["jobs"][0].update(completed_at="2026-09-25T22:02:59Z")),
            ("observed_before_producer_end", lambda e: e.update(observed_at="2026-09-25T22:03:29Z")),
        )
        for label, mutate in negative:
            changed = copy.deepcopy(preliminary)
            mutate(changed)
            with self.subTest(negative=label):
                with self.assertRaisesRegex(self.v.RecoveryError, "current producer/import/upload chronology differs"):
                    self.v.retained_receipt_provenance(self.manifest, record, policy, changed)

        equality = (
            ("producer_start_equals_import_start", lambda e: e["current_jobs"]["jobs"][0].update(started_at="2026-09-25T22:00:01Z")),
            ("checked_equals_import_start", lambda e: e["context"].update(checked_at="2026-09-25T22:00:01Z")),
            ("checked_equals_import_end", lambda e: e["context"].update(checked_at="2026-09-25T22:02:01Z")),
            ("import_end_equals_upload_start", lambda e: e["current_jobs"]["jobs"][0]["steps"][0].update(completed_at="2026-09-25T22:02:02Z")),
            ("upload_start_equals_upload_end", lambda e: e["current_jobs"]["jobs"][0]["steps"][1].update(started_at="2026-09-25T22:02:30Z", completed_at="2026-09-25T22:02:30Z")),
            ("upload_end_equals_producer_end", lambda e: e["current_jobs"]["jobs"][0]["steps"][1].update(completed_at="2026-09-25T22:03:30Z")),
            ("producer_end_equals_observed", lambda e: e.update(observed_at="2026-09-25T22:03:30Z")),
        )
        for label, mutate in equality:
            changed = copy.deepcopy(preliminary)
            mutate(changed)
            with self.subTest(equality=label):
                self.assertEqual(self.v.retained_receipt_provenance(self.manifest, record, policy, changed)["observed_at"],
                                 changed["observed_at"])

    def test_v2_receipts_bind_policy_operation_vector_and_raw_observations(self):
        record, publications, policy, envelope, receipts = self.v2_receipt_fixture()
        path = self.write_receipt_fixture(envelope, receipts)
        result = self.v.verify_retained_receipts(self.manifest, record, publications, envelope,
                                                 "fixture", "fixture", path, policy=policy)
        custody_receipt, acceptance_receipt = receipts.values()
        self.assertEqual(custody_receipt["checker_version"], "retained-027/v2")
        self.assertEqual(custody_receipt["mode"], "recover-0.2.7-retained-404")
        self.assertEqual(custody_receipt["original_observations"], acceptance_receipt["original_observations"])
        self.assertEqual(custody_receipt["original_vector"], result["original_vector"])
        last_observation_finish = max(x["request_finished_at"] for x in envelope["origin"]["observations"]["after"]["records"])
        self.assertLessEqual(last_observation_finish, envelope["context"]["checked_at"])
        self.assertLessEqual(envelope["context"]["checked_at"], envelope["current_jobs"]["jobs"][0]["steps"][1]["started_at"])
        for mutation in (lambda e: e.update(origin=None),
                         lambda e: e["origin"]["observations"]["after"]["records"][0].update(request_started_at="2026-09-25T21:59:59Z"),
                         lambda e: e["origin"]["observations"]["after"]["records"][0].update(request_started_at="2026-09-25T22:02:02Z"),
                         lambda e: e["origin"]["observations"]["observer"].update(job_id=1),
                         lambda e: e["metadata_after"].update(expired=True),
                         lambda e: e.update(observed_at="2026-10-25T22:02:30Z")):
            changed = copy.deepcopy(envelope)
            mutation(changed)
            with self.subTest(mutation=mutation):
                with self.assertRaises(self.v.RecoveryError):
                    self.v.verify_retained_receipts(self.manifest, record, publications, changed,
                                                    "fixture", "fixture", path, policy=policy)
        changed_receipts = copy.deepcopy(receipts)
        changed_receipts["custody-receipt.json"]["original_observations"]["after"]["records"][0]["request_finished_at"] = "2026-09-25T22:01:59Z"
        changed = copy.deepcopy(envelope)
        bad_path = self.write_receipt_fixture(changed, changed_receipts)
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, record, publications, changed, "fixture", "fixture", bad_path, policy=policy)
        for mutation in (lambda r: r["custody-receipt.json"].update(checker_version="retained-027/v1"),
                         lambda r: r["acceptance-receipt.json"].update(metadata_policy_sha256="0" * 64),
                         lambda r: r["custody-receipt.json"]["results"].update(controller_signature_verified=False),
                         lambda r: r["acceptance-receipt.json"]["results"]["publications"][0].update(crypto_verified=False),
                         lambda r: r["custody-receipt.json"].pop("original_observations")):
            modified = copy.deepcopy(receipts)
            mutation(modified)
            changed = copy.deepcopy(envelope)
            bad_path = self.write_receipt_fixture(changed, modified)
            with self.subTest(mutation=mutation):
                with self.assertRaises(self.v.RecoveryError):
                    self.v.verify_retained_receipts(self.manifest, record, publications, changed, "fixture", "fixture", bad_path, policy=policy)
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, record, publications, envelope,
                                            "fixture", "fixture", path)
        old_record, old_publications, old_envelope, old_receipts = self.receipt_fixture()
        old_path = self.write_receipt_fixture(old_envelope, old_receipts)
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, old_record, old_publications, old_envelope,
                                            "fixture", "fixture", old_path, policy=policy)
        corrupted = copy.deepcopy(envelope)
        malformed_path = self.root / "malformed-receipt.zip"
        malformed_path.write_bytes(b"not a receipt ZIP")
        with self.assertRaises(self.v.RecoveryError):
            self.v.verify_retained_receipts(self.manifest, record, publications, corrupted,
                                            "fixture", "fixture", malformed_path, policy=policy)

    def test_current_receipts_require_direct_upload_same_attempt_and_complete_current_acceptance(self):
        record, publications, envelope, receipts = self.receipt_fixture()
        path = self.write_receipt_fixture(envelope, receipts)
        result = self.v.verify_retained_receipts(self.manifest, record, publications, envelope, "fixture", "fixture", path)
        self.assertEqual(result["receipts_verified"], 2)
        self.assertEqual(result["run_attempt"], 2)
        self.assertFalse(result["independent_crypto_verification_performed"])
        mutations = [
            lambda e: e["context"].update(run_attempt=1),
            lambda e: e["context"].update(run_attempt=True),
            lambda e: e["context"].update(run_id=True),
            lambda e: e["context"].update(producer_job_id=True),
            lambda e: e["context"].update(dry_run=1),
            lambda e: e["context"].update(controller_sha=PRODUCT_SHA),
            lambda e: e["context"].update(controller_ref=self.v.RETAINED_REF),
            lambda e: e["context"].update(dry_run=False),
            lambda e: e["context"].update(producer_job_id="retained-acceptance"),
            lambda e: e["upload_outputs"].update(artifact_id=999),
            lambda e: e["upload_outputs"].update(artifact_digest="0" * 64),
            lambda e: e["upload_outputs"].update(producer_job_id=999),
            lambda e: e["current_jobs"]["jobs"][0].update(run_attempt=1),
            lambda e: e["current_jobs"]["jobs"][0].update(status="in_progress"),
            lambda e: e["current_jobs"]["jobs"][0].update(conclusion="failure"),
            lambda e: e["current_jobs"]["jobs"][0]["steps"][0].update(conclusion="failure"),
            lambda e: e["current_jobs"]["jobs"][0]["steps"][0].update(name="earlier upload"),
            lambda e: e["current_jobs"].update(total_count=2),
            lambda e: e["metadata_after"].update(expired=True),
            lambda e: e["metadata_after"].update(expired=0),
            lambda e: e["metadata_before"]["workflow_run"].update(id=1),
            lambda e: e["members"].pop(),
        ]
        for index, mutation in enumerate(mutations):
            changed = copy.deepcopy(envelope)
            mutation(changed)
            with self.subTest(mutation=index):
                self.reject(self.v.verify_retained_receipts, self.manifest, record, publications, changed, "fixture", "fixture", path)
        # Even self-asserted current-attempt JSON cannot redeem an old artifact.
        old = copy.deepcopy(envelope)
        for key in ("metadata_before", "metadata_after"):
            old[key].update(created_at="2026-09-24T21:10:02Z", updated_at="2026-09-24T21:10:02Z")
        self.reject(self.v.verify_retained_receipts, self.manifest, record, publications, old, "fixture", "fixture", path)

    def test_current_receipts_reject_repacked_forged_success_or_missing_crypto(self):
        record, publications, envelope, receipts = self.receipt_fixture()
        mutations = [
            lambda r: r["custody-receipt.json"].update(run_attempt=1),
            lambda r: r["custody-receipt.json"].update(mutation_attempted=True),
            lambda r: r["custody-receipt.json"].update(controller_tag_object="f" * 40),
            lambda r: r["custody-receipt.json"]["results"].update(native_attestations_verified=0),
            lambda r: r["custody-receipt.json"]["results"].update(controller_signature_verified=1),
            lambda r: r["acceptance-receipt.json"]["results"]["publications"].pop(),
            lambda r: r["acceptance-receipt.json"]["results"]["publications"][0].update(crypto_verified=False),
            lambda r: r["acceptance-receipt.json"]["results"]["publications"][0]["source"].update(commit="0" * 40),
            lambda r: r["acceptance-receipt.json"]["results"]["rust"].update(crates_verified=31),
            lambda r: r["acceptance-receipt.json"].update(extra="untrusted"),
        ]
        for index in range(5):
            mutations.append(lambda r, i=index: r["acceptance-receipt.json"]["results"]["publications"].pop(i))
            mutations.append(lambda r, i=index: r["acceptance-receipt.json"]["results"]["publications"][i].update(crypto_verified=False))
        for key in receipts["custody-receipt.json"]["results"]:
            mutations.append(lambda r, k=key: r["custody-receipt.json"]["results"].pop(k))
        for index in range(2):
            mutations.append(lambda r, i=index: r["custody-receipt.json"]["results"]["native_attestations"].pop(i))
            for key, value in (("crypto_verified", False), ("signer_digest", "0" * 40), ("invocation", "wrong")):
                mutations.append(lambda r, i=index, k=key, v=value: r["custody-receipt.json"]["results"]["native_attestations"][i].update({k: v}))
        for index, mutation in enumerate(mutations):
            modified = copy.deepcopy(receipts)
            mutation(modified)
            changed = copy.deepcopy(envelope)
            path = self.write_receipt_fixture(changed, modified)
            with self.subTest(mutation=index):
                self.reject(self.v.verify_retained_receipts, self.manifest, record, publications, changed, "fixture", "fixture", path)

    def test_actual_transport_extracts_only_after_all_checks_and_preserves_disk_floor(self):
        audit = os.environ.get("EXO_RETAINED_AUDIT_DIR")
        if not audit:
            self.skipTest("actual-byte extraction requires explicit read-only audit evidence directory")
        record = self.record()
        archives = self.root / "archives"
        archives.mkdir()
        for artifact_id in (10779404529, 10780480598):
            shutil.copyfile(Path(audit) / f"{artifact_id}.zip", archives / f"{artifact_id}.zip")
        destination = self.root / "output"
        floor = mock.Mock(f_bavail=1, f_frsize=4096)
        with mock.patch.object(self.v.os, "fstatvfs", return_value=floor):
            self.reject(self.v.verify_retained_transport, self.manifest, record, archives, destination)
        self.assertFalse(destination.exists())
        validator = self.v.strict_zip_stream
        def changed_during_extraction(stream, profile, destination=None, collect=False):
            if destination is not None:
                raise self.v.RecoveryError("fixture changed descriptor after initial validation")
            return validator(stream, profile, destination, collect)
        with mock.patch.object(self.v, "strict_zip_stream", side_effect=changed_during_extraction):
            self.reject(self.v.verify_retained_transport, self.manifest, record, archives, destination)
        self.assertFalse(destination.exists())
        self.assertFalse(any(p.name.startswith(".retained-027-") for p in self.root.iterdir()))
        result = self.v.verify_retained_transport(self.manifest, record, archives, destination)
        self.assertEqual(result["original_zip_envelopes_verified"], 0)
        self.assertEqual(self.v.verify_files(self.manifest, destination)["files_verified"], 40)
        self.reject(self.v.verify_retained_transport, self.manifest, record, archives, destination)
        corrupted = archives / "10780480598.zip"
        corrupted.write_bytes(b"corrupt")
        destination2 = self.root / "rejected"
        self.reject(self.v.verify_retained_transport, self.manifest, record, archives, destination2)
        self.assertFalse(destination2.exists())

    def test_actual_retained_origin_with_explicit_current_provider_snapshot(self):
        names = ("EXO_RETAINED_AUDIT_DIR", "EXO_RETAINED_CURRENT_DIR", "EXO_RETAINED_ATTEMPT_DIR", "EXO_RETAINED_OBSERVED_AT")
        if not all(os.environ.get(name) for name in names):
            self.skipTest("actual origin check requires explicitly captured provider snapshot and observation time")
        audit, current, attempt = (Path(os.environ[name]) for name in names[:3])
        read = lambda path: self.v.load_json(path, "actual provider snapshot")
        record = self.record()
        ref, tag = read(current / "retaining-tag-ref.json"), read(current / "retaining-tag-object.json")
        self.assertEqual(ref["object"]["sha"], tag["sha"])
        envelope = {"schema": "exochain-retained-origin-input-027/v1", "observed_at": os.environ[names[3]],
                    "retaining_run": read(attempt / "run-attempt-1.json"), "retaining_jobs": read(attempt / "jobs-attempt-1-complete.json"),
                    "retaining_tag": {"object": tag["sha"], "commit": tag["object"]["sha"], "ref": ref["ref"]},
                    "original_run": read(current / "original-run-attempt-1.json"),
                    "original_jobs": read(current / "original-jobs-attempt-1-complete.json"),
                    "original_metadata": [read(current / "original-artifact-metadata" / f"{a['id']}.json") for a in self.manifest["artifacts"] + self.manifest["rust_preparation"]],
                    "retained_before": [read(audit / f"{a}-metadata-before.json") for a in (10779404529, 10780480598)],
                    "retained_after": [read(current / "retained-artifact-metadata" / f"{a}.json") for a in (10779404529, 10780480598)]}
        result = self.v.verify_retained_origin(self.manifest, record, envelope, audit / "10780480598.zip", current / "retaining-release-workflow.yml")
        self.assertEqual(sum(item["expired"] for item in result["original_expiry"]), 4)
        self.assertFalse(result["current_crypto_verified"])
        self.reject(self.v.verify_origin, self.manifest, envelope["original_run"], envelope["original_jobs"], envelope["original_metadata"])
        input_path = self.root / "origin-input.json"
        input_path.write_text(json.dumps(envelope))
        cli = subprocess.run([sys.executable, "-B", str(HELPER), "retained-origin", "--manifest", str(MANIFEST), "--record", str(self.record_path),
                              "--input", str(input_path), "--evidence", str(audit / "10780480598.zip"),
                              "--retaining-workflow", str(current / "retaining-release-workflow.yml")], capture_output=True, text=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout), result)


if __name__ == "__main__":
    unittest.main()
