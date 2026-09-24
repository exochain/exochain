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


if __name__ == "__main__":
    unittest.main()
