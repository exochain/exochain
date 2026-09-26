#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Offline validation of the one reviewed EXOCHAIN 0.2.7 recovery inventory.

Provider response files are data, never commands or endpoint configuration.
The caller obtains them from fixed authoritative endpoints before using this
validator. This module neither acquires credentials nor performs network I/O.
Inner npm, Python and native archives remain opaque to this custody boundary;
the canonical package/provenance validators must also accept them.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile
import struct
import shutil
import zlib
from datetime import datetime, timezone

PRODUCT_COMMIT = "666c578f719d1e54fce95d6831a3af92ea80df93"
PRODUCT_TAG_OBJECT = "be47589ec7dbefe821ada35ed0a89dedc9751953"
RUN_ID = 35257955565
REPOSITORY_ID = 1116455646
WORKFLOW_ID = 248228578
# Semantic digest of the reviewed owned manifest, not a provider response.
# Pinning it prevents a caller from substituting otherwise well-formed hashes,
# producer mappings, package names or endpoints while retaining the fixed tag.
MANIFEST_SHA256 = "17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4"
PUBLICATIONS_SHA256 = "4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7"
PUBLICATION_IDS = ("wasm", "llm", "sdk", "python-wheel", "python-sdist")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ZIP_BYTES = 96 * 1024 * 1024
MAX_TOTAL_BYTES = 192 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
LANES = ("npm-wasm", "npm-llm", "npm-sdk", "python", "sbom", "native-x86_64", "native-aarch64")
RETAINED_RECORD_SHA256 = "7f2eac05d0fea00a29a1ea3ebf7605eee7ab66905a40d8e016ef50510c2c038a"
RETAINED_METADATA_POLICY_SHA256 = "bf9968454e1fb95fde2b2c435f61940a39cc25e6fb45a28ff9523a82f755c244"
RETAINED_METADATA_OPERATION = "recover-0.2.7-retained-404"
RETAINED_RUN_ID = 35754493083
RETAINED_COMMIT = "2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1"
RETAINED_REF = "refs/tags/v0.2.7-recover.2"
RETAINED_MAX_BYTES = 147126946
DISK_FLOOR_BYTES = 4 * 1024**3
RECEIPT_MAX_BYTES = 1024 * 1024
RECEIPT_JOB = "Verify Retained 0.2.7 Custody and Publications"
RECEIPT_WRITER_JOB = "Complete Retained 0.2.7 GitHub Release"
RECEIPT_UPLOAD = "Upload Current Retained Acceptance Receipt"
RECEIPT_IMPORT = "Verify Retained Custody, Publications and GitHub Inventory"
RECEIPT_ARTIFACT = "exochain-027-retained-acceptance-receipt"
EMPTY_HISTORICAL = ("npm-llm-tarball-check.txt", "npm-sdk-tarball-check.txt", "npm-wasm-tarball-check.txt", "python-artifact-check.json")


def semantic_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def timestamp(value, label):
    require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is not None, f"invalid {label} timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise RecoveryError(f"invalid {label} timestamp") from error


def validate_retained_record(manifest, record):
    validate_manifest(manifest)
    keys(record, ("schema", "mode", "manifest_sha256", "publications_sha256", "product", "retaining", "payload", "custody"), "retained record")
    exact(record["schema"], "exochain-retained-custody-027/v1", "retained schema")
    exact(record["mode"], "recover-0.2.7-retained", "retained mode")
    exact(record["manifest_sha256"], MANIFEST_SHA256, "retained manifest pin")
    exact(record["publications_sha256"], PUBLICATIONS_SHA256, "retained publication pin")
    exact(record["product"], manifest["product"], "retained product")
    # The independent semantic pin covers every nested key, type, timestamp,
    # inventory entry and producer step. It rejects extra nested fields too.
    exact(semantic_digest(record), RETAINED_RECORD_SHA256, "reviewed retained record digest")
    return record


def load_retained_record(manifest, path):
    return validate_retained_record(manifest, load_json(path, "retained custody record"))


def validate_retained_metadata_policy(manifest, record, policy):
    validate_retained_record(manifest, record)
    keys(policy, ("schema", "operation", "manifest_sha256", "publications_sha256", "retained_sha256",
                  "repository", "original", "retaining", "retained_artifact_ids", "unavailable_originals"), "retained metadata policy")
    exact(policy["schema"], "exochain-retained-metadata-policy-027/v1", "retained metadata policy schema")
    exact(policy["operation"], RETAINED_METADATA_OPERATION, "retained metadata operation")
    for name, expected in (("manifest_sha256", MANIFEST_SHA256), ("publications_sha256", PUBLICATIONS_SHA256),
                           ("retained_sha256", RETAINED_RECORD_SHA256)):
        exact(policy[name], expected, "retained metadata " + name)
    exact(policy["repository"], {"name": "exochain/exochain", "id": REPOSITORY_ID, "owner_id": 129763194}, "policy repository")
    exact(policy["original"], {"run_id": RUN_ID, "attempt": 1}, "policy original run")
    exact(policy["retaining"], {"run_id": RETAINED_RUN_ID, "attempt": 1}, "policy retaining run")
    exact(policy["retained_artifact_ids"], [record[k]["metadata"]["id"] for k in ("payload", "custody")], "policy retained IDs")
    originals = policy["unavailable_originals"]
    require(type(originals) is list and len(originals) == 4, "policy unavailable inventory differs")
    exact([item.get("id") if type(item) is dict else None for item in originals],
          [10518086890, 10518128532, 10517978596, 10517854663], "policy unavailable IDs")
    custody_members = {item["path"]: item["sha256"] for item in record["custody"]["files"]}
    original_ids = {item["id"] for item in manifest["artifacts"] + manifest["rust_preparation"]}
    for item in originals:
        keys(item, ("id", "historical_member", "historical_sha256", "expires_at"), "policy original")
        positive_integer(item["id"], "policy original ID")
        require(item["id"] in original_ids, "policy original outside manifest")
        exact(item["historical_member"], f"artifact-metadata/{item['id']}.json", "policy historical member")
        exact(item["historical_sha256"], custody_members.get(item["historical_member"]), "policy custody member hash")
        timestamp(item["expires_at"], "policy original expiry")
    exact(semantic_digest(policy), RETAINED_METADATA_POLICY_SHA256, "reviewed retained metadata policy digest")
    return policy


def load_retained_metadata_policy(manifest, record, path):
    return validate_retained_metadata_policy(manifest, record, load_json(path, "retained metadata policy"))


def retained_profile(manifest, record, kind):
    validate_retained_record(manifest, record)
    require(kind in ("payload", "custody"), "unknown retained archive kind")
    artifact = record[kind]
    files = artifact["files"] if kind == "custody" else [
        dict(file, path=lane["lane"] + "/" + file["path"])
        for lane in manifest["artifacts"] for file in lane["files"]]
    return {"zip_size": artifact["metadata"]["size_in_bytes"],
            "zip_sha256": artifact["metadata"]["digest"].removeprefix("sha256:"),
            "compression": artifact["compression"], "mode": artifact["mode"],
            "dos_attributes": artifact["dos_attributes"],
            "expanded_bytes": artifact["expanded_bytes"], "files": files}


def strict_zip_stream(stream, profile, destination=None, collect=False):
    try:
        return _strict_zip_stream(stream, profile, destination, collect)
    except (OSError, UnicodeError, struct.error, zlib.error) as error:
        raise RecoveryError("retained ZIP structure or bounded stream is invalid") from error


def _strict_zip_stream(stream, profile, destination=None, collect=False):
    """Validate the observed streaming ZIP profile, including every descriptor.

    This lower-level parser also supports bounded current receipt transports.
    Callers must authenticate profile hashes before invoking it. It is never a
    CLI manifest override and it never substitutes the original manifest pin.
    """
    before = os.fstat(stream.fileno())
    exact(before.st_size, profile["zip_size"], "retained ZIP byte length")
    require(22 <= before.st_size <= RETAINED_MAX_BYTES, "retained ZIP exceeds separate byte bound")
    stream.seek(0)
    exact(hash_stream(stream, before.st_size, "retained ZIP"), profile["zip_sha256"], "retained ZIP digest")
    stream.seek(before.st_size - 22)
    end = struct.unpack("<4s4H2IH", stream.read(22))
    require(end[0] == b"PK\x05\x06" and end[1:3] == (0, 0) and end[3] == end[4] and end[7] == 0, "ZIP end record is ambiguous or multidisk")
    expected = {f["path"]: f for f in profile["files"]}
    require(0 < len(expected) <= 100 and len(expected) == len(profile["files"]) == end[4], "ZIP member count differs")
    exact(sum(f["size"] for f in expected.values()), profile["expanded_bytes"], "ZIP expansion bound")
    require(profile["expanded_bytes"] <= RETAINED_MAX_BYTES, "ZIP expansion exceeds bound")
    central_size, central_offset = end[5:7]
    exact(central_offset + central_size + 22, before.st_size, "complete ZIP boundaries")
    require(central_offset > 0 and central_size >= 46 * len(expected), "invalid central directory bounds")
    cursor = 0
    central_cursor = central_offset
    seen = set()
    collected = {}
    for _ in range(len(expected)):
        stream.seek(central_cursor)
        raw = stream.read(46)
        require(len(raw) == 46, "truncated central directory")
        central = struct.unpack("<4s6H3I5H2I", raw)
        sig, creator, version, flags, compression, mtime, mdate, crc, compressed, size, namesize, extrasize, commentsize, disk, internal, external, offset = central
        require(sig == b"PK\x01\x02" and creator == 3 * 256 + 45 and version == 20 and flags == 8, "unsupported central ZIP profile")
        require(compression == profile["compression"] and compression in (0, 8), "wrong retained ZIP compression")
        require(extrasize == commentsize == disk == internal == 0 and external == (profile["mode"] << 16 | profile["dos_attributes"]), "ZIP extra fields, comments or file type differ")
        require(0 < namesize <= 512 and compressed < 0xffffffff and size < 0xffffffff, "ZIP64 or oversized name is forbidden")
        name_bytes = stream.read(namesize)
        name = safe_name(name_bytes.decode("ascii"))
        require(name in expected and name not in seen, "ZIP member inventory differs or duplicates members")
        seen.add(name)
        file = expected[name]
        exact(size, file["size"], "ZIP expanded member size")
        exact(offset, cursor, "ZIP member records overlap or leave prefix/gaps")
        central_cursor += 46 + namesize
        require(central_cursor <= central_offset + central_size, "central directory overlaps archive end")
        stream.seek(cursor)
        local_raw = stream.read(30)
        require(len(local_raw) == 30, "truncated local header")
        local = struct.unpack("<4s5H3I2H", local_raw)
        exact(local, (b"PK\x03\x04", 20, 8, compression, mtime, mdate, 0, 0, 0, namesize, 0), "local header streaming placeholders")
        exact(stream.read(namesize), name_bytes, "local and central names")
        payload_start = cursor + 30 + namesize
        descriptor_start = payload_start + compressed
        require(descriptor_start + 16 <= central_offset, "payload or descriptor overlaps central directory")
        if compression == 0:
            exact(compressed, size, "stored member size")
        remaining = compressed
        digest = hashlib.sha256()
        actual_crc = 0
        expanded = 0
        decompressor = zlib.decompressobj(-15) if compression == 8 else None
        pieces = []
        with ExitStack() as outputs:
            output = outputs.enter_context(exclusive_output(destination, name)) if destination is not None else None
            while remaining:
                chunk = stream.read(min(CHUNK_BYTES, remaining))
                require(bool(chunk), "truncated retained member")
                remaining -= len(chunk)
                # max_length bounds expansion before allocation, including bombs.
                decoded = decompressor.decompress(chunk, size - expanded + 1) if decompressor else chunk
                require(not decompressor or not decompressor.unconsumed_tail, "member exceeds bounded expansion")
                expanded += len(decoded)
                require(expanded <= size, "member exceeds expected size")
                digest.update(decoded)
                actual_crc = zlib.crc32(decoded, actual_crc)
                if output is not None:
                    output.write(decoded)
                if collect:
                    require(profile["expanded_bytes"] <= MAX_JSON_BYTES, "collection exceeds receipt bound")
                    pieces.append(decoded)
            require(not decompressor or (decompressor.eof and not decompressor.unused_data), "truncated or trailing deflate stream")
        exact(expanded, size, "streamed member size")
        exact(actual_crc, crc, "streamed CRC")
        exact(digest.hexdigest(), file["sha256"], "streamed member SHA256")
        descriptor = stream.read(16)
        exact(descriptor, struct.pack("<4s3I", b"PK\x07\x08", crc, compressed, size), "signed 32-bit data descriptor")
        cursor = descriptor_start + 16
        if collect:
            collected[name] = b"".join(pieces)
    exact(cursor, central_offset, "local archive boundary")
    exact(central_cursor, central_offset + central_size, "central archive boundary")
    exact(stable(os.fstat(stream.fileno())), stable(before), "retained stable descriptor")
    return collected


def verify_retained_zip(path, profile):
    fd = regular_fd(path, RETAINED_MAX_BYTES, "retained archive")
    with os.fdopen(fd, "rb") as stream:
        strict_zip_stream(stream, profile)
    return {"files_verified": len(profile["files"]), "zip_sha256": profile["zip_sha256"]}


def read_historical_custody(manifest, record, path):
    profile = retained_profile(manifest, record, "custody")
    fd = regular_fd(path, record["custody"]["metadata"]["size_in_bytes"], "historical custody ZIP")
    with os.fdopen(fd, "rb") as stream:
        members = strict_zip_stream(stream, profile, collect=True)
    evidence = {}
    for name, data in members.items():
        if name in EMPTY_HISTORICAL:
            exact(data, b"", "pinned empty historical command output")
        elif name.endswith(".json"):
            evidence[name] = parse_json(data, "historical " + name)
    metadata = [evidence[f"artifact-metadata/{a['id']}.json"] for a in manifest["artifacts"] + manifest["rust_preparation"]]
    origin = verify_origin(manifest, evidence["run.json"], evidence["jobs.json"], metadata)
    exact(evidence["jobs-page-1.json"], evidence["jobs.json"], "historical complete jobs page")
    exact(evidence["origin-check.json"], origin, "historical origin receipt")
    exact(evidence["final-file-check.json"], {"files_verified": 40, "lanes_verified": 7}, "historical file receipt")
    custody = evidence["artifact-custody-check.json"]
    keys(custody, ("artifacts_verified", "destination", "files_verified"), "historical artifact receipt")
    exact(custody["artifacts_verified"], 7, "historical original ZIP count")
    exact(custody["files_verified"], 40, "historical file count")
    receipt = evidence["import-receipt.json"]
    exact(receipt["product"], manifest["product"], "historical import product")
    exact(receipt["origin"], origin, "historical import origin")
    for identity in (receipt, evidence["identity-before.json"], evidence["identity-after.json"]):
        exact(identity["controller_sha"], RETAINED_COMMIT, "historical controller")
        exact(identity["controller_ref"], RETAINED_REF, "historical controller ref")
    for name in ("identity-before.json", "identity-after.json"):
        identity = evidence[name]
        exact(identity["product_commit"], PRODUCT_COMMIT, "historical identity product")
        exact(identity["product_tag_object"], PRODUCT_TAG_OBJECT, "historical product tag")
    return {"origin": origin, "files_verified": 40, "metadata": metadata,
            "current_crypto_verified": False, "evidence": evidence}


def complete_jobs(response, run_id, attempt, sha, branch):
    require(type(response) is dict, "jobs response must be an object")
    positive_integer(response.get("total_count"), "jobs total", 250)
    jobs = response.get("jobs")
    require(type(jobs) is list and len(jobs) == response["total_count"], "jobs pagination is incomplete")
    by_id = {}
    for job in jobs:
        require(type(job) is dict, "job must be an object")
        positive_integer(job.get("id"), "job ID")
        require(job["id"] not in by_id, "duplicate job ID")
        for field, value in {"run_id": run_id, "run_attempt": attempt, "head_sha": sha, "head_branch": branch}.items():
            exact(job.get(field), value, "job " + field)
        by_id[job["id"]] = job
    return by_id


def validate_run_identity(run, run_id, attempt, sha, branch, completed=True):
    require(type(run) is dict, "run must be an object")
    fields = {"id": run_id, "run_attempt": attempt, "workflow_id": WORKFLOW_ID,
              "path": ".github/workflows/release.yml", "event": "workflow_dispatch",
              "head_sha": sha, "head_branch": branch}
    if completed:
        fields["status"] = "completed"
    for key, value in fields.items():
        exact(run.get(key), value, "run " + key)
    for key in ("repository", "head_repository"):
        repository = run.get(key)
        require(type(repository) is dict, "run repository is absent")
        exact(repository.get("id"), REPOSITORY_ID, "run repository ID")
        exact(repository.get("full_name"), "exochain/exochain", "run repository name")
        require(type(repository.get("owner")) is dict, "repository owner is absent")
        exact(repository["owner"].get("id"), 129763194, "repository owner ID")


def successful_steps(job):
    for field in ("status", "conclusion"):
        exact(job.get(field), "completed" if field == "status" else "success", "producer " + field)
    steps = job.get("steps")
    require(type(steps) is list and 0 < len(steps) <= 100, "producer steps absent or oversized")
    names = [step.get("name") for step in steps if type(step) is dict]
    require(len(names) == len(steps) and len(set(names)) == len(names), "producer steps are duplicate or malformed")
    return {step["name"]: step for step in steps}


def validate_original_observation(manifest, record, policy, historical, observation, *, now):
    """Validate one typed status against authenticated history; never authorize by itself."""
    validate_retained_metadata_policy(manifest, record, policy)
    require(type(observation) is dict, "original observation must be an object")
    keys(observation, ("id", "endpoint_role", "request_started_at", "request_finished_at", "status", "variant",
                       "historical_member", "historical_sha256") if observation.get("status") == 404 else
         ("id", "endpoint_role", "request_started_at", "request_finished_at", "status", "variant",
          "historical_member", "historical_sha256", "metadata"), "original observation")
    positive_integer(observation["id"], "observed original ID")
    exact(observation["endpoint_role"], "original-artifact-metadata", "original endpoint role")
    start = timestamp(observation["request_started_at"], "original request start")
    finish = timestamp(observation["request_finished_at"], "original request finish")
    require(start <= finish <= timestamp(now, "verifier now"), "original observation chronology differs")
    require(type(historical) is dict and type(historical.get("metadata")) is list, "historical origin absent")
    by_id = {item["id"]: item for item in historical["metadata"]}
    require(observation["id"] in by_id and len(by_id) == 9, "observed original outside authenticated history")
    original = by_id[observation["id"]]
    member = f"artifact-metadata/{observation['id']}.json"
    exact(observation["historical_member"], member, "original historical member")
    custody_members = {item["path"]: item["sha256"] for item in record["custody"]["files"]}
    exact(observation["historical_sha256"], custody_members.get(member), "original historical hash")
    selected = {item["id"]: item for item in policy["unavailable_originals"]}.get(observation["id"])
    if selected is not None:
        exact(observation["historical_sha256"], selected["historical_sha256"], "selected historical hash")
        exact(original["expires_at"], selected["expires_at"], "selected historical expiry")
    require(type(observation["status"]) is int and observation["status"] in (200, 404), "original actual status disallowed")
    if observation["status"] == 404:
        require(selected is not None, "unselected original metadata unavailable")
        exact(observation["variant"], "unavailable_404", "unavailable original variant")
        require(start >= timestamp(selected["expires_at"], "selected original expiry"), "original 404 precedes pinned expiry")
        return {"id": observation["id"], "variant": "unavailable_404", "status": 404,
                "historical_sha256": observation["historical_sha256"]}
    exact(observation["variant"], "present", "present original variant")
    actual = observation["metadata"]
    keys(actual, original.keys(), "present original metadata")
    for key, value in original.items():
        if key != "expired":
            exact(actual[key], value, "present original " + key)
    require(type(actual["expired"]) is bool, "present original expired must be boolean")
    require(actual["expired"] == (finish >= timestamp(original["expires_at"], "original expiry")),
            "present original expiry differs from request finish")
    try:
        actual_digest = semantic_digest(actual)
        expected_digest = semantic_digest(dict(original, expired=actual["expired"]))
    except (TypeError, ValueError, RecursionError) as error:
        raise RecoveryError("present original metadata is not canonical JSON") from error
    exact(actual_digest, expected_digest, "strict present original metadata types")
    return {"id": observation["id"], "variant": "present", "status": 200,
            "historical_sha256": observation["historical_sha256"], "metadata_sha256": actual_digest}


def validate_original_observations(manifest, record, policy, historical, observations, *, now):
    validate_retained_metadata_policy(manifest, record, policy)
    keys(observations, ("schema", "operation", "policy_sha256", "observer", "before", "after"), "original observations")
    exact(observations["schema"], "exochain-retained-original-observations-027/v1", "observations schema")
    exact(observations["operation"], RETAINED_METADATA_OPERATION, "observations operation")
    exact(observations["policy_sha256"], RETAINED_METADATA_POLICY_SHA256, "observations policy pin")
    observer = observations["observer"]
    keys(observer, ("run_id", "run_attempt", "controller_sha", "controller_ref", "controller_tag_object",
                    "job_id", "job_name", "job_started_at"), "original observer")
    for field in ("run_id", "run_attempt", "job_id"):
        positive_integer(observer[field], "observer " + field)
    require(observer["run_id"] not in (RUN_ID, RETAINED_RUN_ID), "observer reused historical run")
    verify_controller(observer["controller_sha"], observer["controller_ref"], observer["controller_ref"].removeprefix("refs/tags/") if type(observer["controller_ref"]) is str else "")
    require(type(observer["controller_tag_object"]) is str and re.fullmatch(r"[0-9a-f]{40}", observer["controller_tag_object"]) is not None,
            "observer tag object is invalid")
    require(observer["job_name"] in (RECEIPT_JOB, RECEIPT_WRITER_JOB), "observer job role is not retained producer or writer")
    job_start = timestamp(observer["job_started_at"], "observer job start")
    now_time = timestamp(now, "verifier now")
    vectors = []
    prior_finish = job_start
    expected_ids = sorted(item["id"] for item in manifest["artifacts"] + manifest["rust_preparation"])
    for phase in ("before", "after"):
        passage = observations[phase]
        keys(passage, ("observed_at", "records"), phase + " observation pass")
        observed = timestamp(passage["observed_at"], phase + " observed at")
        require(type(passage["records"]) is list and len(passage["records"]) == 9, "original observation inventory incomplete")
        exact([item.get("id") if type(item) is dict else None for item in passage["records"]], expected_ids,
              "original observation order/inventory")
        vector = []
        for item in passage["records"]:
            request_start = timestamp(item.get("request_started_at"), "original request start")
            request_finish = timestamp(item.get("request_finished_at"), "original request finish")
            require(prior_finish <= request_start <= request_finish <= observed <= now_time,
                    "original observation interval outside job/pass")
            vector.append(validate_original_observation(manifest, record, policy, historical, item, now=now))
            prior_finish = request_finish
        vectors.append(vector)
        prior_finish = observed
    exact(vectors[0], vectors[1], "original availability transition")
    return vectors[1]


def _verify_retaining_context(record, retaining_run, retaining_jobs, retaining_tag, workflow_path):
    retaining = record["retaining"]
    exact(retaining_tag, {"object": retaining["tag_object"], "commit": RETAINED_COMMIT, "ref": RETAINED_REF}, "retaining tag object and peel")
    verify_retaining_workflow_source(record, workflow_path)
    validate_run_identity(retaining_run, RETAINED_RUN_ID, 1, RETAINED_COMMIT, "v0.2.7-recover.2")
    exact(retaining_run.get("conclusion"), "failure", "retaining overall conclusion")
    jobs = complete_jobs(retaining_jobs, RETAINED_RUN_ID, 1, RETAINED_COMMIT, "v0.2.7-recover.2")
    exact(len(jobs), retaining["jobs_total"], "complete retaining jobs inventory")
    producer = jobs.get(retaining["producer"]["id"])
    require(producer is not None, "retaining producer is absent")
    exact(producer.get("name"), retaining["producer"]["name"], "retaining producer name")
    for key in ("started_at", "completed_at"):
        exact(producer.get(key), retaining["producer"][key], "retaining producer " + key)
    steps = successful_steps(producer)
    for expected in retaining["producer"]["steps"]:
        step = steps.get(expected["name"])
        require(step is not None, "required retaining upload/import step absent")
        exact(step.get("status"), "completed", "retaining step status")
        exact(step.get("conclusion"), "success", "retaining step conclusion")
        for key, value in expected.items():
            exact(step.get(key), value, "retaining step " + key)
        require(timestamp(step.get("started_at"), "step start") <= timestamp(step.get("completed_at"), "step end"), "retaining step chronology differs")
    require(timestamp(producer["started_at"], "retaining producer start") <=
            timestamp(retaining["producer"]["steps"][0]["started_at"], "retaining import start") <=
            timestamp(retaining["producer"]["steps"][0]["completed_at"], "retaining import finish") <=
            timestamp(retaining["producer"]["steps"][1]["started_at"], "retaining payload upload start") <=
            timestamp(retaining["producer"]["steps"][1]["completed_at"], "retaining payload upload end") <=
            timestamp(retaining["producer"]["steps"][2]["started_at"], "retaining custody upload start") <=
            timestamp(retaining["producer"]["steps"][2]["completed_at"], "retaining custody upload end") <=
            timestamp(producer["completed_at"], "retaining producer finish"), "retaining import/upload chronology differs")
    return timestamp(retaining["producer"]["steps"][0]["completed_at"], "proved historical import")


def _verify_retained_origin_v2(manifest, record, policy, input_record, evidence_path, workflow_path, *, historical=None):
    validate_retained_metadata_policy(manifest, record, policy)
    keys(input_record, ("schema", "operation", "policy_sha256", "observations", "controls_before", "controls_after", "retaining_tag"), "retained origin v2 input")
    exact(input_record["schema"], "exochain-retained-origin-027/v2", "retained origin v2 schema")
    exact(input_record["operation"], RETAINED_METADATA_OPERATION, "retained origin v2 operation")
    exact(input_record["policy_sha256"], RETAINED_METADATA_POLICY_SHA256, "retained origin v2 policy")
    if historical is None:
        historical = read_historical_custody(manifest, record, evidence_path)
    import_finished = None
    before_time = None
    for phase in ("controls_before", "controls_after"):
        controls = input_record[phase]
        keys(controls, ("original_run", "original_jobs", "retaining_run", "retaining_jobs", "retained_metadata", "observed_at"), "origin " + phase)
        observed = timestamp(controls["observed_at"], phase + " observed at")
        if before_time is not None:
            require(before_time <= observed, "origin controls reversed")
        else:
            before_time = observed
        import_finished = _verify_retaining_context(record, controls["retaining_run"], controls["retaining_jobs"],
                                                    input_record["retaining_tag"], workflow_path)
        validate_run_identity(controls["original_run"], RUN_ID, 1, PRODUCT_COMMIT, "v0.2.7")
        verify_origin(manifest, controls["original_run"], controls["original_jobs"], historical["metadata"])
        values = controls["retained_metadata"]
        require(type(values) is list and len(values) == 2, "retained control metadata inventory differs")
        for actual, kind in zip(values, ("payload", "custody")):
            exact(actual, record[kind]["metadata"], "fresh retained " + kind + " metadata")
            exact(semantic_digest(actual), semantic_digest(record[kind]["metadata"]), "strict retained control types")
            require(timestamp(actual["created_at"], "retained creation") <= observed < timestamp(actual["expires_at"], "retained expiry"),
                    "retained control outside availability interval")
    observations = input_record["observations"]
    vector = validate_original_observations(manifest, record, policy, historical, observations,
                                            now=input_record["controls_after"]["observed_at"])
    require(before_time <= timestamp(observations["before"]["records"][0]["request_started_at"], "first original request") <=
            timestamp(observations["before"]["observed_at"], "before original observations") <=
            timestamp(observations["after"]["observed_at"], "after original observations") <=
            timestamp(input_record["controls_after"]["observed_at"], "after controls"), "origin observation/control chronology differs")
    for original in historical["metadata"]:
        require(timestamp(original["created_at"], "original creation") <= import_finished < timestamp(original["expires_at"], "original expiry"),
                "historical import was not pre-expiry")
    return {"schema": "exochain-retained-origin-result-027/v2", "mode": RETAINED_METADATA_OPERATION,
            "retained_record_sha256": RETAINED_RECORD_SHA256, "metadata_policy_sha256": RETAINED_METADATA_POLICY_SHA256,
            "historical_original_origin": historical["origin"], "observations": observations, "original_vector": vector,
            "retaining_run_id": RETAINED_RUN_ID, "retained_artifacts_verified": 2, "historical_files_verified": 60,
            "current_crypto_verified": False, "signature_verified": False, "mutation_attempted": False}


def verify_retained_origin(manifest, record, input_record, evidence_path, workflow_path, *, policy=None):
    if policy is not None:
        return _verify_retained_origin_v2(manifest, record, policy, input_record, evidence_path, workflow_path)
    validate_retained_record(manifest, record)
    keys(input_record, ("schema", "observed_at", "retaining_run", "retaining_jobs", "retaining_tag",
                        "original_run", "original_jobs", "original_metadata", "retained_before", "retained_after"), "retained origin input")
    exact(input_record["schema"], "exochain-retained-origin-input-027/v1", "retained origin input schema")
    observed = timestamp(input_record["observed_at"], "observation")
    import_finished = _verify_retaining_context(record, input_record["retaining_run"], input_record["retaining_jobs"],
                                                input_record["retaining_tag"], workflow_path)
    for phase in ("retained_before", "retained_after"):
        values = input_record[phase]
        require(type(values) is list and len(values) == 2, "retained metadata inventory differs")
        for actual, kind in zip(values, ("payload", "custody")):
            exact(actual, record[kind]["metadata"], "fresh retained " + kind + " metadata")
            exact(semantic_digest(actual), semantic_digest(record[kind]["metadata"]), "strict retained metadata types")
            require(timestamp(actual["created_at"], "retained creation") <= observed < timestamp(actual["expires_at"], "retained expiry"), "retained artifact unavailable at observation")
    historical = read_historical_custody(manifest, record, evidence_path)
    validate_run_identity(input_record["original_run"], RUN_ID, 1, PRODUCT_COMMIT, "v0.2.7")
    # The unchanged checker receives actual pinned historical metadata, never
    # a fresh response whose expired field has been normalized away.
    current_origin = verify_origin(manifest, input_record["original_run"], input_record["original_jobs"], historical["metadata"])
    actual_metadata = input_record["original_metadata"]
    require(type(actual_metadata) is list and len(actual_metadata) == 9, "current original metadata incomplete")
    by_id = {}
    for actual in actual_metadata:
        require(type(actual) is dict, "current original metadata must be an object")
        positive_integer(actual.get("id"), "current original artifact ID")
        require(actual["id"] not in by_id, "duplicate current original artifact")
        by_id[actual["id"]] = actual
    expiry = []
    for original in historical["metadata"]:
        actual = by_id.get(original["id"])
        require(actual is not None, "current original metadata missing")
        keys(actual, original.keys(), "current original metadata fields")
        for key, value in original.items():
            if key != "expired":
                exact(actual[key], value, "immutable original artifact " + key)
        exact(type(actual["expired"]), bool, "original expiry boolean type")
        expires = timestamp(original["expires_at"], "original expiry")
        require(timestamp(original["created_at"], "original creation") <= import_finished < expires, "historical import was not pre-expiry")
        require(observed >= import_finished, "observation predates historical import")
        require(actual["expired"] == (observed >= expires), "original current expiry disagrees with observation time")
        expiry.append({"id": original["id"], "expired": actual["expired"], "expires_at": original["expires_at"],
                       "historical_expired": original["expired"]})
    return {"schema": "exochain-retained-origin-result-027/v1", "mode": record["mode"],
            "retained_record_sha256": RETAINED_RECORD_SHA256, "historical_origin": historical["origin"],
            "current_original_origin": current_origin, "original_expiry": expiry,
            "observed_at": input_record["observed_at"], "retaining_run_id": RETAINED_RUN_ID,
            "retained_artifacts_verified": 2, "historical_files_verified": 60,
            "current_crypto_verified": False, "signature_verified": False, "mutation_attempted": False}


def verify_retaining_workflow_source(record, path):
    source = read_regular(path, MAX_JSON_BYTES, "retaining workflow source")
    exact(hashlib.sha256(source).hexdigest(), record["retaining"]["workflow_sha256"], "retaining workflow source digest")


def verify_retained_transport(manifest, record, archives, destination=None):
    validate_retained_record(manifest, record)
    with ExitStack() as stack:
        source_fd = directory_fd(archives)
        stack.callback(os.close, source_fd)
        names = {str(record[k]["metadata"]["id"]) + ".zip" for k in ("payload", "custody")}
        exact(set(os.listdir(source_fd)), names, "retained archive directory inventory")
        validated = {}
        for kind in ("payload", "custody"):
            profile = retained_profile(manifest, record, kind)
            fd = regular_fd(str(record[kind]["metadata"]["id"]) + ".zip", RETAINED_MAX_BYTES, "retained ZIP", source_fd)
            stream = stack.enter_context(os.fdopen(fd, "rb"))
            strict_zip_stream(stream, profile)
            validated[kind] = (stream, profile)
        result = {"schema": "exochain-retained-transport-result-027/v1", "retained_record_sha256": RETAINED_RECORD_SHA256,
                  "retained_archives_verified": 2, "payload_files_verified": 40, "historical_files_verified": 60,
                  "original_zip_envelopes_verified": 0, "current_crypto_verified": False, "mutation_attempted": False}
        if destination is not None:
            destination = Path(destination)
            require(destination.is_absolute() and destination.name not in ("", ".", ".."), "destination must be one absent absolute directory")
            parent_fd = directory_fd(destination.parent)
            stack.callback(os.close, parent_fd)
            require(destination.name not in os.listdir(parent_fd), "retained destination already exists")
            free = os.fstatvfs(parent_fd)
            require(free.f_bavail * free.f_frsize >= DISK_FLOOR_BYTES + record["payload"]["expanded_bytes"], "retained extraction violates 4 GiB disk floor")
            # A private staging directory is never returned on rejection. All
            # hashes are checked again while writing from the same descriptors.
            parent_stat = os.fstat(parent_fd)
            require(parent_stat.st_uid == os.geteuid() and not parent_stat.st_mode & 0o022, "retained destination parent must be private and owned by this user")
            stage_name = ".retained-027-" + os.urandom(16).hex()
            os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
            try:
                stage_fd = directory_fd(stage_name, parent_fd)
                try:
                    strict_zip_stream(*validated["payload"], destination=stage_fd)
                    verify_files(manifest, stage_fd)
                finally:
                    os.close(stage_fd)
                require(destination.name not in os.listdir(parent_fd), "retained destination appeared during validation")
                os.rename(stage_name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            finally:
                if stage_name in os.listdir(parent_fd):
                    shutil.rmtree(stage_name, dir_fd=parent_fd)
            result["destination"] = str(destination)
        return result


def _validate_retained_receipt_context(context):
    keys(context, ("controller_sha", "controller_ref", "controller_tag_object", "run_id", "run_attempt",
                   "producer_job_id", "checked_at", "checker_sha256", "runtime_versions", "dry_run"), "current receipt context")
    sha, ref = context["controller_sha"], context["controller_ref"]
    require(type(ref) is str, "controller ref must be a string")
    verify_controller(sha, ref, ref.removeprefix("refs/tags/"))
    require(sha != RETAINED_COMMIT and ref != RETAINED_REF, "current controller must differ from historical retaining controller")
    require(type(context["controller_tag_object"]) is str and re.fullmatch(r"[0-9a-f]{40}", context["controller_tag_object"]) is not None, "invalid current controller tag object")
    for key in ("run_id", "run_attempt", "producer_job_id"):
        positive_integer(context[key], "current " + key)
    require(context["run_id"] not in (RUN_ID, RETAINED_RUN_ID), "current receipt cannot reuse a historical run")
    require(type(context["checker_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", context["checker_sha256"]) is not None, "invalid captured checker digest")
    require(type(context["dry_run"]) is bool, "workflow dry_run must be an explicit boolean")
    timestamp(context["checked_at"], "current receipt check")
    versions = context["runtime_versions"]
    keys(versions, ("python", "node", "npm", "gh"), "current runtime versions")
    for value in versions.values():
        require(type(value) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is not None, "runtime version must be exact")
    for runtime, expected in {"python": "3.13.7", "node": "24.15.0", "npm": "11.12.1"}.items():
        exact(versions[runtime], expected, "pinned current " + runtime + " runtime")


def retained_receipt_bindings(manifest, record, context, origin, *, policy=None):
    """Build flat receipt bindings; result does not independently perform crypto."""
    validate_retained_record(manifest, record)
    _validate_retained_receipt_context(context)
    exact(origin.get("retained_record_sha256"), RETAINED_RECORD_SHA256, "receipt origin record pin")
    if policy is not None:
        validate_retained_metadata_policy(manifest, record, policy)
        exact(origin.get("schema"), "exochain-retained-origin-result-027/v2", "receipt v2 origin")
        exact(origin.get("metadata_policy_sha256"), RETAINED_METADATA_POLICY_SHA256, "receipt v2 policy")
        exact(origin.get("mode"), RETAINED_METADATA_OPERATION, "receipt v2 operation")
        require(type(origin.get("original_vector")) is list and len(origin["original_vector"]) == 9, "receipt v2 original vector absent")
        return {"mode": RETAINED_METADATA_OPERATION, **context, "checker_version": "retained-027/v2",
                "retained_record_sha256": RETAINED_RECORD_SHA256, "metadata_policy_sha256": RETAINED_METADATA_POLICY_SHA256,
                "manifest_sha256": MANIFEST_SHA256, "publications_sha256": PUBLICATIONS_SHA256,
                "product": manifest["product"], "historical_original_origin": origin["historical_original_origin"],
                "original_vector": origin["original_vector"],
                "transports": [{"id": record[k]["metadata"]["id"], "digest": record[k]["metadata"]["digest"]} for k in ("payload", "custody")],
                "mutation_attempted": False}
    exact(origin.get("schema"), "exochain-retained-origin-result-027/v1", "receipt v1 origin")
    return {"mode": record["mode"], **context, "checker_version": "retained-027/v1",
            "retained_record_sha256": RETAINED_RECORD_SHA256, "manifest_sha256": MANIFEST_SHA256,
            "publications_sha256": PUBLICATIONS_SHA256, "product": manifest["product"],
            "original_origin": origin["current_original_origin"], "original_expiry": origin["original_expiry"],
            "transports": [{"id": record[k]["metadata"]["id"], "digest": record[k]["metadata"]["digest"]} for k in ("payload", "custody")],
            "mutation_attempted": False}


def _retained_receipt_transport_profile(manifest, record, input_record, observed_at, *, require_import):
    context = input_record["context"]
    _validate_retained_receipt_context(context)
    run_id, attempt, sha, ref = (context[k] for k in ("run_id", "run_attempt", "controller_sha", "controller_ref"))
    validate_run_identity(input_record["current_run"], run_id, attempt, sha, ref.removeprefix("refs/tags/"), completed=False)
    jobs = complete_jobs(input_record["current_jobs"], run_id, attempt, sha, ref.removeprefix("refs/tags/"))
    producer = jobs.get(context["producer_job_id"])
    require(producer is not None, "current receipt producer absent")
    exact(producer.get("name"), RECEIPT_JOB, "current receipt producer name")
    require(sum(j.get("name") == RECEIPT_JOB for j in jobs.values()) == 1, "ambiguous current receipt producer")
    steps = successful_steps(producer)
    upload = steps.get(RECEIPT_UPLOAD)
    require(upload is not None, "current receipt upload step absent")
    exact(upload.get("status"), "completed", "receipt upload status")
    exact(upload.get("conclusion"), "success", "receipt upload conclusion")
    started = timestamp(producer.get("started_at"), "current producer start")
    finished = timestamp(producer.get("completed_at"), "current producer end")
    upload_start = timestamp(upload.get("started_at"), "current upload start")
    upload_end = timestamp(upload.get("completed_at"), "current upload end")
    checked = timestamp(context["checked_at"], "current checks")
    observed = timestamp(observed_at, "current observation")
    if require_import:
        import_step = steps.get(RECEIPT_IMPORT)
        require(import_step is not None, "current receipt import step absent")
        exact(import_step.get("status"), "completed", "receipt import status")
        exact(import_step.get("conclusion"), "success", "receipt import conclusion")
        import_start = timestamp(import_step.get("started_at"), "current import start")
        import_end = timestamp(import_step.get("completed_at"), "current import end")
        require(started <= import_start <= checked <= import_end <= upload_start <= upload_end <= finished <= observed,
                "current producer/import/upload chronology differs")
    else:
        import_step = None
        require(started <= checked <= upload_start <= upload_end <= finished <= observed, "current producer/upload chronology differs")
    outputs = input_record["upload_outputs"]
    keys(outputs, ("artifact_id", "artifact_digest", "producer_job_id"), "direct upload outputs")
    positive_integer(outputs["artifact_id"], "direct upload artifact ID")
    exact(outputs["producer_job_id"], context["producer_job_id"], "direct upload producer")
    require(type(outputs["artifact_digest"]) is str and re.fullmatch(r"[0-9a-f]{64}", outputs["artifact_digest"]) is not None, "direct artifact digest must be bare SHA256 output")
    metadata = input_record["metadata_before"]
    keys(metadata, record["custody"]["metadata"].keys(), "current receipt metadata")
    for field, value in {"id": outputs["artifact_id"], "digest": "sha256:" + outputs["artifact_digest"], "name": RECEIPT_ARTIFACT, "expired": False}.items():
        exact(metadata.get(field), value, "current receipt metadata " + field)
    positive_integer(metadata.get("size_in_bytes"), "current receipt ZIP size", RECEIPT_MAX_BYTES)
    exact(metadata.get("workflow_run"), {"id": run_id, "repository_id": REPOSITORY_ID, "head_repository_id": REPOSITORY_ID, "head_sha": sha, "head_branch": ref.removeprefix("refs/tags/")}, "current receipt workflow")
    base = f"https://api.github.com/repos/exochain/exochain/actions/artifacts/{outputs['artifact_id']}"
    exact(metadata["url"], base, "receipt metadata URL")
    exact(metadata["archive_download_url"], base + "/zip", "receipt download URL")
    created = timestamp(metadata["created_at"], "current receipt creation")
    require(upload_start <= created <= upload_end, "receipt artifact predates current upload or attempt")
    exact(metadata["updated_at"], metadata["created_at"], "receipt update timestamp")
    require(observed < timestamp(metadata["expires_at"], "current receipt expiry"), "current receipt transport expired")
    members = input_record["members"]
    require(type(members) is list and len(members) == 2, "receipt archive must have exactly two members")
    require([m.get("path") for m in members if type(m) is dict] == ["custody-receipt.json", "acceptance-receipt.json"], "receipt member names/order differ")
    for member in members:
        keys(member, ("path", "size", "sha256"), "receipt member")
        positive_integer(member["size"], "receipt member size", RECEIPT_MAX_BYTES // 2)
        require(type(member["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", member["sha256"]) is not None, "invalid receipt member hash")
    profile = {"zip_size": metadata["size_in_bytes"], "zip_sha256": outputs["artifact_digest"], "compression": 8,
               "mode": 0o100600, "dos_attributes": 32, "expanded_bytes": sum(m["size"] for m in members), "files": members}
    return profile, producer, import_step, upload


def retained_receipt_provenance(manifest, record, policy, input_record):
    """Authenticate the direct handoff without historical-origin or receipt-byte claims."""
    validate_retained_metadata_policy(manifest, record, policy)
    keys(input_record, ("schema", "operation", "policy_sha256", "observed_at", "context", "current_run",
                        "current_jobs", "upload_outputs", "metadata_before", "members"), "receipt preliminary input")
    exact(input_record["schema"], "exochain-retained-receipts-input-027/v2", "receipt v2 input schema")
    exact(input_record["operation"], RETAINED_METADATA_OPERATION, "receipt v2 operation")
    exact(input_record["policy_sha256"], RETAINED_METADATA_POLICY_SHA256, "receipt v2 policy")
    profile, _, _, _ = _retained_receipt_transport_profile(manifest, record, input_record,
                                                            input_record["observed_at"], require_import=True)
    return {"profile": profile, "context": input_record["context"],
            "upload_outputs": input_record["upload_outputs"], "observed_at": input_record["observed_at"]}


def retained_receipt_profile(manifest, record, publications, input_record, evidence_path, workflow_path, *, policy=None):
    """Validate provenance and origin before downloading; no receipt acceptance."""
    validate_publications(manifest, publications)
    if policy is None:
        keys(input_record, ("schema", "origin", "context", "current_run", "current_jobs", "upload_outputs", "metadata_before", "members"), "receipt pre-download input")
        exact(input_record["schema"], "exochain-retained-receipts-input-027/v1", "receipt input schema")
        origin = verify_retained_origin(manifest, record, input_record["origin"], evidence_path, workflow_path)
        bindings = retained_receipt_bindings(manifest, record, input_record["context"], origin)
        profile, _, _, _ = _retained_receipt_transport_profile(manifest, record, input_record,
                                                                input_record["origin"]["observed_at"], require_import=False)
        return bindings, profile
    keys(input_record, ("schema", "operation", "policy_sha256", "observed_at", "origin", "context", "current_run",
                        "current_jobs", "upload_outputs", "metadata_before", "members"), "receipt v2 pre-download input")
    preliminary = {key: value for key, value in input_record.items() if key != "origin"}
    provenance = retained_receipt_provenance(manifest, record, policy, preliminary)
    origin = verify_retained_origin(manifest, record, input_record["origin"], evidence_path, workflow_path, policy=policy)
    bindings = retained_receipt_bindings(manifest, record, input_record["context"], origin, policy=policy)
    return bindings, provenance["profile"]


def _validate_producer_receipt_observations(manifest, record, policy, input_record, historical, receipts, writer_vector):
    """Authenticate receipt-contained producer observations separately from the writer."""
    custody = receipts["custody-receipt.json"]
    acceptance = receipts["acceptance-receipt.json"]
    require(type(custody) is dict and type(acceptance) is dict, "receipt members must be objects")
    producer_observations = custody.get("original_observations")
    require(type(producer_observations) is dict, "producer original observations absent")
    exact(acceptance.get("original_observations"), producer_observations, "receipt producer observations")
    exact(semantic_digest(acceptance["original_observations"]), semantic_digest(producer_observations),
          "strict receipt producer observation types")
    context = input_record["context"]
    producer_vector = validate_original_observations(manifest, record, policy, historical, producer_observations,
                                                     now=context["checked_at"])
    exact(producer_vector, writer_vector, "producer/writer original vector")
    producer = complete_jobs(input_record["current_jobs"], context["run_id"], context["run_attempt"],
                             context["controller_sha"], context["controller_ref"].removeprefix("refs/tags/"))[context["producer_job_id"]]
    steps = successful_steps(producer)
    import_step, upload = steps[RECEIPT_IMPORT], steps[RECEIPT_UPLOAD]
    observer = producer_observations["observer"]
    for name, value in {"run_id": context["run_id"], "run_attempt": context["run_attempt"],
                        "controller_sha": context["controller_sha"], "controller_ref": context["controller_ref"],
                        "controller_tag_object": context["controller_tag_object"], "job_id": producer["id"],
                        "job_name": producer["name"], "job_started_at": producer["started_at"]}.items():
        exact(observer[name], value, "producer observation " + name)
    producer_start = timestamp(producer["started_at"], "producer start")
    import_start = timestamp(import_step["started_at"], "import start")
    import_end = timestamp(import_step["completed_at"], "import end")
    checked = timestamp(context["checked_at"], "producer checked at")
    upload_start = timestamp(upload["started_at"], "upload start")
    upload_end = timestamp(upload["completed_at"], "upload end")
    producer_end = timestamp(producer["completed_at"], "producer end")
    observed_at = timestamp(input_record["observed_at"], "final receipt observation")
    require(producer_start <= import_start <= import_end <= upload_start <= upload_end <= producer_end <= observed_at,
            "producer/import/upload interval differs")
    for phase in ("before", "after"):
        passage = producer_observations[phase]
        for observation in passage["records"]:
            require(import_start <= timestamp(observation["request_started_at"], "producer observation start") <=
                    timestamp(observation["request_finished_at"], "producer observation finish") <= checked <= import_end,
                    "producer original observation outside import/check interval")
        require(timestamp(passage["observed_at"], "producer observation pass") <= checked,
                "producer observation pass after checked at")
    return producer_observations


def verify_retained_receipts(manifest, record, publications, input_record, evidence_path, workflow_path, receipt_path, *, policy=None):
    """Final strict ZIP/results acceptance requires real before and after observations."""
    if policy is None:
        keys(input_record, ("schema", "origin", "context", "current_run", "current_jobs", "upload_outputs", "metadata_before", "metadata_after", "members"), "receipt verification input")
    else:
        keys(input_record, ("schema", "operation", "policy_sha256", "observed_at", "origin", "context", "current_run",
                            "current_jobs", "upload_outputs", "metadata_before", "metadata_after", "members"), "receipt v2 verification input")
    if policy is None:
        bindings, profile = retained_receipt_profile(manifest, record, publications,
            {key:value for key,value in input_record.items() if key != 'metadata_after'}, evidence_path, workflow_path)
    else:
        validate_publications(manifest, publications)
        preliminary = {key: value for key, value in input_record.items() if key not in ("origin", "metadata_after")}
        profile = retained_receipt_provenance(manifest, record, policy, preliminary)["profile"]
        historical = read_historical_custody(manifest, record, evidence_path)
        origin = _verify_retained_origin_v2(manifest, record, policy, input_record["origin"], evidence_path,
                                           workflow_path, historical=historical)
        bindings = retained_receipt_bindings(manifest, record, input_record["context"], origin, policy=policy)
    metadata = input_record['metadata_before']
    exact(metadata, input_record['metadata_after'], 'current receipt metadata changed during download')
    exact(semantic_digest(metadata), semantic_digest(input_record['metadata_after']), 'strict receipt metadata types')
    if policy is not None:
        observed_at = timestamp(input_record["observed_at"], "final receipt observation")
        require(observed_at < timestamp(metadata["expires_at"], "current receipt expiry"), "receipt expired before final validation")
        writer_observer = origin["observations"]["observer"]
        for field in ("run_id", "run_attempt", "controller_sha", "controller_ref", "controller_tag_object"):
            exact(writer_observer[field], input_record["context"][field], "writer observation " + field)
        context = input_record["context"]
        current_jobs = complete_jobs(input_record["current_jobs"], context["run_id"], context["run_attempt"],
                                     context["controller_sha"], context["controller_ref"].removeprefix("refs/tags/"))
        writer_job = current_jobs.get(writer_observer["job_id"])
        require(writer_job is not None, "writer observation job absent from current run")
        exact(writer_job.get("name"), writer_observer["job_name"], "writer observation job name")
        exact(writer_job.get("started_at"), writer_observer["job_started_at"], "writer observation job start")
        require(timestamp(writer_job["started_at"], "writer job start") <=
                timestamp(input_record["origin"]["controls_before"]["observed_at"], "writer initial controls") <=
                timestamp(input_record["origin"]["controls_after"]["observed_at"], "writer final controls") <= observed_at,
                "writer origin/final receipt chronology differs")
        if writer_job.get("status") == "completed":
            exact(writer_job.get("conclusion"), "success", "writer observation completed job conclusion")
            require(timestamp(origin["observations"]["after"]["observed_at"], "writer final pass") <=
                    timestamp(writer_job.get("completed_at"), "writer job finish"), "writer observation after job finish")
        else:
            exact(writer_job.get("status"), "in_progress", "writer observation job status")
            exact(writer_job.get("conclusion"), None, "writer in-progress job conclusion")
    context, outputs = input_record['context'], input_record['upload_outputs']
    run_id, attempt = context['run_id'], context['run_attempt']
    fd = regular_fd(receipt_path, RECEIPT_MAX_BYTES, "current receipt ZIP")
    with os.fdopen(fd, "rb") as stream:
        payloads = strict_zip_stream(stream, profile, collect=True)
    receipts = {name: parse_json(data, "current " + name) for name, data in payloads.items()}
    if policy is not None:
        producer_observations = _validate_producer_receipt_observations(manifest, record, policy, input_record,
                                                                        historical, receipts, origin["original_vector"])
    custody_results = {"payload_files_verified": 40, "retained_archives_verified": 2, "original_zip_envelopes_verified": 0,
                       "native_attestations_verified": 2, "native_libraries_per_archive": 29,
                       "product_signature_verified": True, "retaining_signature_verified": True, "controller_signature_verified": True}
    custody_results["native_attestations"] = [
        {"lane": artifact["lane"], "file": artifact["files"][0], "repository": "exochain/exochain",
         "source": {"commit": PRODUCT_COMMIT, "ref": "refs/tags/v0.2.7"},
         "signer_workflow": "exochain/exochain/.github/workflows/release.yml", "signer_digest": PRODUCT_COMMIT,
         "invocation": manifest["origin"]["native_attestation_invocation"], "crypto_verified": True}
        for artifact in manifest["artifacts"] if artifact["lane"].startswith("native-")]
    acceptance_results = {"rust": {"crates_verified": 32, "checksum_verified": True, "version_verified": True, "unyanked_verified": True},
                          "publications": [{"id": p["id"], "package": p["package"], "version": p["version"],
                                            "file": p["file"], "source": p["source"], "public_bytes_verified": True,
                                            "crypto_verified": True} for p in publications["publications"]]}
    for name, results in (("custody", custody_results), ("acceptance", acceptance_results)):
        expected = {"schema": "exochain-retained-" + name + "-receipt-027/" + ("v2" if policy is not None else "v1"),
                    **bindings, "results": results}
        if policy is not None:
            expected["original_observations"] = producer_observations
        exact(receipts[name + "-receipt.json"], expected, "current " + name + " receipt")
        # Recursive bool/int distinctions are checked by canonical JSON bytes.
        exact(semantic_digest(receipts[name + "-receipt.json"]), semantic_digest(expected), "strict receipt value types")
    result = {"schema": "exochain-retained-receipts-result-027/" + ("v2" if policy is not None else "v1"), "run_id": run_id, "run_attempt": attempt,
            "artifact_id": outputs["artifact_id"], "artifact_digest": outputs["artifact_digest"],
            "producer_job_id": context["producer_job_id"], "receipts_verified": 2, "dry_run": context["dry_run"],
            "crypto_claims_bound_to_current_producer": True, "independent_crypto_verification_performed": False,
            "mutation_attempted": False}
    if policy is not None:
        result["metadata_policy_sha256"] = RETAINED_METADATA_POLICY_SHA256
        result["original_vector"] = origin["original_vector"]
    return result


class RecoveryError(ValueError):
    """An identity, custody, or bounded-input requirement was not met."""


class RetainedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # No caller-provided arguments are echoed into machine-readable errors.
        raise RecoveryError("invalid or incomplete retained command arguments")


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def exact(actual, expected, label):
    require(type(actual) is type(expected) and actual == expected, f"{label} differs from the fixed recovery identity")


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), f"{label} has missing or unexpected fields")


def positive_integer(value, label, maximum=10**15):
    require(type(value) is int and 0 < value <= maximum, f"{label} must be a bounded positive integer")


def safe_name(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value) is not None, "unsafe inventory path")
    require(all(part not in {".", ".."} for part in value.split("/")), "unsafe inventory path component")
    return value


def parse_json(data, label):
    require(type(data) is bytes and 0 < len(data) <= MAX_JSON_BYTES, f"{label} JSON is empty or oversized")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def forbidden_number(value):
        raise RecoveryError(f"{label} contains a non-integer JSON number")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=forbidden_number, parse_float=forbidden_number)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise RecoveryError(f"{label} is not bounded strict JSON: {error}") from error


def stable(metadata):
    return tuple(getattr(metadata, field) for field in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def open_flags(directory=False):
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY"):
        require(hasattr(os, name), f"platform lacks secure filesystem flag {name}")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0)


def regular_fd(path, limit, label, dir_fd=None):
    try:
        fd = os.open(path, open_flags(), dir_fd=dir_fd)
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, f"{label} must be regular and non-hardlinked")
        require(0 < metadata.st_size <= limit, f"{label} has an invalid size")
        return fd
    except (OSError, RecoveryError) as error:
        if "fd" in locals():
            os.close(fd)
        raise RecoveryError(f"cannot securely open {label}: {error}") from error


def directory_fd(path, dir_fd=None):
    try:
        if type(path) is int:
            require(stat.S_ISDIR(os.fstat(path).st_mode), "directory descriptor is not a directory")
            return os.dup(path)
        return os.open(path, open_flags(True), dir_fd=dir_fd)
    except OSError as error:
        raise RecoveryError(f"cannot securely open directory {path}: {error}") from error


def read_regular(path, limit, label, dir_fd=None):
    fd = regular_fd(path, limit, label, dir_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        require(len(data) == before.st_size and stable(before) == stable(os.fstat(stream.fileno())), f"{label} changed while read")
        return data


def load_json(path, label):
    return parse_json(read_regular(path, MAX_JSON_BYTES, label), label)


def validate_manifest(manifest):
    keys(manifest, ("schema", "product", "origin", "ci_jobs", "release_jobs", "artifacts", "rust_preparation", "rust_crates"), "manifest")
    exact(manifest["schema"], "exochain-release-recovery-027/v1", "manifest schema")
    exact(manifest["product"], {"version":"0.2.7", "tag":"v0.2.7", "tag_object":PRODUCT_TAG_OBJECT, "commit":PRODUCT_COMMIT}, "product")
    keys(manifest["origin"], ("repository", "repository_id", "workflow_id", "workflow_path", "event", "ref", "run_id", "attempt", "jobs_total", "native_attestation_invocation"), "origin")
    for field in ("repository_id", "workflow_id", "run_id", "attempt", "jobs_total"):
        positive_integer(manifest["origin"][field], f"origin {field}")
    for field, count in (("ci_jobs",35),("release_jobs",22),("artifacts",7),("rust_preparation",2),("rust_crates",32)):
        require(type(manifest[field]) is list and len(manifest[field]) == count, f"manifest {field} inventory is incomplete or oversized")
    all_jobs = manifest["ci_jobs"] + manifest["release_jobs"]
    for job in all_jobs:
        keys(job, ("id","name"), "job")
        positive_integer(job["id"], "job ID")
        require(type(job["name"]) is str and 0 < len(job["name"]) < 256, "job name is invalid")
    require(len({job["id"] for job in all_jobs}) == 57, "duplicate manifest job IDs")
    require([a.get("lane") for a in manifest["artifacts"]] == list(LANES), "artifact lanes differ from the fixed inventory")
    for artifact in manifest["artifacts"]:
        keys(artifact, ("lane","id","name","zip_sha256","zip_size","producer_job_id","files"), "artifact")
        positive_integer(artifact["id"], "artifact ID")
        positive_integer(artifact["producer_job_id"], "artifact producer ID")
        positive_integer(artifact["zip_size"], "artifact ZIP size", MAX_ZIP_BYTES)
        safe_name(artifact["name"])
        require(type(artifact["files"]) is list and 1 <= len(artifact["files"]) <= 32, "invalid artifact file count")
        for file in artifact["files"]:
            keys(file, ("path","size","sha256"), "artifact file")
            safe_name(file["path"])
            positive_integer(file["size"], "artifact payload size", MAX_ZIP_BYTES)
            require(type(file["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",file["sha256"]) is not None, "invalid payload digest")
        require(len({f["path"] for f in artifact["files"]}) == len(artifact["files"]), "duplicate artifact payload")
    for record in manifest["rust_preparation"]:
        keys(record, ("id","name","zip_sha256","zip_size","producer_job_id","manifest_path","manifest_sha256"), "Rust preparation")
    for record in manifest["rust_crates"]:
        keys(record, ("name","sha256"), "Rust crate")
    try:
        canonical = json.dumps(manifest, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise RecoveryError(f"manifest cannot be canonically represented: {error}") from error
    exact(hashlib.sha256(canonical).hexdigest(), MANIFEST_SHA256, "reviewed complete manifest digest")
    return manifest


def load_manifest(path):
    return validate_manifest(load_json(path, "recovery manifest"))


def validate_publications(manifest, value):
    """Bind one reviewed prior identity per exact artifact; never a fallback."""
    validate_manifest(manifest)
    keys(value, ("schema", "artifact_manifest_sha256", "publications"), "publication identities")
    exact(value["schema"], "exochain-release-publication-identities-027/v1", "publication schema")
    exact(value["artifact_manifest_sha256"], MANIFEST_SHA256, "publication artifact manifest")
    records = value["publications"]
    require(type(records) is list and len(records) == 5, "publication inventory differs")
    require([r.get("id") for r in records if type(r) is dict] == list(PUBLICATION_IDS), "publication IDs differ")
    lanes = {lane["lane"]: lane for lane in manifest["artifacts"]}
    for record in records:
        keys(record, ("id", "package", "version", "lane", "file", "source", "observed_publication"), "publication")
        exact(record["version"], "0.2.7", "publication version")
        require(type(record["lane"]) is str and record["lane"] in lanes, "publication lane is unknown")
        keys(record["file"], ("path", "size", "sha256"), "publication file")
        require(record["file"] in lanes[record["lane"]]["files"], "publication file differs from original custody")
        positive_integer(record["file"]["size"], "publication file size", MAX_ZIP_BYTES)
        keys(record["source"], ("commit", "ref"), "publication source")
        require(type(record["source"]["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", record["source"]["commit"]) is not None, "invalid publication commit")
        require(type(record["source"]["ref"]) is str and re.fullmatch(r"refs/tags/v0\.2\.7(?:-recover\.[1-9][0-9]*)?", record["source"]["ref"]) is not None, "invalid publication ref")
        keys(record["observed_publication"], ("run_id", "attempt"), "observed publication")
        for field in ("run_id", "attempt"):
            positive_integer(record["observed_publication"][field], "observed publication " + field)
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    exact(hashlib.sha256(canonical).hexdigest(), PUBLICATIONS_SHA256, "reviewed publication identities digest")
    return value


def load_publications(manifest, path):
    return validate_publications(manifest, load_json(path, "publication identities"))


def verify_origin(manifest, run, jobs_response, metadata):
    require(type(run) is dict and type(jobs_response) is dict and type(metadata) is list, "malformed original provider records")
    for field, expected in {"id":RUN_ID,"run_attempt":1,"workflow_id":WORKFLOW_ID,"path":".github/workflows/release.yml","event":"workflow_dispatch","head_branch":"v0.2.7","head_sha":PRODUCT_COMMIT,"status":"completed","conclusion":"failure"}.items():
        exact(run.get(field), expected, f"original run {field}")
    for field in ("repository", "head_repository"):
        require(type(run.get(field)) is dict, f"original run {field} is missing")
        exact(run[field].get("id"), REPOSITORY_ID, f"original {field} ID")
        exact(run[field].get("full_name"), "exochain/exochain", f"original {field} name")
    exact(jobs_response.get("total_count"),62,"complete original jobs count")
    jobs = jobs_response.get("jobs")
    require(type(jobs) is list and len(jobs) == 62, "original jobs pagination is incomplete")
    by_id = {}
    for job in jobs:
        require(type(job) is dict, "original job must be an object")
        positive_integer(job.get("id"), "original job ID")
        require(job["id"] not in by_id, "duplicate original job ID")
        for field, expected in {"run_id":RUN_ID,"run_attempt":1,"head_sha":PRODUCT_COMMIT,"head_branch":"v0.2.7"}.items():
            exact(job.get(field), expected, f"original job {field}")
        by_id[job["id"]] = job
    required = manifest["ci_jobs"] + manifest["release_jobs"]
    for expected in required:
        actual = by_id.get(expected["id"])
        require(actual is not None, f"required original job {expected['id']} is missing")
        for field,value in {"name":expected["name"],"status":"completed","conclusion":"success"}.items():
            exact(actual.get(field),value,f"original job {expected['id']} {field}")
    require({j["id"] for j in jobs if isinstance(j.get("name"),str) and j["name"].startswith("Run CI Pipeline /")} == {j["id"] for j in manifest["ci_jobs"]}, "original reusable CI inventory differs")
    expected_artifacts = manifest["artifacts"] + manifest["rust_preparation"]
    require(len(metadata) == len(expected_artifacts), "original artifact metadata inventory differs")
    by_artifact = {}
    for artifact in metadata:
        require(type(artifact) is dict, "artifact metadata must be an object")
        positive_integer(artifact.get("id"), "provider artifact ID")
        require(artifact["id"] not in by_artifact, "duplicate provider artifact ID")
        by_artifact[artifact["id"]] = artifact
    for expected in expected_artifacts:
        actual = by_artifact.get(expected["id"])
        require(actual is not None, "required original artifact metadata is missing")
        for field,value in {"name":expected["name"],"size_in_bytes":expected["zip_size"],"digest":"sha256:"+expected["zip_sha256"],"expired":False}.items():
            exact(actual.get(field),value,f"original artifact {expected['id']} {field}")
        workflow = actual.get("workflow_run")
        require(type(workflow) is dict, "original artifact workflow_run is missing")
        for field,value in {"id":RUN_ID,"repository_id":REPOSITORY_ID,"head_repository_id":REPOSITORY_ID,"head_sha":PRODUCT_COMMIT,"head_branch":"v0.2.7"}.items():
            exact(workflow.get(field),value,f"original artifact workflow {field}")
        # Artifact metadata has no producer/attempt field. The reviewed mapping
        # is corroborated against the explicit original-attempt job inventory.
        require(expected["producer_job_id"] in by_id, "original artifact producer is absent")
    return {"run_id":RUN_ID,"run_attempt":1,"ci_jobs_verified":35,"successful_jobs_verified":57,"artifacts_verified":7,"rust_preparation_verified":2}


def verify_product_tag(manifest, local_object, local_commit, remote_refs):
    exact(local_object,PRODUCT_TAG_OBJECT,"local original tag object")
    exact(local_commit,PRODUCT_COMMIT,"local original tag peel")
    require(type(remote_refs) is str and len(remote_refs) < 512, "original remote refs are oversized")
    require(remote_refs.endswith("\n") and "\r" not in remote_refs,"original remote refs must be complete LF records")
    expected = {f"{PRODUCT_TAG_OBJECT}\trefs/tags/v0.2.7",f"{PRODUCT_COMMIT}\trefs/tags/v0.2.7^{{}}"}
    lines = remote_refs.splitlines()
    require(len(lines) == 2 and set(lines) == expected,"authoritative original tag object or peel changed")
    return {"tag":"v0.2.7","tag_object":PRODUCT_TAG_OBJECT,"commit":PRODUCT_COMMIT,"signature_verified":False}


def verify_controller(sha, ref, tag):
    require(type(sha) is str and re.fullmatch(r"[0-9a-f]{40}",sha) is not None and sha != PRODUCT_COMMIT,"controller must use its distinct real dispatch commit")
    require(type(tag) is str and re.fullmatch(r"v0\.2\.7-recover\.[1-9][0-9]*",tag) is not None,"controller tag must be a positive numbered 0.2.7 maintenance tag")
    exact(ref,"refs/tags/"+tag,"controller dispatch ref")
    return {"controller_sha":sha,"controller_ref":ref}


def hash_stream(stream, size, label, target=None):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = stream.read(min(CHUNK_BYTES,remaining))
        require(bool(chunk),f"{label} was truncated")
        remaining -= len(chunk)
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    require(not stream.read(1),f"{label} grew beyond the expected size")
    return digest.hexdigest()


def validate_zip_stream(stream, artifact, destination=None):
    before = os.fstat(stream.fileno())
    exact(before.st_size,artifact["zip_size"],"ZIP byte length")
    stream.seek(0)
    exact(hash_stream(stream,before.st_size,"ZIP"),artifact["zip_sha256"],"original ZIP digest")
    stream.seek(0)
    expected = {file["path"]:file for file in artifact["files"]}
    try:
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            require(len(names) == len(expected) and len(set(names)) == len(names) and set(names) == set(expected),"ZIP member inventory differs or duplicates members")
            require(not archive.comment,"ZIP comments are outside the reviewed transport")
            for member in members:
                safe_name(member.filename)
                file = expected[member.filename]
                mode = member.external_attr >> 16
                require(stat.S_IFMT(mode) in (0,stat.S_IFREG) and not member.is_dir() and not member.external_attr & 0x10,"ZIP members must be regular files")
                require(not member.flag_bits & ~0x808,"ZIP encryption or unsupported flags are forbidden")
                require(not member.extra and not member.comment,"ZIP extra fields and link encodings are forbidden")
                require(member.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),"unexpected ZIP compression")
                exact(member.file_size,file["size"],"ZIP expanded member size")
                require(0 < member.compress_size <= artifact["zip_size"],"invalid ZIP compressed member size")
                if member.compress_type == zipfile.ZIP_STORED:
                    exact(member.compress_size,member.file_size,"stored ZIP compressed size")
                with archive.open(member) as payload:
                    if destination is None:
                        digest = hash_stream(payload,file["size"],member.filename)
                    else:
                        with exclusive_output(destination,member.filename) as output:
                            digest = hash_stream(payload,file["size"],member.filename,output)
                    exact(digest,file["sha256"],"ZIP payload digest")
    except (OSError,zipfile.BadZipFile,RuntimeError,NotImplementedError) as error:
        raise RecoveryError(f"ZIP validation failed: {error}") from error
    exact(stable(os.fstat(stream.fileno())),stable(before),"ZIP stable file identity")


def verify_zip(path, artifact):
    with os.fdopen(regular_fd(path,MAX_ZIP_BYTES,"artifact ZIP"),"rb") as stream:
        validate_zip_stream(stream,artifact)


def exclusive_output(root_fd, relative):
    parts = safe_name(relative).split("/")
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part,0o700,dir_fd=parent)
            except FileExistsError:
                pass
            child = directory_fd(part,parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=parent)
        return os.fdopen(fd,"wb")
    finally:
        os.close(parent)


def extract_artifacts(manifest, archives, destination):
    destination = Path(destination)
    require(destination.is_absolute() and destination.name not in ("", ".", ".."),"destination must be one absent absolute directory")
    require(sum(a["zip_size"] for a in manifest["artifacts"]) <= MAX_TOTAL_BYTES,"aggregate ZIP bytes exceed bound")
    with ExitStack() as stack:
        source_fd = directory_fd(archives); stack.callback(os.close,source_fd)
        parent_fd = directory_fd(destination.parent); stack.callback(os.close,parent_fd)
        require(destination.name not in os.listdir(parent_fd),"recovery extraction destination must not exist")
        expected_names = {f"{a['id']}.zip" for a in manifest["artifacts"]}
        require(set(os.listdir(source_fd)) == expected_names,"ZIP directory contains missing or extra entries")
        validated = []
        for artifact in manifest["artifacts"]:
            fd = regular_fd(f"{artifact['id']}.zip",MAX_ZIP_BYTES,"original artifact ZIP",source_fd)
            stream = stack.enter_context(os.fdopen(fd,"rb"))
            validate_zip_stream(stream,artifact)
            validated.append((stream,artifact,stable(os.fstat(stream.fileno()))))
        # No destination is created until every original ZIP has passed. Reuse
        # the same open descriptors, then rehash while writing private files.
        os.mkdir(destination.name,0o700,dir_fd=parent_fd)
        root_fd = directory_fd(destination.name,parent_fd); stack.callback(os.close,root_fd)
        for stream,artifact,identity in validated:
            exact(stable(os.fstat(stream.fileno())),identity,"validated ZIP identity")
            os.mkdir(artifact["lane"],0o700,dir_fd=root_fd)
            lane_fd = directory_fd(artifact["lane"],root_fd)
            try:
                validate_zip_stream(stream,artifact,lane_fd)
            finally:
                os.close(lane_fd)
    return {"artifacts_verified":7,"files_verified":40,"destination":str(destination)}


def verify_files(manifest, directory, lane=None):
    require(lane is None or lane in LANES,"unknown artifact lane")
    selected = [a for a in manifest["artifacts"] if lane is None or a["lane"] == lane]
    root_fd = directory_fd(directory)
    count = 0
    try:
        if lane is None:
            require(set(os.listdir(root_fd)) == set(LANES),"recovery directory has missing or extra lanes")
        for artifact in selected:
            expected = {file["path"]:file for file in artifact["files"]}
            actual = set()
            directories = {"/".join(name.split("/")[:i]) for name in expected for i in range(1,len(name.split("/")))}
            observed_directories = set()

            def walk(fd, prefix=""):
                for name in os.listdir(fd):
                    relative = prefix+name
                    safe_name(relative)
                    metadata = os.stat(name,dir_fd=fd,follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        require(relative in directories,"unexpected artifact directory")
                        observed_directories.add(relative)
                        child = directory_fd(name,fd)
                        try:
                            walk(child,relative+"/")
                        finally:
                            os.close(child)
                    else:
                        require(relative in expected,"unexpected artifact file")
                        file = expected[relative]
                        opened = regular_fd(name,MAX_ZIP_BYTES,"artifact payload",fd)
                        with os.fdopen(opened,"rb") as stream:
                            before = os.fstat(stream.fileno())
                            exact(before.st_size,file["size"],"artifact file size")
                            exact(hash_stream(stream,file["size"],relative),file["sha256"],"artifact file digest")
                            exact(stable(os.fstat(stream.fileno())),stable(before),"artifact file identity")
                        actual.add(relative)

            lane_fd = directory_fd(artifact["lane"],root_fd)
            try:
                walk(lane_fd)
            finally:
                os.close(lane_fd)
            require(actual == set(expected) and observed_directories == directories,"artifact file inventory is incomplete")
            count += len(actual)
    finally:
        os.close(root_fd)
    return {"lanes_verified":len(selected),"files_verified":count}


def verify_rust(manifest, responses):
    require(type(responses) is dict and set(responses) == {r["name"] for r in manifest["rust_crates"]},"Rust registry inventory must contain exactly 32 packages")
    for crate in manifest["rust_crates"]:
        response = responses[crate["name"]]
        require(type(response) is dict and type(response.get("version")) is dict,"missing Rust version record")
        version = response["version"]
        positive_integer(version.get("id"),"Rust registry version ID")
        for field,value in {"crate":crate["name"],"num":"0.2.7","yanked":False,"checksum":crate["sha256"]}.items():
            exact(version.get(field),value,f"Rust registry {crate['name']} {field}")
    return {"version":"0.2.7","crates_verified":32}


def json_directory(path, names):
    fd = directory_fd(path)
    try:
        require(set(os.listdir(fd)) == set(names),"provider response directory has missing or extra files")
        return {name:parse_json(read_regular(name,MAX_JSON_BYTES,name,fd),name) for name in names}
    finally:
        os.close(fd)


def main():
    parser_type = RetainedArgumentParser if len(sys.argv) > 1 and sys.argv[1].startswith("retained-") else argparse.ArgumentParser
    parser = parser_type(description=__doc__)
    commands = parser.add_subparsers(dest="mode",required=True)
    for mode in ("manifest","publication","origin","artifacts","files","product-tag","rust-registry"):
        child = commands.add_parser(mode)
        child.add_argument("--manifest",type=Path,required=True)
        if mode == "publication":
            child.add_argument("--identities", type=Path, required=True)
            child.add_argument("--publication", choices=PUBLICATION_IDS)
        elif mode == "origin":
            for name in ("run","jobs","artifact-metadata"):
                child.add_argument("--"+name,type=Path,required=True)
        elif mode == "artifacts":
            child.add_argument("--archives",type=Path,required=True)
            child.add_argument("--destination",type=Path,required=True)
        elif mode == "files":
            child.add_argument("--directory",type=Path,required=True)
            child.add_argument("--lane",choices=LANES)
        elif mode == "product-tag":
            child.add_argument("--local-tag-object",required=True)
            child.add_argument("--local-peeled-commit",required=True)
            child.add_argument("--remote-refs",type=Path,required=True)
        elif mode == "rust-registry":
            child.add_argument("--responses",type=Path,required=True)
    for mode in ("retained-record", "retained-origin", "retained-transport", "retained-receipts"):
        child = commands.add_parser(mode)
        child.add_argument("--manifest", type=Path, required=True)
        child.add_argument("--record", type=Path, required=True)
        if mode in ("retained-origin", "retained-receipts"):
            for name in ("input", "evidence", "retaining-workflow"):
                child.add_argument("--" + name, type=Path, required=True)
        if mode == "retained-transport":
            child.add_argument("--archives", type=Path, required=True)
            child.add_argument("--destination", type=Path)
        if mode == "retained-receipts":
            child.add_argument("--receipts", type=Path, required=True)
            child.add_argument("--identities", type=Path, required=True)
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    if args.mode.startswith("retained-"):
        record = load_retained_record(manifest, args.record)
        if args.mode == "retained-record":
            result = record
        elif args.mode == "retained-origin":
            result = verify_retained_origin(manifest, record, load_json(args.input, "retained origin input"), args.evidence, args.retaining_workflow)
        elif args.mode == "retained-transport":
            result = verify_retained_transport(manifest, record, args.archives, args.destination)
        else:
            result = verify_retained_receipts(manifest, record, load_publications(manifest, args.identities),
                                              load_json(args.input, "retained receipt input"), args.evidence, args.retaining_workflow, args.receipts)
    elif args.mode == "manifest":
        result = manifest
    elif args.mode == "publication":
        result = load_publications(manifest, args.identities)
        if args.publication:
            result = next(record for record in result["publications"] if record["id"] == args.publication)
    elif args.mode == "origin":
        names = [f"{a['id']}.json" for a in manifest["artifacts"]+manifest["rust_preparation"]]
        metadata = json_directory(args.artifact_metadata,names)
        result = verify_origin(manifest,load_json(args.run,"original run"),load_json(args.jobs,"original jobs"),list(metadata.values()))
    elif args.mode == "artifacts":
        result = extract_artifacts(manifest,args.archives,args.destination)
    elif args.mode == "files":
        result = verify_files(manifest,args.directory,args.lane)
    elif args.mode == "product-tag":
        refs = read_regular(args.remote_refs,512,"original remote refs").decode("ascii")
        result = verify_product_tag(manifest,args.local_tag_object,args.local_peeled_commit,refs)
    else:
        values = json_directory(args.responses,[r["name"]+".json" for r in manifest["rust_crates"]])
        result = verify_rust(manifest,{name[:-5]:value for name,value in values.items()})
    print(json.dumps(result,sort_keys=True,separators=(",",":")))


if __name__ == "__main__":
    try:
        main()
    except (RecoveryError,OSError,UnicodeError,KeyError,TypeError,RecursionError,struct.error,zlib.error) as error:
        print(json.dumps({"error":"release_recovery_027_rejected","message":str(error)}),file=sys.stderr)
        raise SystemExit(1) from error
