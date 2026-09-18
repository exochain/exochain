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

PRODUCT_COMMIT = "666c578f719d1e54fce95d6831a3af92ea80df93"
PRODUCT_TAG_OBJECT = "be47589ec7dbefe821ada35ed0a89dedc9751953"
RUN_ID = 35257955565
REPOSITORY_ID = 1116455646
WORKFLOW_ID = 248228578
# Semantic digest of the reviewed owned manifest, not a provider response.
# Pinning it prevents a caller from substituting otherwise well-formed hashes,
# producer mappings, package names or endpoints while retaining the fixed tag.
MANIFEST_SHA256 = "17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ZIP_BYTES = 96 * 1024 * 1024
MAX_TOTAL_BYTES = 192 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
LANES = ("npm-wasm", "npm-llm", "npm-sdk", "python", "sbom", "native-x86_64", "native-aarch64")


class RecoveryError(ValueError):
    """An identity, custody, or bounded-input requirement was not met."""


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
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode",required=True)
    for mode in ("manifest","origin","artifacts","files","product-tag","rust-registry"):
        child = commands.add_parser(mode)
        child.add_argument("--manifest",type=Path,required=True)
        if mode == "origin":
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
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    if args.mode == "manifest":
        result = manifest
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
    except (RecoveryError,OSError,UnicodeError,KeyError,TypeError,RecursionError) as error:
        print(json.dumps({"error":"release_recovery_027_rejected","message":str(error)}),file=sys.stderr)
        raise SystemExit(1) from error
