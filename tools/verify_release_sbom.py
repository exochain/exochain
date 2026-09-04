#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Validate cargo-cyclonedx 0.5.9 output and rebuild a trusted SBOM set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import quote, unquote

SCHEMA_URI = "http://cyclonedx.org/schema/bom-1.5.schema.json"
EXPECTED_TIMESTAMP = "1970-01-01T00:00:00.000000000Z"
EXPECTED_TOOL = {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}
EXPECTED_TARGET_PROPERTY = {"name": "cdx:rustc:sbom:target:all_targets", "value": "true"}
TOP_LEVEL_KEYS = {"bomFormat", "components", "dependencies", "metadata", "specVersion", "version"}
METADATA_KEYS = {"component", "properties", "timestamp", "tools"}
ROOT_KEYS = {
    "type", "bom-ref", "name", "version", "description", "scope", "licenses",
    "purl", "externalReferences", "components",
}
TARGET_KEYS = {"type", "bom-ref", "name", "version", "purl"}
RELEASE_TARGET_KINDS = {"lib", "bin", "proc-macro", "cdylib", "staticlib", "dylib"}
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
TARGET_REF_PATTERN = re.compile(r" bin-target-(0|[1-9][0-9]*)")
RAW_FILE_LIMIT = 8 * 1024 * 1024
METADATA_LIMIT = 64 * 1024 * 1024
LOCK_LIMIT = 8 * 1024 * 1024
MAX_JSON_NODES = 750_000
MAX_JSON_DEPTH = 96
READ_CHUNK = 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release SBOM validation failed: {message}")


def open_flags(*, directory: bool = False, writable: bool = False) -> int:
    required = ["O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"]
    if directory:
        required.append("O_DIRECTORY")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        fail(f"platform lacks secure open flags: {', '.join(missing)}")
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_WRONLY if writable else os.O_RDONLY
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def read_descriptor(descriptor: int, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(READ_CHUNK, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            fail(f"{label} exceeds its size limit")


def read_stable_descriptor(descriptor: int, limit: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a regular non-symlink, non-hardlinked file")
    if before.st_size <= 0 or before.st_size > limit:
        fail(f"{label} has an invalid size")
    payload = read_descriptor(descriptor, limit, label)
    after = os.fstat(descriptor)
    stable = lambda value: (
        value.st_dev, value.st_ino, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if stable(before) != stable(after) or len(payload) != before.st_size:
        fail(f"{label} changed while it was read")
    return payload


def read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        descriptor = os.open(path, open_flags())
    except OSError as error:
        fail(f"cannot securely open {label}: {error}")
    try:
        return read_stable_descriptor(descriptor, limit, label)
    finally:
        os.close(descriptor)


def reject_constant(value: str) -> NoReturn:
    fail(f"JSON contains non-finite constant {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def parse_json(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    try:
        value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except json.JSONDecodeError as error:
        fail(f"{label} is malformed JSON: {error}")
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            fail(f"{label} exceeds JSON complexity limits")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            fail(f"{label} contains floating-point data")
    return value


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be nonempty text")
    return value


def package_key(package: dict[str, Any]) -> tuple[str, str, str | None]:
    source = package.get("source")
    if source is not None and not isinstance(source, str):
        fail("Cargo package source must be text or null")
    return (
        require_text(package.get("name"), "Cargo package name"),
        require_text(package.get("version"), "Cargo package version"),
        source,
    )


def canonical_purl(name: str, version: str) -> str:
    return f"pkg:cargo/{quote(name, safe='-._~')}@{quote(version, safe='-._~+')}"


def workspace_ref(name: str, version: str) -> str:
    return f"urn:exochain:workspace:cargo:{name}@{version}"


def root_component_type(package: dict[str, Any]) -> str:
    kinds: set[str] = set()
    for raw_target in require_list(package.get("targets"), "Cargo package targets"):
        target = require_dict(raw_target, "Cargo target")
        raw_kinds = require_list(target.get("kind"), "Cargo target kinds")
        if any(not isinstance(kind, str) for kind in raw_kinds):
            fail("Cargo target kind must be text")
        kinds.update(raw_kinds)
    return "application" if "bin" in kinds else "library"


def expected_licenses(package: dict[str, Any]) -> list[dict[str, str]]:
    expression = package.get("license")
    if expression is None:
        return []
    if not isinstance(expression, str) or not expression:
        fail("Cargo package license must be nonempty text or null")
    return [{"expression": expression.replace("/", " OR ")}]


def expected_external_references(package: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for key, reference_type in (
        ("documentation", "documentation"), ("homepage", "website"),
        ("links", "other"), ("repository", "vcs"),
    ):
        value = package.get(key)
        if value is not None:
            result.append({"type": reference_type, "url": require_text(value, f"Cargo {key}")})
    return result


def expected_description(package: dict[str, Any]) -> str:
    description = package.get("description")
    if description is None:
        return ""
    if not isinstance(description, str):
        fail("Cargo package description must be text or null")
    return description.replace("\r", " ").replace("\n", " ")


def relative_manifest_directory(package: dict[str, Any], root: dict[str, Any]) -> str:
    package_manifest = Path(require_text(package.get("manifest_path"), "Cargo manifest path"))
    root_manifest = Path(require_text(root.get("manifest_path"), "root Cargo manifest path"))
    try:
        relative = os.path.relpath(package_manifest.parent, root_manifest.parent)
    except ValueError as error:
        fail(f"workspace manifest paths cannot be related: {error}")
    if not relative or "\\" in relative:
        fail("workspace manifest relative directory is invalid")
    return relative


def expected_raw_purl(package: dict[str, Any], root: dict[str, Any], workspace_ids: set[str]) -> str:
    name, version, _ = package_key(package)
    base = canonical_purl(name, version)
    package_id = require_text(package.get("id"), "Cargo package id")
    if package_id in workspace_ids:
        return f"{base}?download_url=file://{relative_manifest_directory(package, root)}"
    return base


def expected_raw_component(
    package: dict[str, Any], root: dict[str, Any], workspace_ids: set[str],
    checksum: str | None, scope: str,
) -> dict[str, Any]:
    name, version, _ = package_key(package)
    result: dict[str, Any] = {
        # cargo-cyclonedx models dependency packages as libraries even when the
        # package also ships a binary. Only a document root becomes an
        # application when that root has a bin target.
        "type": "library",
        "bom-ref": require_text(package.get("id"), "Cargo package id"),
        "name": name,
        "version": version,
        "description": expected_description(package),
        "scope": scope,
        "licenses": expected_licenses(package),
        "purl": expected_raw_purl(package, root, workspace_ids),
        "externalReferences": expected_external_references(package),
    }
    authors = require_list(package.get("authors"), "Cargo package authors")
    if any(not isinstance(author, str) or not author for author in authors):
        fail("Cargo package authors must be nonempty text")
    if authors:
        result["author"] = ", ".join(authors)
    if checksum is not None:
        result["hashes"] = [{"alg": "SHA-256", "content": checksum}]
    return result


def expected_targets(package: dict[str, Any]) -> dict[str, dict[str, str]]:
    manifest = Path(require_text(package.get("manifest_path"), "Cargo manifest path"))
    name, version, _ = package_key(package)
    result: dict[str, dict[str, str]] = {}
    for raw_target in require_list(package.get("targets"), f"Cargo targets for {name}"):
        target = require_dict(raw_target, f"Cargo target for {name}")
        kinds = require_list(target.get("kind"), f"Cargo target kinds for {name}")
        if any(not isinstance(kind, str) for kind in kinds):
            fail(f"Cargo target kind for {name} must be text")
        if not RELEASE_TARGET_KINDS.intersection(kinds):
            continue
        target_name = require_text(target.get("name"), f"Cargo target name for {name}")
        source_path = Path(require_text(target.get("src_path"), f"Cargo target source for {name}"))
        try:
            relative_source = source_path.relative_to(manifest.parent).as_posix()
        except ValueError:
            fail(f"Cargo target {target_name} escapes its manifest directory")
        target_type = "application" if "bin" in kinds else "library"
        identity = f"{target_type}\0{target_name}\0{relative_source}"
        if identity in result:
            fail(f"Cargo metadata contains duplicate release target {target_name}")
        result[identity] = {
            "type": target_type, "name": target_name, "version": version,
            "relative_source": relative_source,
        }
    if not result:
        fail(f"Cargo package {name} has no release target")
    return result


def validate_targets(raw_root: dict[str, Any], package: dict[str, Any]) -> list[dict[str, str]]:
    name, version, _ = package_key(package)
    package_id = require_text(package.get("id"), "root Cargo package id")
    raw_targets = require_list(raw_root.get("components"), f"raw SBOM {name} root targets")
    expected = expected_targets(package)
    matched: dict[str, dict[str, str]] = {}
    seen_raw_refs: set[str] = set()
    for raw_value in raw_targets:
        target = require_dict(raw_value, f"raw SBOM {name} target")
        if set(target) != TARGET_KEYS:
            fail(f"raw SBOM {name} target has an unexpected field set")
        target_name = require_text(target.get("name"), f"raw SBOM {name} target name")
        target_type = require_text(target.get("type"), f"raw SBOM {name} target type")
        if target.get("version") != version:
            fail(f"raw SBOM {name} target {target_name} has the wrong version")
        raw_ref = require_text(target.get("bom-ref"), f"raw SBOM {name} target ref")
        if not raw_ref.startswith(package_id) or TARGET_REF_PATTERN.fullmatch(raw_ref[len(package_id):]) is None:
            fail(f"raw SBOM {name} target {target_name} has an invalid generator ref")
        if raw_ref in seen_raw_refs:
            fail(f"raw SBOM {name} contains a duplicate target ref")
        seen_raw_refs.add(raw_ref)
        purl = require_text(target.get("purl"), f"raw SBOM {name} target purl")
        prefix = f"{expected_raw_purl(package, package, {package_id})}#"
        if not purl.startswith(prefix):
            fail(f"raw SBOM {name} target {target_name} has an invalid source purl")
        relative_source = purl[len(prefix):]
        identity = f"{target_type}\0{target_name}\0{relative_source}"
        expected_target = expected.get(identity)
        if expected_target is None or identity in matched:
            fail(f"raw SBOM {name} target set differs from Cargo metadata")
        matched[identity] = expected_target
    if set(matched) != set(expected):
        fail(f"raw SBOM {name} target set is incomplete")

    canonical_targets: list[dict[str, str]] = []
    for identity in sorted(expected):
        target = expected[identity]
        semantic = ":".join(
            quote(target[field], safe="-._~/")
            for field in ("type", "name", "relative_source")
        )
        canonical_targets.append({
            "type": target["type"],
            "bom-ref": f"{workspace_ref(name, version)}:target:{semantic}",
            "name": target["name"],
            "version": version,
            "purl": f"{canonical_purl(name, version)}#{quote(target['relative_source'], safe='-._~/')}",
        })
    return canonical_targets


def filtered_resolve_graph(metadata: dict[str, Any]) -> tuple[dict[str, set[str]], dict[tuple[str, str], bool]]:
    resolve = require_dict(metadata.get("resolve"), "Cargo resolve graph")
    graph: dict[str, set[str]] = {}
    normal_edges: dict[tuple[str, str], bool] = {}
    for raw_node in require_list(resolve.get("nodes"), "Cargo resolve nodes"):
        node = require_dict(raw_node, "Cargo resolve node")
        node_id = require_text(node.get("id"), "Cargo resolve node id")
        if node_id in graph:
            fail("Cargo resolve graph contains duplicate nodes")
        targets: set[str] = set()
        for raw_dep in require_list(node.get("deps"), "Cargo resolve node dependencies"):
            dep = require_dict(raw_dep, "Cargo resolve dependency")
            target_id = require_text(dep.get("pkg"), "Cargo resolve dependency package id")
            dep_kinds = require_list(dep.get("dep_kinds"), "Cargo resolve dependency kinds")
            if not dep_kinds:
                fail("Cargo resolve dependency must declare a dependency kind")
            kinds: list[str | None] = []
            for raw_kind in dep_kinds:
                kind = require_dict(raw_kind, "Cargo resolve dependency kind").get("kind")
                if kind not in (None, "build", "dev"):
                    fail("Cargo resolve dependency kind is unsupported")
                kinds.append(kind)
            if all(kind == "dev" for kind in kinds):
                continue
            targets.add(target_id)
            normal_edges[(node_id, target_id)] = normal_edges.get((node_id, target_id), False) or None in kinds
        graph[node_id] = targets
    return graph, normal_edges


def expected_closure(
    root_id: str, graph: dict[str, set[str]], normal_edges: dict[tuple[str, str], bool],
) -> tuple[set[str], dict[str, str]]:
    if root_id not in graph:
        fail("Cargo resolve graph omits a publishable workspace root")
    reachable = {root_id}
    pending = [root_id]
    while pending:
        source = pending.pop()
        if source not in graph:
            fail("Cargo resolve graph omits a reachable package node")
        for target in graph[source]:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    scopes = {package_id: "excluded" for package_id in reachable}
    scopes[root_id] = "required"
    changed = True
    while changed:
        changed = False
        for source in sorted(reachable):
            if scopes[source] != "required":
                continue
            for target in graph[source]:
                if normal_edges.get((source, target), False) and scopes[target] != "required":
                    scopes[target] = "required"
                    changed = True
    return reachable, scopes


def validate_raw_document(
    payload: bytes, root_package: dict[str, Any], packages_by_id: dict[str, dict[str, Any]],
    checksums: dict[str, str | None], workspace_ids: set[str], graph: dict[str, set[str]],
    normal_edges: dict[tuple[str, str], bool], expected_version: str,
) -> bytes:
    name, version, _ = package_key(root_package)
    if version != expected_version:
        fail(f"workspace package {name} does not match release version {expected_version}")
    document = require_dict(parse_json(payload, f"raw SBOM {name}"), f"raw SBOM {name}")
    if set(document) != TOP_LEVEL_KEYS:
        fail(f"raw SBOM {name} has an unexpected top-level field set")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        fail(f"raw SBOM {name} is not CycloneDX 1.5")
    if document.get("version") != 1:
        fail(f"raw SBOM {name} must have document version 1")

    metadata = require_dict(document.get("metadata"), f"raw SBOM {name} metadata")
    if set(metadata) != METADATA_KEYS:
        fail(f"raw SBOM {name} metadata has an unexpected field set")
    if metadata.get("timestamp") != EXPECTED_TIMESTAMP:
        fail(f"raw SBOM {name} has a nondeterministic timestamp")
    if metadata.get("tools") != [EXPECTED_TOOL]:
        fail(f"raw SBOM {name} was not produced only by cargo-cyclonedx 0.5.9")
    if metadata.get("properties") != [EXPECTED_TARGET_PROPERTY]:
        fail(f"raw SBOM {name} is not bound exactly to target=all")

    root_id = require_text(root_package.get("id"), "root Cargo package id")
    closure, scopes = expected_closure(root_id, graph, normal_edges)
    root = require_dict(metadata.get("component"), f"raw SBOM {name} root component")
    if set(root) != ROOT_KEYS:
        fail(f"raw SBOM {name} root has an unexpected field set")
    expected_root = expected_raw_component(
        root_package, root_package, workspace_ids, checksums[root_id], "required"
    )
    expected_root["type"] = root_component_type(root_package)
    expected_root.pop("hashes", None)
    expected_root.pop("author", None)
    expected_root["components"] = root.get("components")
    if root != expected_root:
        fail(f"raw SBOM {name} root metadata differs from Cargo metadata")
    canonical_targets = validate_targets(root, root_package)

    expected_component_ids = closure - {root_id}
    actual_components: dict[str, dict[str, Any]] = {}
    for raw_component in require_list(document.get("components"), f"raw SBOM {name} components"):
        component = require_dict(raw_component, f"raw SBOM {name} component")
        component_id = require_text(component.get("bom-ref"), "raw component bom-ref")
        if component_id in actual_components:
            fail(f"raw SBOM {name} contains a duplicate component")
        package = packages_by_id.get(component_id)
        if package is None or component_id not in expected_component_ids:
            fail(f"raw SBOM {name} contains a component outside its exact Cargo closure")
        expected = expected_raw_component(
            package, root_package, workspace_ids, checksums[component_id], scopes[component_id]
        )
        if component != expected:
            fail(f"raw SBOM {name} component {package['name']} differs from Cargo metadata or scope")
        actual_components[component_id] = component
    if set(actual_components) != expected_component_ids:
        missing = sorted(packages_by_id[item]["name"] for item in expected_component_ids - set(actual_components))
        fail(f"raw SBOM {name} component closure is incomplete: {missing}")

    actual_edges: dict[str, set[str]] = {}
    for raw_entry in require_list(document.get("dependencies"), f"raw SBOM {name} dependencies"):
        entry = require_dict(raw_entry, f"raw SBOM {name} dependency entry")
        if set(entry) not in ({"ref"}, {"ref", "dependsOn"}):
            fail(f"raw SBOM {name} dependency entry has an unexpected field set")
        source = require_text(entry.get("ref"), "dependency ref")
        if source not in closure or source in actual_edges:
            fail(f"raw SBOM {name} contains an unknown or duplicate dependency ref")
        raw_targets = entry.get("dependsOn", [])
        if not isinstance(raw_targets, list) or any(not isinstance(item, str) for item in raw_targets):
            fail(f"raw SBOM {name} dependency edges must be text arrays")
        if len(raw_targets) != len(set(raw_targets)):
            fail(f"raw SBOM {name} contains duplicate dependency edges")
        actual_edges[source] = set(raw_targets)
    expected_edges = {source: graph[source] & closure for source in closure}
    if set(actual_edges) != closure:
        fail(f"raw SBOM {name} dependency records are incomplete")
    if actual_edges != expected_edges:
        fail(f"raw SBOM {name} dependency edges differ from exact Cargo target-all closure")

    ref_map = {
        package_id: (
            workspace_ref(packages_by_id[package_id]["name"], packages_by_id[package_id]["version"])
            if package_id in workspace_ids else package_id
        ) for package_id in closure
    }
    if len(set(ref_map.values())) != len(ref_map):
        fail(f"raw SBOM {name} normalizes to duplicate package refs")
    canonical_components: list[dict[str, Any]] = []
    for package_id in sorted(expected_component_ids, key=lambda item: ref_map[item]):
        package = packages_by_id[package_id]
        component: dict[str, Any] = {
            "type": "library", "bom-ref": ref_map[package_id],
            "name": package["name"], "version": package["version"],
            "scope": scopes[package_id],
            "purl": canonical_purl(package["name"], package["version"]),
        }
        checksum = checksums[package_id]
        if checksum is not None:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        canonical_components.append(component)
    canonical_dependencies = []
    for source in sorted(closure, key=lambda item: ref_map[item]):
        entry: dict[str, Any] = {"ref": ref_map[source]}
        targets = sorted(ref_map[target] for target in expected_edges[source])
        if targets:
            entry["dependsOn"] = targets
        canonical_dependencies.append(entry)
    canonical_document = {
        "$schema": SCHEMA_URI, "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": EXPECTED_TIMESTAMP, "tools": [EXPECTED_TOOL],
            "properties": [EXPECTED_TARGET_PROPERTY],
            "component": {
                "type": root_component_type(root_package), "bom-ref": ref_map[root_id],
                "name": name, "version": version, "scope": "required",
                "purl": canonical_purl(name, version), "components": canonical_targets,
            },
        },
        "components": canonical_components, "dependencies": canonical_dependencies,
    }
    canonical = json.dumps(
        canonical_document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    reparsed = parse_json(canonical, f"canonical SBOM {name}")
    if json.dumps(reparsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n" != canonical:
        fail(f"canonical SBOM {name} is not idempotent")
    return canonical


def reject_forbidden_strings(value: Any, forbidden_prefixes: tuple[str, ...], label: str) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            forms = {item}
            decoded = item
            for _ in range(3):
                decoded = unquote(decoded)
                forms.add(decoded)
            lowered = {form.lower() for form in forms}
            if any("file://" in form or "path+file:" in form for form in lowered):
                fail(f"{label} retains a local file URI")
            for prefix in forbidden_prefixes:
                encoded = quote(prefix, safe="")
                if any(prefix in form or encoded.lower() in form.lower() for form in forms):
                    fail(f"{label} retains forbidden local path material")


def load_lock_checksums(lock_bytes: bytes) -> dict[tuple[str, str, str | None], str | None]:
    try:
        lock_text = lock_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"Cargo.lock is not UTF-8: {error}")
    if not lock_text.startswith("# This file is automatically @generated by Cargo.\n") or "\nversion = 4\n" not in lock_text:
        fail("Cargo.lock is not canonical lockfile version 4")
    try:
        document = tomllib.loads(lock_text)
    except tomllib.TOMLDecodeError as error:
        fail(f"Cargo.lock is malformed: {error}")
    if document.get("version") != 4:
        fail("Cargo.lock is not version 4")
    result: dict[tuple[str, str, str | None], str | None] = {}
    for raw_entry in require_list(document.get("package"), "Cargo.lock packages"):
        entry = require_dict(raw_entry, "Cargo.lock package")
        source = entry.get("source")
        if source is not None and not isinstance(source, str):
            fail("Cargo.lock source must be text or null")
        key = (
            require_text(entry.get("name"), "Cargo.lock package name"),
            require_text(entry.get("version"), "Cargo.lock package version"), source,
        )
        if key in result:
            fail("Cargo.lock contains a duplicate package identity")
        checksum = entry.get("checksum")
        if checksum is not None and (not isinstance(checksum, str) or SHA256_PATTERN.fullmatch(checksum) is None):
            fail(f"Cargo.lock checksum for {key[0]}@{key[1]} is invalid")
        result[key] = checksum
    return result


def read_raw_set(input_path: Path, expected_names: list[str]) -> dict[str, bytes]:
    try:
        directory = os.open(input_path, open_flags(directory=True))
    except OSError as error:
        fail(f"cannot securely open raw SBOM directory: {error}")
    try:
        if sorted(os.listdir(directory)) != expected_names:
            fail("raw SBOM directory does not exactly match Cargo workspace inventory")
        result: dict[str, bytes] = {}
        for name in expected_names:
            try:
                descriptor = os.open(name, open_flags(), dir_fd=directory)
            except OSError as error:
                fail(f"cannot securely open raw SBOM {name}: {error}")
            try:
                result[name] = read_stable_descriptor(descriptor, RAW_FILE_LIMIT, f"raw SBOM {name}")
            finally:
                os.close(descriptor)
        if sorted(os.listdir(directory)) != expected_names:
            fail("raw SBOM directory changed while it was read")
        return result
    finally:
        os.close(directory)


def prepare_output(path: Path) -> int:
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        try:
            parent = path.parent.resolve(strict=True)
            os.mkdir(parent / path.name, 0o700)
            path = parent / path.name
        except OSError as error:
            fail(f"cannot create output directory: {error}")
    except OSError as error:
        fail(f"cannot inspect output directory: {error}")
    else:
        if not stat.S_ISDIR(status.st_mode):
            fail("output path must be a real directory")
    try:
        directory = os.open(path, open_flags(directory=True))
    except OSError as error:
        fail(f"cannot securely open output directory: {error}")
    if os.listdir(directory):
        os.close(directory)
        fail("output directory must start empty")
    return directory


def write_outputs(output_path: Path, outputs: dict[str, bytes]) -> None:
    directory = prepare_output(output_path)
    created: list[str] = []
    complete = False
    try:
        for name in sorted(outputs):
            payload = outputs[name]
            descriptor = os.open(
                name, open_flags(writable=True) | os.O_CREAT | os.O_EXCL, 0o644,
                dir_fd=directory,
            )
            created.append(name)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        fail(f"short write while creating {name}")
                    offset += written
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if sorted(os.listdir(directory)) != sorted(outputs):
            fail("output directory changed during canonicalization")
        complete = True
    finally:
        if not complete:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    pass
        os.close(directory)


def main() -> None:
    if sys.version_info[:2] < (3, 11):
        fail("Python 3.11 or newer is required for strict TOML parsing")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--cargo-metadata", required=True)
    parser.add_argument("--cargo-lock", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--forbid-prefix", action="append", required=True)
    args = parser.parse_args()
    if VERSION_PATTERN.fullmatch(args.version) is None:
        fail("release version must contain exactly three numeric components")
    paths = tuple(Path(value) for value in (args.input_dir, args.output_dir, args.cargo_metadata, args.cargo_lock))
    if any(not path.is_absolute() for path in paths):
        fail("all filesystem arguments must be absolute")
    forbidden = tuple(sorted({str(Path(value)).rstrip("/") for value in args.forbid_prefix}))
    if not forbidden or any(not Path(value).is_absolute() for value in forbidden):
        fail("forbidden prefixes must be absolute paths")

    metadata = require_dict(
        parse_json(read_regular(paths[2], METADATA_LIMIT, "Cargo metadata"), "Cargo metadata"),
        "Cargo metadata",
    )
    lock_checksums = load_lock_checksums(read_regular(paths[3], LOCK_LIMIT, "Cargo.lock"))
    packages_by_id: dict[str, dict[str, Any]] = {}
    checksums: dict[str, str | None] = {}
    for raw_package in require_list(metadata.get("packages"), "Cargo metadata packages"):
        package = require_dict(raw_package, "Cargo package")
        package_id = require_text(package.get("id"), "Cargo package id")
        if package_id in packages_by_id:
            fail("Cargo metadata contains duplicate package ids")
        key = package_key(package)
        if key not in lock_checksums:
            fail(f"Cargo metadata package {key[0]}@{key[1]} is absent from Cargo.lock")
        packages_by_id[package_id] = package
        checksums[package_id] = lock_checksums[key]
    member_values = require_list(metadata.get("workspace_members"), "Cargo workspace members")
    if any(not isinstance(value, str) for value in member_values):
        fail("Cargo workspace member ids must be text")
    workspace_ids = set(member_values)
    if len(workspace_ids) != len(member_values) or not workspace_ids <= set(packages_by_id):
        fail("Cargo workspace member inventory is invalid")
    workspace_packages = [
        packages_by_id[package_id] for package_id in workspace_ids
        if "/crates/" in require_text(packages_by_id[package_id].get("manifest_path"), "manifest path")
        and packages_by_id[package_id].get("publish") != []
    ]
    workspace_packages.sort(key=lambda package: package["name"])
    if len(workspace_packages) != 32 or len({package["name"] for package in workspace_packages}) != 32:
        fail("Cargo metadata must expose exactly 32 uniquely named publishable workspace crates")
    graph, normal_edges = filtered_resolve_graph(metadata)
    if set(graph) != set(packages_by_id):
        fail("Cargo resolve graph must contain exactly every Cargo metadata package")
    if any(not targets <= set(packages_by_id) for targets in graph.values()):
        fail("Cargo resolve graph refers to an unknown package")

    expected_names = sorted(f"{package['name']}.cdx.json" for package in workspace_packages)
    raw_payloads = read_raw_set(paths[0], expected_names)
    outputs: dict[str, bytes] = {}
    for package in workspace_packages:
        name = package["name"]
        canonical = validate_raw_document(
            raw_payloads[f"{name}.cdx.json"], package, packages_by_id, checksums,
            workspace_ids, graph, normal_edges, args.version,
        )
        reject_forbidden_strings(parse_json(canonical, f"canonical SBOM {name}"), forbidden, f"canonical SBOM {name}")
        outputs[f"exochain-{args.version}-{name}.cdx.json"] = canonical
    if len(outputs) != 32:
        fail("canonical SBOM set does not contain exactly 32 unique files")
    write_outputs(paths[1], outputs)
    digest = hashlib.sha256()
    for name in sorted(outputs):
        payload = outputs[name]
        digest.update(name.encode("ascii") + b"\0")
        digest.update(str(len(payload)).encode("ascii") + b"\0")
        digest.update(hashlib.sha256(payload).digest())
    print(digest.hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, OverflowError, RecursionError, ValueError) as error:
        fail(str(error))
