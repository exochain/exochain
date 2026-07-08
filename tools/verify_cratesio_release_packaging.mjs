#!/usr/bin/env node
/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const workspaceToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
const workspaceVersion = workspaceToml.match(/^\[workspace\.package\][\s\S]*?^version = "([^"]+)"/m)?.[1];

if (!workspaceVersion) {
  throw new Error("workspace package version is missing");
}
if (!/^0\.2\.1-beta$/.test(workspaceVersion)) {
  throw new Error(`workspace package version must be 0.2.1-beta for this release, got ${workspaceVersion}`);
}
if (!/^\[workspace\.package\][\s\S]*^publish = true$/m.test(workspaceToml)) {
  throw new Error("workspace package publish must be true for release packaging");
}

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  }),
);

const workspacePackageIds = new Set(metadata.workspace_members);
const packages = metadata.packages.filter((pkg) => workspacePackageIds.has(pkg.id));
const packageNames = new Set(packages.map((pkg) => pkg.name));
const cratePackageMap = new Map(
  packages
    .filter((pkg) => pkg.manifest_path.includes("/crates/"))
    .map((pkg) => [path.basename(path.dirname(pkg.manifest_path)), pkg.name]),
);

const failures = [];
const canonicalDagDbFixturePath = path.join(
  repoRoot,
  "crates/exo-dag-db-api/fixtures/json/all_dto_fixtures.json",
);
const nodeDagDbFixturePath = path.join(
  repoRoot,
  "crates/exo-node/fixtures/dagdb/all_dto_fixtures.json",
);
const nodeDagDbToolPath = path.join(repoRoot, "crates/exo-node/src/mcp/tools/dagdb.rs");
const nodeDagDbToolSource = fs.readFileSync(nodeDagDbToolPath, "utf8");

if (nodeDagDbToolSource.includes("../../../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json")) {
  failures.push("exochain-node must not include DAG DB fixtures from outside its package tarball");
}
if (!nodeDagDbToolSource.includes("../../../fixtures/dagdb/all_dto_fixtures.json")) {
  failures.push("exochain-node DAG DB MCP schema binding must use its packaged DAG DB fixture copy");
}
if (!fs.existsSync(nodeDagDbFixturePath)) {
  failures.push("exochain-node package must include fixtures/dagdb/all_dto_fixtures.json");
} else {
  const nodeDagDbFixture = fs.readFileSync(nodeDagDbFixturePath, "utf8");
  const canonicalDagDbFixture = fs.readFileSync(canonicalDagDbFixturePath, "utf8");
  if (nodeDagDbFixture !== canonicalDagDbFixture) {
    failures.push("exochain-node packaged DAG DB fixture must match the canonical exo-dag-db-api fixture");
  }
}

const requiredBinaryNamesByLegacyDir = new Map([
  ["exo-gateway", "exo-gateway"],
  ["exo-node", "exochain"],
]);

for (const pkg of packages) {
  const relativeManifest = path.relative(repoRoot, pkg.manifest_path);
  if (relativeManifest === "fuzz/Cargo.toml") {
    if (pkg.name !== "exo-fuzz" || pkg.version !== "0.0.0") {
      failures.push("fuzz package must remain unpublished exo-fuzz 0.0.0");
    }
    continue;
  }

  if (!pkg.manifest_path.includes("/crates/")) {
    failures.push(`unexpected workspace package outside crates/: ${relativeManifest}`);
    continue;
  }

  const legacyDirName = path.basename(path.dirname(pkg.manifest_path));
  const expectedName = legacyDirName.startsWith("exo-")
    ? `exochain-${legacyDirName.slice("exo-".length)}`
    : legacyDirName === "decision-forum"
      ? "exochain-decision-forum"
      : legacyDirName;

  if (pkg.name !== expectedName) {
    failures.push(`${relativeManifest} package name must be ${expectedName}, got ${pkg.name}`);
  }
  if (!pkg.name.startsWith("exochain-")) {
    failures.push(`${relativeManifest} package name must use the exochain-* crates.io namespace`);
  }
  if (pkg.name.startsWith("exo-") || pkg.name === "decision-forum") {
    failures.push(`${relativeManifest} still uses legacy or first-come-sensitive package name ${pkg.name}`);
  }
  if (pkg.version !== workspaceVersion) {
    failures.push(`${relativeManifest} version ${pkg.version} does not match workspace ${workspaceVersion}`);
  }
  if (!pkg.description || !pkg.description.trim()) {
    failures.push(`${relativeManifest} must include a crates.io package description`);
  }
  if (Array.isArray(pkg.publish) && pkg.publish.length === 0) {
    failures.push(`${relativeManifest} is still publish=false through workspace inheritance`);
  }

  const libTarget = pkg.targets.find((target) => target.kind.includes("lib"));
  if (libTarget) {
    const expectedLibName = legacyDirName.replaceAll("-", "_");
    if (libTarget.name !== expectedLibName) {
      failures.push(`${relativeManifest} lib target must remain ${expectedLibName}, got ${libTarget.name}`);
    }
  }

  const requiredBinaryName = requiredBinaryNamesByLegacyDir.get(legacyDirName);
  if (requiredBinaryName) {
    const hasRequiredBinary = pkg.targets.some(
      (target) => target.kind.includes("bin") && target.name === requiredBinaryName,
    );
    if (!hasRequiredBinary) {
      failures.push(`${relativeManifest} must preserve binary target ${requiredBinaryName}`);
    }
  }

  const manifestText = fs.readFileSync(pkg.manifest_path, "utf8");
  const pathDependencyLines = manifestText
    .split(/\r?\n/)
    .filter((line) => /= \{/.test(line) && /path = "\.\./.test(line));

  for (const line of pathDependencyLines) {
    const dependencyKey = line.match(/^([A-Za-z0-9_-]+)\s*=/)?.[1];
    const dependencyPath = line.match(/path = "\.\.\/([^"]+)"/)?.[1];
    if (!dependencyKey || !dependencyPath) {
      failures.push(`${relativeManifest} has unparsable path dependency line: ${line}`);
      continue;
    }

    const targetPackage = cratePackageMap.get(dependencyPath);
    if (!targetPackage) {
      failures.push(`${relativeManifest} path dependency ${dependencyKey} points at non-workspace crate ${dependencyPath}`);
      continue;
    }
    if (!line.includes(`package = "${targetPackage}"`)) {
      failures.push(`${relativeManifest} dependency ${dependencyKey} must set package = "${targetPackage}"`);
    }
    if (!line.includes(`version = "=${workspaceVersion}"`)) {
      failures.push(`${relativeManifest} dependency ${dependencyKey} must set version = "=${workspaceVersion}"`);
    }
  }
}

const releaseWorkflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");
const releaseCrateBlock = releaseWorkflow.match(/CRATES=\(\n([\s\S]*?)\n[ \t]*\)/)?.[1];
if (!releaseCrateBlock) {
  failures.push("release publish loop must declare a CRATES bash array");
}
const releasePackageNames = releaseCrateBlock
  ? releaseCrateBlock
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
  : [];
const releasePackageIndexes = new Map(releasePackageNames.map((name, index) => [name, index]));

for (const pkg of packages.filter((pkg) => pkg.manifest_path.includes("/crates/"))) {
  if (!releaseWorkflow.includes(`            ${pkg.name}`)) {
    failures.push(`release publish loop must include ${pkg.name}`);
  }
}

for (const crateName of releasePackageNames) {
  if (!packageNames.has(crateName)) {
    failures.push(`release publish loop includes unknown package ${crateName}`);
  }
}
if (releasePackageIndexes.size !== releasePackageNames.length) {
  failures.push("release publish loop must not contain duplicate packages");
}

for (const pkg of packages.filter((pkg) => pkg.manifest_path.includes("/crates/"))) {
  const packageIndex = releasePackageIndexes.get(pkg.name);
  if (packageIndex === undefined) {
    continue;
  }

  const manifestText = fs.readFileSync(pkg.manifest_path, "utf8");
  const pathDependencyLines = manifestText
    .split(/\r?\n/)
    .filter((line) => /= \{/.test(line) && /path = "\.\./.test(line));

  for (const line of pathDependencyLines) {
    const dependencyPath = line.match(/path = "\.\.\/([^"]+)"/)?.[1];
    const targetPackage = dependencyPath ? cratePackageMap.get(dependencyPath) : undefined;
    if (!targetPackage) {
      continue;
    }
    const dependencyIndex = releasePackageIndexes.get(targetPackage);
    if (dependencyIndex !== undefined && dependencyIndex > packageIndex) {
      failures.push(`release publish loop must publish ${targetPackage} before ${pkg.name}`);
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`crates.io release packaging verifier passed for ${releasePackageNames.length} package(s) at ${workspaceVersion}`);
