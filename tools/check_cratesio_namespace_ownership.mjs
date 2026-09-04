#!/usr/bin/env node
/* Copyright 2026 Exochain Foundation
 * SPDX-License-Identifier: Apache-2.0
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 15_000;
const MAX_JSON_DEPTH = 64;

// Intentionally duplicated in the token-free packager and live publisher. The
// release guard compares all literal inventories so no package can silently
// enter or leave only one trust boundary.
const CANONICAL_CRATES = Object.freeze([
  "exochain-core",
  "exochain-dag-db-api",
  "exochain-identity",
  "exochain-api",
  "exochain-authority",
  "exochain-pdp",
  "exochain-avc",
  "exochain-consent",
  "exochain-dag-db-core",
  "exochain-dag-db-graph",
  "exochain-dag-db-domain",
  "exochain-dag-db-retrieval",
  "exochain-dag-db-exchange",
  "exochain-dag",
  "exochain-dag-db-postgres",
  "exochain-gatekeeper",
  "exochain-proofs",
  "exochain-governance",
  "exochain-escalation",
  "exochain-tenant",
  "exochain-catapult",
  "exochain-legal",
  "exochain-decision-forum",
  "exochain-consensus",
  "exochain-dag-db-lab",
  "exochain-economy",
  "exochain-gateway",
  "exochain-messaging",
  "exochain-root",
  "exochain-sdk",
  "exochain-node",
  "exochain-wasm",
]);

class StrictJsonScanner {
  constructor(text, label) {
    this.text = text;
    this.label = label;
    this.index = 0;
  }

  fail(message) {
    throw new Error(`${this.label} contains invalid JSON: ${message}`);
  }

  whitespace() {
    while (/\s/u.test(this.text[this.index] ?? "")) {
      this.index += 1;
    }
  }

  string() {
    const start = this.index;
    if (this.text[this.index] !== '"') {
      this.fail("expected a string");
    }
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        const token = this.text.slice(start, this.index);
        try {
          return JSON.parse(token);
        } catch {
          this.fail("malformed string escape");
        }
      }
      if (code < 0x20) {
        this.fail("unescaped control character in string");
      }
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) {
            this.fail("malformed Unicode escape");
          }
          this.index += 5;
          continue;
        }
        if (!['"', "\\", "/", "b", "f", "n", "r", "t"].includes(escape)) {
          this.fail("malformed escape");
        }
      }
      this.index += 1;
    }
    this.fail("unterminated string");
  }

  value(depth) {
    if (depth > MAX_JSON_DEPTH) {
      this.fail("nesting exceeds the accepted depth");
    }
    this.whitespace();
    const character = this.text[this.index];
    if (character === "{") {
      this.object(depth + 1);
      return;
    }
    if (character === "[") {
      this.array(depth + 1);
      return;
    }
    if (character === '"') {
      this.string();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return;
      }
    }
    const number = this.text.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0];
    if (number !== undefined) {
      if (!Number.isFinite(Number(number))) {
        this.fail("non-finite number");
      }
      this.index += number.length;
      return;
    }
    this.fail("unexpected token");
  }

  object(depth) {
    this.index += 1;
    this.whitespace();
    const keys = new Set();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }
    for (;;) {
      const key = this.string();
      if (keys.has(key)) {
        this.fail(`duplicate object key ${JSON.stringify(key)}`);
      }
      keys.add(key);
      this.whitespace();
      if (this.text[this.index] !== ":") {
        this.fail("expected ':' after object key");
      }
      this.index += 1;
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === "}") {
        this.index += 1;
        return;
      }
      if (this.text[this.index] !== ",") {
        this.fail("expected ',' or '}' in object");
      }
      this.index += 1;
      this.whitespace();
    }
  }

  array(depth) {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }
    for (;;) {
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === "]") {
        this.index += 1;
        return;
      }
      if (this.text[this.index] !== ",") {
        this.fail("expected ',' or ']' in array");
      }
      this.index += 1;
      this.whitespace();
    }
  }

  scan() {
    this.whitespace();
    this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) {
      this.fail("trailing data");
    }
  }
}

function parseStrictJson(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8: ${error.message}`);
  }
  new StrictJsonScanner(text, label).scan();
  return JSON.parse(text);
}

function stableStat(statValue) {
  return [
    statValue.dev,
    statValue.ino,
    statValue.mode,
    statValue.nlink,
    statValue.size,
    statValue.mtimeNs,
    statValue.ctimeNs,
  ].join(":");
}

function readSecureFixture(fixturePath, label) {
  for (const requiredFlag of ["O_NOFOLLOW", "O_NONBLOCK"]) {
    if (typeof fs.constants[requiredFlag] !== "number") {
      throw new Error(`platform lacks ${requiredFlag} for secure fixture reads`);
    }
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      fixturePath,
      fs.constants.O_RDONLY
        | fs.constants.O_NOFOLLOW
        | fs.constants.O_NONBLOCK,
    );
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw new Error(`${label} cannot be securely opened: ${error.message}`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      throw new Error(`${label} must be one regular non-symlink, non-hardlinked file`);
    }
    if (before.size <= 0n || before.size > BigInt(MAX_RESPONSE_BYTES)) {
      throw new Error(`${label} size is outside the accepted range`);
    }
    const buffer = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(descriptor, buffer, offset, buffer.length - offset, null);
      if (count === 0) {
        throw new Error(`${label} was truncated while it was read`);
      }
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (stableStat(before) !== stableStat(after)) {
      throw new Error(`${label} changed while it was read`);
    }
    return parseStrictJson(buffer, label);
  } finally {
    fs.closeSync(descriptor);
  }
}

async function readBoundedResponse(response, label) {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) {
      throw new Error(`${label} returned a malformed Content-Length`);
    }
    const declaredLength = Number(contentLength);
    if (declaredLength <= 0 || declaredLength > MAX_RESPONSE_BYTES) {
      throw new Error(`${label} declared a response outside the accepted size`);
    }
  }
  if (response.body === null) {
    throw new Error(`${label} returned no response body`);
  }
  const chunks = [];
  let total = 0;
  const reader = response.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`${label} exceeded the accepted response size`);
    }
    chunks.push(Buffer.from(value));
  }
  if (total === 0) {
    throw new Error(`${label} returned an empty response`);
  }
  return parseStrictJson(Buffer.concat(chunks, total), label);
}

const allowedOwnersConfig = process.env.EXOCHAIN_CRATES_IO_ALLOWED_OWNERS;
if (typeof allowedOwnersConfig !== "string" || allowedOwnersConfig.trim() === "") {
  throw new Error(
    "EXOCHAIN_CRATES_IO_ALLOWED_OWNERS must be explicitly configured with at least one crates.io owner login",
  );
}

const ownerLoginPattern = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/iu;
const configuredOwners = allowedOwnersConfig.split(",").map((owner) => owner.trim().toLowerCase());
if (
  configuredOwners.some((owner) => !ownerLoginPattern.test(owner))
  || new Set(configuredOwners).size !== configuredOwners.length
) {
  throw new Error(
    "EXOCHAIN_CRATES_IO_ALLOWED_OWNERS contains a duplicate, empty, or malformed crates.io owner login",
  );
}
const allowedOwners = new Set(configuredOwners);

function resolvePackageNames() {
  const exactTarget = process.env.EXOCHAIN_CRATES_IO_EXACT_TARGET;
  if (exactTarget !== undefined) {
    if (!CANONICAL_CRATES.includes(exactTarget)) {
      throw new Error("EXOCHAIN_CRATES_IO_EXACT_TARGET is not one of the exact 32 release crates");
    }
    return [exactTarget];
  }

  const metadataBytes = execFileSync("cargo", [
    "metadata",
    "--manifest-path",
    path.resolve("Cargo.toml"),
    "--no-deps",
    "--format-version",
    "1",
    "--locked",
  ], {
    encoding: "buffer",
    maxBuffer: 20 * 1024 * 1024,
  });
  const metadata = parseStrictJson(metadataBytes, "Cargo metadata");
  if (
    typeof metadata !== "object"
    || metadata === null
    || !Array.isArray(metadata.workspace_members)
    || !Array.isArray(metadata.packages)
  ) {
    throw new Error("Cargo metadata lacks package or workspace-member arrays");
  }
  const workspacePackageIds = new Set(metadata.workspace_members);
  const packageNames = metadata.packages
    .filter((pkg) => workspacePackageIds.has(pkg.id))
    .filter((pkg) => pkg.publish !== false && !(Array.isArray(pkg.publish) && pkg.publish.length === 0))
    .map((pkg) => pkg.name);
  const actual = [...packageNames].sort();
  const expected = [...CANONICAL_CRATES].sort();
  if (
    actual.length !== 32
    || new Set(actual).size !== 32
    || actual.some((name, index) => name !== expected[index])
  ) {
    throw new Error("publishable Cargo metadata differs from the exact 32-crate release inventory");
  }
  return [...CANONICAL_CRATES];
}

const fixtureDir = process.env.EXOCHAIN_CRATES_IO_FIXTURE_DIR;
const requireClaimedConfig = process.env.EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED;
if (requireClaimedConfig !== undefined && requireClaimedConfig !== "true") {
  throw new Error("EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED must be exactly true when set");
}
const requireClaimed = requireClaimedConfig === "true";

async function fetchJson(url, label, acceptedStatuses) {
  const response = await fetch(url, {
    headers: {
      "User-Agent": "exochain-release-namespace-guard (https://github.com/exochain/exochain)",
    },
    redirect: "error",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!acceptedStatuses.includes(response.status)) {
    throw new Error(`${label} failed: HTTP ${response.status}`);
  }
  if (response.status === 404) {
    if (response.body !== null) {
      await response.body.cancel();
    }
    return null;
  }
  return readBoundedResponse(response, label);
}

async function loadPublishedCrateOwners(crateName) {
  if (fixtureDir !== undefined) {
    if (!path.isAbsolute(fixtureDir)) {
      throw new Error("EXOCHAIN_CRATES_IO_FIXTURE_DIR must be absolute");
    }
    return readSecureFixture(
      path.join(fixtureDir, `${crateName}.json`),
      `fixture for ${crateName}`,
    );
  }

  const cratePayload = await fetchJson(
    `https://crates.io/api/v1/crates/${encodeURIComponent(crateName)}`,
    `crates.io lookup for ${crateName}`,
    [200, 404],
  );
  if (cratePayload === null) {
    return null;
  }
  if (
    typeof cratePayload !== "object"
    || cratePayload === null
    || Array.isArray(cratePayload)
    || typeof cratePayload.crate !== "object"
    || cratePayload.crate === null
    || cratePayload.crate.id !== crateName
  ) {
    throw new Error(`crates.io lookup for ${crateName} returned a mismatched crate identity`);
  }
  return fetchJson(
    `https://crates.io/api/v1/crates/${encodeURIComponent(crateName)}/owners`,
    `crates.io owner lookup for ${crateName}`,
    [200],
  );
}

const packageNames = resolvePackageNames();
const failures = [];

for (const crateName of packageNames) {
  if (!crateName.startsWith("exochain-")) {
    failures.push(`${crateName} does not use the exochain-* namespace`);
    continue;
  }

  const payload = await loadPublishedCrateOwners(crateName);
  if (payload === null) {
    if (requireClaimed) {
      failures.push(`${crateName} must already be claimed by an approved crates.io owner`);
    }
    continue;
  }

  if (typeof payload !== "object" || Array.isArray(payload) || !Array.isArray(payload.users)) {
    failures.push(`${crateName} returned a malformed crates.io owner response without a users array`);
    continue;
  }
  if (payload.users.length === 0) {
    failures.push(`${crateName} returned an empty crates.io owner response`);
    continue;
  }

  const ownerLogins = [];
  let malformedOwnerRecord = false;
  for (const user of payload.users) {
    if (
      typeof user !== "object"
      || user === null
      || Array.isArray(user)
      || typeof user.login !== "string"
      || !ownerLoginPattern.test(user.login)
    ) {
      malformedOwnerRecord = true;
      break;
    }
    ownerLogins.push(user.login.toLowerCase());
  }
  if (malformedOwnerRecord) {
    failures.push(`${crateName} returned a malformed crates.io owner record`);
    continue;
  }

  const unapprovedOwners = [...new Set(ownerLogins.filter((login) => !allowedOwners.has(login)))];
  if (unapprovedOwners.length > 0) {
    failures.push(`${crateName} has an unapproved crates.io owner: [${unapprovedOwners.join(", ")}]`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`crates.io namespace ownership guard passed for ${packageNames.length} package(s)`);
