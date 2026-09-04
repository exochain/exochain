#!/usr/bin/env node
// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import { X509Certificate } from 'node:crypto';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_DEPTH = 64;
const EXPECTED_REPOSITORY = 'https://github.com/exochain/exochain';
const EXPECTED_WORKFLOW_PATH = '.github/workflows/release.yml';
const EXPECTED_REGISTRY = 'https://registry.npmjs.org';
const PUBLISH_PREDICATE = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const PROVENANCE_PREDICATE = 'https://slsa.dev/provenance/v1';
const GITHUB_ACTIONS_BUILD_TYPE = 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1';

function fail(message) {
  console.error(`npm registry attestation verification failed: ${message}`);
  process.exit(1);
}

class StrictJsonScanner {
  constructor(text) { this.text = text; this.index = 0; }
  error(message) { throw new Error(message); }
  whitespace() { while (/\s/u.test(this.text[this.index] ?? '')) this.index += 1; }
  string() {
    const start = this.index;
    if (this.text[this.index] !== '"') this.error('expected string');
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        return JSON.parse(this.text.slice(start, this.index));
      }
      if (code < 0x20) this.error('unescaped control character');
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(this.text.slice(this.index + 1, this.index + 5))) {
            this.error('malformed Unicode escape');
          }
          this.index += 5;
          continue;
        }
        if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) {
          this.error('malformed escape');
        }
      }
      this.index += 1;
    }
    this.error('unterminated string');
  }
  value(depth) {
    if (depth > MAX_DEPTH) this.error('nesting exceeds limit');
    this.whitespace();
    const character = this.text[this.index];
    if (character === '{') return this.object(depth + 1);
    if (character === '[') return this.array(depth + 1);
    if (character === '"') { this.string(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return;
      }
    }
    const number = this.text.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0];
    if (number !== undefined && Number.isFinite(Number(number))) {
      this.index += number.length;
      return;
    }
    this.error('unexpected token');
  }
  object(depth) {
    this.index += 1;
    this.whitespace();
    const keys = new Set();
    if (this.text[this.index] === '}') { this.index += 1; return; }
    for (;;) {
      const key = this.string();
      if (keys.has(key)) this.error(`duplicate key ${key}`);
      keys.add(key);
      this.whitespace();
      if (this.text[this.index] !== ':') this.error("expected ':'");
      this.index += 1;
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === '}') { this.index += 1; return; }
      if (this.text[this.index] !== ',') this.error("expected ',' or '}'");
      this.index += 1;
      this.whitespace();
    }
  }
  array(depth) {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === ']') { this.index += 1; return; }
    for (;;) {
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === ']') { this.index += 1; return; }
      if (this.text[this.index] !== ',') this.error("expected ',' or ']'");
      this.index += 1;
      this.whitespace();
    }
  }
  scan() {
    this.whitespace();
    this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) this.error('trailing data');
  }
}

function stableStat(value) {
  return [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs].join(':');
}

function readJson(filePath, label) {
  if (typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_NONBLOCK !== 'number') {
    fail('platform lacks secure file-open flags');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(MAX_BYTES)) {
      fail(`${label} must be one bounded regular file`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) fail(`${label} was truncated while read`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (stableStat(before) !== stableStat(after)) fail(`${label} changed while read`);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    new StrictJsonScanner(text).scan();
    return JSON.parse(text);
  } catch (error) {
    fail(`cannot parse ${label}: ${error.message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function exactString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\n') || value.includes('\0')) {
    fail(`${label} is invalid`);
  }
  return value;
}

function decodeStatement(payload, label) {
  if (typeof payload !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/u.test(payload)) {
    fail(`${label} statement is not canonical base64`);
  }
  try {
    const bytes = Buffer.from(payload, 'base64');
    if (bytes.toString('base64') !== payload) fail(`${label} statement has non-canonical base64`);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    new StrictJsonScanner(text).scan();
    return JSON.parse(text);
  } catch (error) {
    fail(`${label} statement is invalid: ${error.message}`);
  }
}

function canonicalBase64Bytes(value, label) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    fail(`${label} is not canonical base64`);
  }
  try {
    const bytes = Buffer.from(value, 'base64');
    if (bytes.length === 0 || bytes.toString('base64') !== value) fail(`${label} is not canonical base64`);
    return bytes;
  } catch (error) {
    fail(`${label} is malformed: ${error.message}`);
  }
}

function verifyEnvelope(bundle, label) {
  if (bundle?.mediaType !== 'application/vnd.dev.sigstore.bundle+json;version=0.2') {
    fail(`${label} has an unsupported Sigstore bundle format`);
  }
  const envelope = bundle?.dsseEnvelope;
  if (envelope?.payloadType !== 'application/vnd.in-toto+json'
      || !Array.isArray(envelope?.signatures) || envelope.signatures.length !== 1) {
    fail(`${label} has an invalid DSSE envelope`);
  }
  canonicalBase64Bytes(envelope.signatures[0]?.sig, `${label} signature`);
  return decodeStatement(envelope.payload, label);
}

function expectedSubject(name, version, integrity) {
  if (!integrity.startsWith('sha512-')) fail('expected integrity is not SHA-512 SRI');
  let digest;
  try {
    const encoded = integrity.slice('sha512-'.length);
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.length !== 64 || bytes.toString('base64') !== encoded) fail('expected integrity is malformed');
    digest = bytes.toString('hex');
  } catch (error) {
    fail(`expected integrity is malformed: ${error.message}`);
  }
  return {
    name: `pkg:npm/${name.replace(/^@/u, '%40')}@${version}`,
    digest,
  };
}

function verifySubject(statement, expected, label) {
  const subjects = statement?.subject;
  if (!Array.isArray(subjects) || subjects.length !== 1
      || subjects[0]?.name !== expected.name
      || subjects[0]?.digest?.sha512 !== expected.digest
      || Object.keys(subjects[0]?.digest ?? {}).length !== 1) {
    fail(`${label} subject does not bind the exact npm tarball`);
  }
}

function verifyRegistry(response, name, version, integrity, maintainerName, maintainerEmail) {
  const expectedMaintainers = [{ name: maintainerName, email: maintainerEmail }];
  const unscopedName = name.split('/').at(-1);
  const expectedTarball = `${EXPECTED_REGISTRY}/${name}/-/${unscopedName}-${version}.tgz`;
  if (response?.name !== name || response?.version !== version || response?.dist?.integrity !== integrity) {
    fail('registry identity or integrity differs from the release');
  }
  if (response.dist.tarball !== expectedTarball) {
    fail('registry tarball URL differs from the exact canonical package artifact');
  }
  if (JSON.stringify(response.maintainers) !== JSON.stringify(expectedMaintainers)) {
    fail('registry maintainers differ from the exact release owner policy');
  }
  if (JSON.stringify(response._npmUser) !== JSON.stringify(expectedMaintainers[0])) {
    fail('registry publisher identity differs from the exact release owner policy');
  }
  if (!Array.isArray(response.dist.signatures) || response.dist.signatures.length === 0
      || response.dist.signatures.some((entry) => typeof entry?.keyid !== 'string' || typeof entry?.sig !== 'string')) {
    fail('registry response has no signed package record');
  }
  if (response.dist.attestations?.provenance?.predicateType !== PROVENANCE_PREDICATE
      || typeof response.dist.attestations?.url !== 'string'
      || !response.dist.attestations.url.startsWith(`${EXPECTED_REGISTRY}/-/npm/v1/attestations/`)) {
    fail('registry response has no exact provenance locator');
  }
}

function verifyAudit(response, name, version, integrity, expectedCommit, expectedRef) {
  if (!Array.isArray(response?.invalid) || response.invalid.length !== 0
      || !Array.isArray(response?.missing) || response.missing.length !== 0
      || !Array.isArray(response?.verified)) {
    fail('npm audit result contains invalid or missing signatures');
  }
  const matches = response.verified.filter((entry) => entry?.name === name && entry?.version === version);
  if (matches.length !== 1) fail('npm audit did not verify exactly one release package');
  const entry = matches[0];
  if (entry.registry !== `${EXPECTED_REGISTRY}/`
      || entry.attestations?.provenance?.predicateType !== PROVENANCE_PREDICATE
      || !Array.isArray(entry.attestationBundles)) {
    fail('npm audit result lacks the verified provenance bundle');
  }

  const expected = expectedSubject(name, version, integrity);
  const publishBundles = entry.attestationBundles.filter((bundle) => bundle?.predicateType === PUBLISH_PREDICATE);
  const provenanceBundles = entry.attestationBundles.filter((bundle) => bundle?.predicateType === PROVENANCE_PREDICATE);
  if (publishBundles.length !== 1 || provenanceBundles.length !== 1) {
    fail('npm audit must verify one publish and one provenance attestation');
  }

  const publish = publishBundles[0];
  const publishStatement = verifyEnvelope(publish?.bundle, 'publish');
  verifySubject(publishStatement, expected, 'publish');
  if (publishStatement?.predicateType !== PUBLISH_PREDICATE
      || publishStatement?.predicate?.name !== name
      || publishStatement?.predicate?.version !== version
      || publishStatement?.predicate?.registry !== EXPECTED_REGISTRY) {
    fail('publish attestation predicate differs from the release');
  }
  if (!Array.isArray(publish?.bundle?.verificationMaterial?.tlogEntries)
      || publish.bundle.verificationMaterial.tlogEntries.length === 0) {
    fail('publish attestation has no transparency-log proof');
  }

  const provenance = provenanceBundles[0];
  const statement = verifyEnvelope(provenance?.bundle, 'provenance');
  verifySubject(statement, expected, 'provenance');
  if (statement?.predicateType !== PROVENANCE_PREDICATE) fail('wrong provenance predicate type');
  const definition = statement?.predicate?.buildDefinition;
  const workflow = definition?.externalParameters?.workflow;
  if (definition?.buildType !== GITHUB_ACTIONS_BUILD_TYPE
      || workflow?.repository !== EXPECTED_REPOSITORY
      || workflow?.path !== EXPECTED_WORKFLOW_PATH
      || workflow?.ref !== expectedRef) {
    fail('provenance workflow identity differs from exochain/exochain release.yml');
  }
  const dependencies = definition?.resolvedDependencies;
  if (!Array.isArray(dependencies) || dependencies.length !== 1
      || dependencies[0]?.digest?.gitCommit !== expectedCommit
      || dependencies[0]?.uri !== `git+${EXPECTED_REPOSITORY}@${expectedRef}`) {
    fail('provenance does not bind the exact release commit');
  }
  if (definition?.internalParameters?.github?.event_name !== 'workflow_dispatch') {
    fail('provenance was not created by the reviewed release workflow trigger');
  }
  if (statement?.predicate?.runDetails?.builder?.id !== 'https://github.com/actions/runner/github-hosted') {
    fail('provenance was not created by the GitHub-hosted builder');
  }
  const material = provenance?.bundle?.verificationMaterial;
  if (!Array.isArray(material?.x509CertificateChain?.certificates)
      || material.x509CertificateChain.certificates.length !== 1
      || !Array.isArray(material?.tlogEntries) || material.tlogEntries.length === 0) {
    fail('provenance lacks Fulcio certificate or transparency-log proof');
  }
  const certificateBytes = canonicalBase64Bytes(
    material.x509CertificateChain.certificates[0]?.rawBytes,
    'provenance Fulcio certificate',
  );
  let certificate;
  try {
    certificate = new X509Certificate(certificateBytes);
  } catch (error) {
    fail(`provenance Fulcio certificate is malformed: ${error.message}`);
  }
  const expectedSan = `URI:${EXPECTED_REPOSITORY}/${EXPECTED_WORKFLOW_PATH}@${expectedRef}`;
  if (certificate.subjectAltName !== expectedSan) {
    fail('provenance Fulcio certificate does not bind the exact release workflow and ref');
  }
}

const [command, filePath, name, version, integrity, ...rest] = process.argv.slice(2);
exactString(filePath, 'input path');
exactString(name, 'package name');
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$/u.test(version ?? '')) fail('version is invalid');
exactString(integrity, 'integrity');
const response = readJson(filePath, command === 'registry' ? 'registry response' : 'npm audit response');

if (command === 'registry') {
  const [maintainerName, maintainerEmail] = rest;
  verifyRegistry(
    response,
    name,
    version,
    integrity,
    exactString(maintainerName, 'maintainer name'),
    exactString(maintainerEmail, 'maintainer email'),
  );
} else if (command === 'audit') {
  const [expectedCommit, expectedRef] = rest;
  if (!/^[0-9a-f]{40}$/u.test(expectedCommit ?? '')) fail('expected commit is invalid');
  if (!/^refs\/(?:heads|tags)\/[0-9A-Za-z._/-]+$/u.test(expectedRef ?? '') || expectedRef.includes('..')) {
    fail('expected ref is invalid');
  }
  verifyAudit(response, name, version, integrity, expectedCommit, expectedRef);
} else {
  fail('usage: verify_npm_registry_attestation.mjs <registry|audit> ...');
}

console.log(`Verified ${name}@${version} registry signature and provenance identity`);
