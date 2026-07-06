#!/usr/bin/env node

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const {
  DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM,
  DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS,
  PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM,
  PublicOutputEvidenceSummaryError,
  buildPublicOutputEvidenceHashRecord,
  evaluateExochainProductionTrustEvidence,
  exochainProductionTrustConfig,
} = require("../server/utils/exochain-production-trust-evidence.js");
const {
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
} = require("../server/utils/public-adapter-output-authorization.js");
const {
  runtimeExochainAdapter,
} = require("../server/utils/livesafe-exochain-adapter.js");

function parseArgs(argv) {
  const options = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--as-of") {
      options.asOf = argv[index + 1];
      index += 1;
      continue;
    }

    if (arg === "--max-age-ms") {
      options.maxEvidenceAgeMs = Number(argv[index + 1]);
      index += 1;
      continue;
    }

    if (arg === "--pretty") {
      options.pretty = true;
      continue;
    }

    if (arg === "--help") {
      options.help = true;
      continue;
    }

    throw new PublicOutputEvidenceSummaryError([
      `Unsupported argument: ${arg}`,
    ]);
  }

  return options;
}

function printUsage() {
  process.stdout.write(
    [
      "Usage: npm run evidence:public-output-hash -- --as-of ISO_UTC [--max-age-ms INTEGER] [--pretty]",
      "",
      "Emits a non-secret JSON record with the canonical LiveSafe public-output evidence hash.",
    ].join("\n"),
  );
  process.stdout.write("\n");
}

function serialize(record, pretty) {
  return JSON.stringify(record, null, pretty ? 2 : 0);
}

function blockedRecord(reasons) {
  return {
    evidence_hash: null,
    algorithm: PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM,
    subject: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
    audience: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
    generated_from: DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM,
    state: "blocked",
    reasons,
    public_claims_allowed: false,
  };
}

function reasonsFor(error) {
  if (
    error instanceof PublicOutputEvidenceSummaryError &&
    Array.isArray(error.reasons)
  ) {
    return error.reasons;
  }

  return ["Public output evidence hash generation failed."];
}

function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printUsage();
    return 0;
  }

  const productionTrustEvidence = evaluateExochainProductionTrustEvidence({
    config: exochainProductionTrustConfig,
  });
  const runtimeStatus = runtimeExochainAdapter.getRuntimeStatus();
  const record = buildPublicOutputEvidenceHashRecord({
    subject: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
    audience: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
    asOf: options.asOf,
    maxEvidenceAgeMs:
      options.maxEvidenceAgeMs ||
      DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS,
    exochainConnected:
      productionTrustEvidence.production_health_verified === true &&
      productionTrustEvidence.production_ready_verified === true,
    productionTrustEvidence,
    runtimeStatus,
    generatedFrom: DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM,
  });

  process.stdout.write(serialize(record, options.pretty));
  process.stdout.write("\n");
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  process.stdout.write(serialize(blockedRecord(reasonsFor(error)), false));
  process.stdout.write("\n");
  process.exitCode = 1;
}
