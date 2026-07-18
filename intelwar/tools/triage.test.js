import assert from "node:assert/strict";
import test from "node:test";
import { triage } from "./triage.js";

test("triage emits iw and panel labels for consent/bailment text", () => {
  const result = triage("Need consent bailment revoke on fail-closed path");
  assert.equal(result.schema, "intelwar.triage.v1");
  assert.ok(result.labels.some((l) => l === "iw:consent-required"));
  assert.ok(result.labels.some((l) => l.startsWith("panel:")));
  assert.ok(result.invariants.some((i) => i.id === "consent-required"));
});

test("triage defaults when no keywords match", () => {
  const result = triage("zzzz unrelated fluff");
  assert.deepEqual(result.labels.slice(0, 1), ["iw:log-integrity"]);
  assert.ok(result.labels.includes("panel:architecture"));
});
