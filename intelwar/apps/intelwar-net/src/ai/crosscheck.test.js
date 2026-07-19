import test from "node:test";
import assert from "node:assert/strict";
import { draftCrossCheck } from "./crosscheck.js";

test("draftCrossCheck rejects ab-repeat placeholder signature", () => {
  const r = draftCrossCheck({
    checker_did: "did:exo:c",
    subject_entry_hash_hex: "00".repeat(32),
    signature_hex: "ab".repeat(64),
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "fake_signature_rejected");
});

test("draftCrossCheck accepts 128-hex real-shaped sig", () => {
  const r = draftCrossCheck({
    checker_did: "did:exo:c",
    subject_entry_hash_hex: "11".repeat(32),
    signature_hex: "cd".repeat(64),
  });
  assert.equal(r.ok, true);
  assert.equal(r.result.signature_hex.length, 128);
});
