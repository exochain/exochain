import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildOdentitySummary } from "./odentity.js";

describe("0dentity summary", () => {
  it("empty mirror yields zeroed, unlinked summary", () => {
    const s = buildOdentitySummary([]);
    assert.equal(s.log_offset, 0);
    assert.equal(s.dimensions.log_entries, 0);
    assert.equal(s.chain_linked, false);
    assert.equal(s.head_receipt_hash, null);
  });

  it("counts voices, kinds, campaign zero, analysis; verifies chain", () => {
    const entries = [
      {
        summary: "CZ-01 · founding",
        entry_kind: "DevelopmentDecision",
        voice_kind: "human",
        receipt_hash: "aa",
        previous_receipt_hash: null,
      },
      {
        summary: "analysis.stress_test: claim",
        entry_kind: "Analysis",
        voice_kind: "synthetic",
        receipt_hash: "bb",
        previous_receipt_hash: "aa",
      },
      {
        summary: "regular note",
        entry_kind: "Observation",
        voice_kind: "human",
        receipt_hash: "cc",
        previous_receipt_hash: "bb",
      },
    ];
    const s = buildOdentitySummary(entries);
    assert.equal(s.log_offset, 3);
    assert.equal(s.dimensions.human_entries, 2);
    assert.equal(s.dimensions.synthetic_entries, 1);
    assert.equal(s.dimensions.analysis_events, 1);
    assert.equal(s.dimensions.campaign_zero_founding, 1);
    assert.equal(s.by_entry_kind.Analysis, 1);
    assert.equal(s.chain_linked, true);
    assert.equal(s.head_receipt_hash, "cc");
  });

  it("broken chain is reported, not hidden", () => {
    const s = buildOdentitySummary([
      { receipt_hash: "aa", previous_receipt_hash: null },
      { receipt_hash: "bb", previous_receipt_hash: "WRONG" },
    ]);
    assert.equal(s.chain_linked, false);
  });

  it("is deterministic", () => {
    const rows = [
      { summary: "x", entry_kind: "Observation", voice_kind: "human", receipt_hash: "a" },
    ];
    assert.deepEqual(buildOdentitySummary(rows), buildOdentitySummary(rows));
  });
});
