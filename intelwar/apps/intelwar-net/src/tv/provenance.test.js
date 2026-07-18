import assert from "node:assert/strict";
import test from "node:test";
import { buildReceiptChain, summarizeProvenance } from "./provenance.js";

test("summarizeProvenance labels simulated honestly", () => {
  const s = summarizeProvenance({
    simulated: false,
    kernel_adjudicated: true,
    voice_kind: "human",
    receipt_hash: "abc",
  });
  assert.equal(s.ok, true);
  assert.equal(s.simulated, false);
  assert.equal(s.kernel_adjudicated, true);
  assert.equal(s.receipt_hash, "abc");
});

test("buildReceiptChain walks previous_receipt_hash", () => {
  const entries = [
    {
      entry_id: "a",
      summary: "first",
      receipt_hash: "r1",
      previous_receipt_hash: null,
      simulated: false,
      kernel_adjudicated: true,
    },
    {
      entry_id: "b",
      summary: "second",
      receipt_hash: "r2",
      previous_receipt_hash: "r1",
      simulated: false,
      kernel_adjudicated: true,
    },
  ];
  const chain = buildReceiptChain(entries, "b");
  assert.equal(chain.ok, true);
  assert.equal(chain.broken, false);
  assert.equal(chain.depth, 2);
  assert.equal(chain.chain[0].entry_id, "b");
  assert.equal(chain.chain[1].entry_id, "a");
});

test("buildReceiptChain marks broken when prev missing", () => {
  const entries = [
    {
      entry_id: "x",
      receipt_hash: "rx",
      previous_receipt_hash: "missing",
      simulated: true,
    },
  ];
  const chain = buildReceiptChain(entries, "x");
  assert.equal(chain.ok, true);
  assert.equal(chain.broken, true);
  assert.equal(chain.depth, 1);
});
