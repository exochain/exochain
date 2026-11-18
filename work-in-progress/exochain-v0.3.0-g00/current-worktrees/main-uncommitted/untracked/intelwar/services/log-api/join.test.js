import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  JOIN_PRICE_CENTS,
  PASS_BUDGET_MULTIPLIER,
  feeBreakdownCents,
  grossForNetCents,
  issuePass,
  passCount,
  passValid,
} from "./join.js";

describe("join economics (integer cents)", () => {
  it("$3.69 nets $3.28 after US card fees", () => {
    const f = feeBreakdownCents(JOIN_PRICE_CENTS);
    assert.equal(f.amount_cents, 369);
    assert.equal(f.stripe_fee_cents, 41); // ceil(10.701)=11 + 30
    assert.equal(f.net_cents, 328);
  });

  it("gross-up to net $3.69 is $4.11", () => {
    const gross = grossForNetCents(369);
    assert.equal(gross, 411);
    const f = feeBreakdownCents(gross);
    assert.equal(f.net_cents, 369);
  });

  it("pass multiplier is bounded and positive", () => {
    assert.ok(PASS_BUDGET_MULTIPLIER >= 1 && PASS_BUDGET_MULTIPLIER <= 10);
  });
});

describe("frontier pass store", () => {
  it("issues, validates, expires, and blocks double-claim", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "iw-pass-"));
    try {
      const now = 1_000_000;
      const issued = issuePass(dir, {
        sessionId: "cs_test_1",
        amountCents: 368,
        nowMs: now,
      });
      assert.equal(issued.ok, true);
      assert.match(issued.pass_token, /^fp_[0-9a-f]{48}$/);

      const valid = passValid(dir, issued.pass_token, now + 1000);
      assert.equal(valid.valid, true);

      const expired = passValid(
        dir,
        issued.pass_token,
        now + 31 * 24 * 60 * 60 * 1000,
      );
      assert.equal(expired.valid, false);

      const dup = issuePass(dir, {
        sessionId: "cs_test_1",
        amountCents: 368,
        nowMs: now,
      });
      assert.equal(dup.ok, false);
      assert.equal(dup.error, "session_already_claimed");

      assert.equal(passValid(dir, "fp_wrong", now).valid, false);
      assert.equal(passCount(dir), 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
