import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DailyBudget,
  RateBucket,
  extractOperatorToken,
  originAllowed,
  tokenMatches,
} from "./security.js";

describe("write guard primitives", () => {
  it("tokenMatches is strict and empty-safe", () => {
    assert.equal(tokenMatches("abc", "abc"), true);
    assert.equal(tokenMatches("abc", "abd"), false);
    assert.equal(tokenMatches("", ""), false);
    assert.equal(tokenMatches("abc", ""), false);
    assert.equal(tokenMatches("ab", "abc"), false);
  });

  it("extractOperatorToken reads Bearer then admin header", () => {
    assert.equal(
      extractOperatorToken({ headers: { authorization: "Bearer tok1" } }),
      "tok1",
    );
    assert.equal(
      extractOperatorToken({ headers: { "x-intelwar-admin": "tok2" } }),
      "tok2",
    );
    assert.equal(extractOperatorToken({ headers: {} }), "");
  });

  it("originAllowed permits brand hosts and origin-less clients only", () => {
    assert.equal(originAllowed(undefined), true);
    assert.equal(originAllowed("https://intelwar.ai"), true);
    assert.equal(originAllowed("https://evil.example.com"), false);
  });

  it("RateBucket blocks over limit and resets by window", () => {
    const rb = new RateBucket({ limit: 2, windowMs: 1_000 });
    assert.equal(rb.allow("ip1", 0).allowed, true);
    assert.equal(rb.allow("ip1", 10).allowed, true);
    const blocked = rb.allow("ip1", 20);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retry_after_ms > 0);
    assert.equal(rb.allow("ip1", 1_001).allowed, true);
    assert.equal(rb.allow("ip2", 20).allowed, true);
  });

  it("DailyBudget caps per key per day", () => {
    const db = new DailyBudget({ capMicroUsd: 100 });
    assert.equal(db.remaining("ip1", "d1"), 100);
    db.add("ip1", "d1", 60);
    assert.equal(db.remaining("ip1", "d1"), 40);
    db.add("ip1", "d1", 60);
    assert.equal(db.remaining("ip1", "d1"), 0);
    assert.equal(db.remaining("ip1", "d2"), 100);
    assert.equal(db.remaining("ip2", "d1"), 100);
  });
});
