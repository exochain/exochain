/**
 * Source guard: success JSON builders must never assign simulated: true.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

/** Match object-literal property `simulated: true` (not prose in error strings). */
const ASSIGN_TRUE = /(?:^|[,{])\s*simulated:\s*true\b/m;

test("server.js never assigns simulated: true on success objects", () => {
  const src = readFileSync(path.join(root, "server.js"), "utf8");
  assert.equal(ASSIGN_TRUE.test(src), false);
  assert.match(src, /core_bin_required|kernel_required/);
  assert.match(src, /INTELWAR_CROSSCHECK_BIN/);
});

test("crosscheck-verify.js never assigns simulated: true", () => {
  const src = readFileSync(path.join(root, "crosscheck-verify.js"), "utf8");
  assert.equal(ASSIGN_TRUE.test(src), false);
});
