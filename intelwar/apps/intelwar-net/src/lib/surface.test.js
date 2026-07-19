import test from "node:test";
import assert from "node:assert/strict";
import { surfaceTitle } from "./surface.js";

test("surfaceTitle maps surfaces", () => {
  assert.match(surfaceTitle("net"), /Living Log/);
  assert.match(surfaceTitle("ai"), /CrossCheck/);
  assert.match(surfaceTitle("tv"), /Provenance/);
});
