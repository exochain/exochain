import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(root, "check-prod-env.mjs");

test("Railway/public check fails closed without VITE_LOG_API_URL", () => {
  const r = spawnSync(process.execPath, [script], {
    env: {
      ...process.env,
      RAILWAY_ENVIRONMENT: "production",
      VITE_LOG_API_URL: "",
    },
    encoding: "utf8",
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /fail-closed/);
});

test("Railway check accepts absolute https URL", () => {
  const r = spawnSync(process.execPath, [script], {
    env: {
      ...process.env,
      RAILWAY_ENVIRONMENT: "production",
      VITE_LOG_API_URL: "https://example.up.railway.app",
    },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
});

test("local build may omit VITE_LOG_API_URL", () => {
  const env = { ...process.env, VITE_LOG_API_URL: "" };
  delete env.RAILWAY_ENVIRONMENT;
  delete env.INTELWAR_REQUIRE_LOG_API;
  const r = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});
