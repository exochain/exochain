import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

const TEST_OPERATOR_TOKEN = "test-operator-token";

async function startServer(stateDir, port, extraEnv = {}) {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      INTELWAR_CORE_STATE_DIR: stateDir,
      INTELWAR_CORE_BIN: "",
      INTELWAR_CROSSCHECK_BIN: "",
      INTELWAR_ADMIN_TOKEN: TEST_OPERATOR_TOKEN,
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await sleep(500);
  return child;
}

async function stopServer(child) {
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), sleep(1000)]);
}

test("consent survives a server restart via state dir", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-consent-"));
  const port = 19100 + Math.floor(Math.random() * 200);
  let child = await startServer(stateDir, port);
  try {
    const grant = await fetch(`http://127.0.0.1:${port}/api/consent/grant`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TEST_OPERATOR_TOKEN}`,
      },
      body: JSON.stringify({ scope: "log:append" }),
    });
    const granted = await grant.json();
    assert.equal(granted.ok, true);
    assert.equal(granted.durable, true);

    await stopServer(child);
    child = await startServer(stateDir, port);

    const after = await fetch(`http://127.0.0.1:${port}/api/consent`);
    const state = await after.json();
    assert.equal(state.active, true, "consent must survive restart");
    assert.equal(state.durable, true);
  } finally {
    await stopServer(child);
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("write guard: 401 without token, 503 when unconfigured, reads public", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-guard-"));
  const port = 19700 + Math.floor(Math.random() * 200);
  let child = await startServer(stateDir, port);
  try {
    const noToken = await fetch(`http://127.0.0.1:${port}/api/consent/grant`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(noToken.status, 401);
    const noTokenBody = await noToken.json();
    assert.equal(noTokenBody.error, "operator_token_required");

    const badSeed = await fetch(
      `http://127.0.0.1:${port}/api/campaign-zero/seed`,
      { method: "POST", headers: { authorization: "Bearer wrong-token" } },
    );
    assert.equal(badSeed.status, 401);

    const read = await fetch(`http://127.0.0.1:${port}/api/campaign-zero`);
    assert.equal(read.status, 200, "reads stay public");

    await stopServer(child);
    child = await startServer(stateDir, port, { INTELWAR_ADMIN_TOKEN: "" });
    const unconfigured = await fetch(
      `http://127.0.0.1:${port}/api/consent/grant`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      },
    );
    assert.equal(unconfigured.status, 503, "unconfigured guard fails closed");
    const ub = await unconfigured.json();
    assert.equal(ub.error, "write_guard_unconfigured");
  } finally {
    await stopServer(child);
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("0dentity summary route serves mirror-derived signals", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-odentity-"));
  const port = 19400 + Math.floor(Math.random() * 200);
  const child = await startServer(stateDir, port);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/0dentity/summary`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.computed_from, "kernel_local_mirror");
    assert.equal(body.final_authority, false);
    assert.equal(body.summary.log_offset, 0);
  } finally {
    await stopServer(child);
    rmSync(stateDir, { recursive: true, force: true });
  }
});
