import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(fileURLToPath(import.meta.url));

async function withServer(fn) {
  const port = 18787;
  const child = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: { ...process.env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await sleep(400);
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    child.kill("SIGTERM");
    await Promise.race([once(child, "exit"), sleep(1000)]);
  }
}

test("health and consent-gated append", async () => {
  await withServer(async (base) => {
    const health = await fetch(`${base}/health`).then((r) => r.json());
    assert.equal(health.trust_claim, "none");

    const denied = await fetch(`${base}/api/log/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ summary: "no consent" }),
    });
    assert.equal(denied.status, 403);

    await fetch(`${base}/api/consent/grant`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });

    const ok = await fetch(`${base}/api/log/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ summary: "after consent" }),
    });
    assert.equal(ok.status, 201);
    const body = await ok.json();
    assert.equal(body.entry.simulated, true);

    const log = await fetch(`${base}/api/log`).then((r) => r.json());
    assert.ok(log.entries.some((e) => e.summary === "after consent"));
  });
});
