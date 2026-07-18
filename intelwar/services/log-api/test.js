import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { loadDagDbConfig } from "./dagdb-persist.js";

const root = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(root, "../../..");
const defaultBin = path.join(repoRoot, "target/debug/intelwar-log-append");

/**
 * @param {(base: string) => Promise<void>} fn
 * @param {Record<string, string | undefined>} [extraEnv]
 */
async function withServer(fn, extraEnv = {}) {
  const port = 18787 + Math.floor(Math.random() * 200);
  const child = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      ...extraEnv,
      PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await sleep(500);
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    child.kill("SIGTERM");
    await Promise.race([once(child, "exit"), sleep(1000)]);
  }
}

test("health and consent-gated simulated append", async () => {
  await withServer(async (base) => {
    const health = await fetch(`${base}/health`).then((r) => r.json());
    assert.equal(health.trust_claim, "none");
    assert.equal(health.kernel_bridge_configured, false);

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
    assert.equal(body.entry.kernel_adjudicated, false);
  });
});

test("INTELWAR_CORE_BIN Kernel path appends with simulated false", async (t) => {
  const bin = process.env.INTELWAR_TEST_CORE_BIN || defaultBin;
  const { accessSync, constants } = await import("node:fs");
  try {
    accessSync(bin, constants.X_OK);
  } catch {
    t.skip(`Kernel binary not found/executable at ${bin}; run cargo build -p intelwar-core --bin intelwar-log-append`);
    return;
  }

  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-kernel-it-"));
  try {
    await withServer(
      async (base) => {
        const health = await fetch(`${base}/health`).then((r) => r.json());
        assert.equal(health.kernel_bridge_configured, true);

        await fetch(`${base}/api/consent/grant`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        });

        const res = await fetch(`${base}/api/log/append`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            summary: "kernel path integration test",
            entry_kind: "Observation",
            voice_kind: "human",
          }),
        });
        const bodyText = await res.text();
        assert.equal(res.status, 201, bodyText);
        const body = JSON.parse(bodyText);
        assert.equal(body.entry.simulated, false);
        assert.equal(body.entry.kernel_adjudicated, true);
        assert.equal(body.bridge.kernel_verdict, "permitted");
        assert.ok(body.entry.content_hash);
        assert.ok(body.entry.receipt_hash);
        assert.equal(body.bridge.dag_scope, "local-multi-node-genesis");

        const res2 = await fetch(`${base}/api/log/append`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            summary: "kernel path second append continuity",
            entry_kind: "Observation",
            voice_kind: "human",
          }),
        });
        const body2Text = await res2.text();
        assert.equal(res2.status, 201, body2Text);
        const body2 = JSON.parse(body2Text);
        assert.equal(body2.bridge.dag_scope, "local-multi-node");
        assert.equal(
          body2.entry.previous_receipt_hash,
          body.entry.receipt_hash,
        );
        assert.notEqual(body2.entry.dag_node_hash, body.entry.dag_node_hash);
      },
      {
        INTELWAR_CORE_BIN: bin,
        INTELWAR_CORE_STATE_DIR: stateDir,
      },
    );
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("INTELWAR_CORE_BIN fail-closed on bad binary (no simulated fallback)", async () => {
  await withServer(
    async (base) => {
      await fetch(`${base}/api/consent/grant`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });

      const res = await fetch(`${base}/api/log/append`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ summary: "should fail closed" }),
      });
      assert.equal(res.status, 503);
      const body = await res.json();
      assert.equal(body.fail_closed, true);
      assert.equal(body.ok, false);
    },
    {
      INTELWAR_CORE_BIN: "/nonexistent/intelwar-log-append-missing",
      INTELWAR_CORE_STATE_DIR: path.join(tmpdir(), "iw-fail-closed-unused"),
    },
  );
});

test("loadDagDbConfig: unset URL is no-op; incomplete URL fails closed", () => {
  assert.equal(loadDagDbConfig({}), null);
  assert.throws(
    () =>
      loadDagDbConfig({
        INTELWAR_DAGDB_GATEWAY_URL: "http://127.0.0.1:9",
      }),
    /incomplete/,
  );
});

test("INTELWAR_DAGDB_* incomplete config fail-closed after Kernel success", async (t) => {
  const bin = process.env.INTELWAR_TEST_CORE_BIN || defaultBin;
  const { accessSync, constants } = await import("node:fs");
  try {
    accessSync(bin, constants.X_OK);
  } catch {
    t.skip(`Kernel binary not found/executable at ${bin}`);
    return;
  }

  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-dagdb-cfg-"));
  try {
    await withServer(
      async (base) => {
        await fetch(`${base}/api/consent/grant`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        });
        const res = await fetch(`${base}/api/log/append`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ summary: "dagdb incomplete should 503" }),
        });
        assert.equal(res.status, 503);
        const body = await res.json();
        assert.equal(body.fail_closed, true);
        assert.equal(body.error, "dagdb_config_incomplete");
      },
      {
        INTELWAR_CORE_BIN: bin,
        INTELWAR_CORE_STATE_DIR: stateDir,
        INTELWAR_DAGDB_GATEWAY_URL: "http://127.0.0.1:9",
      },
    );
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("INTELWAR_DAGDB_* gateway rejection fail-closed", async (t) => {
  const bin = process.env.INTELWAR_TEST_CORE_BIN || defaultBin;
  const { accessSync, constants } = await import("node:fs");
  try {
    accessSync(bin, constants.X_OK);
  } catch {
    t.skip(`Kernel binary not found/executable at ${bin}`);
    return;
  }

  const gateway = createServer((_req, res) => {
    res.writeHead(403, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "denied" }));
  });
  await new Promise((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const addr = gateway.address();
  const gwPort = typeof addr === "object" && addr ? addr.port : 0;

  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-dagdb-rej-"));
  try {
    await withServer(
      async (base) => {
        await fetch(`${base}/api/consent/grant`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        });
        const res = await fetch(`${base}/api/log/append`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ summary: "gateway deny should 503" }),
        });
        assert.equal(res.status, 503);
        const body = await res.json();
        assert.equal(body.fail_closed, true);
        assert.equal(body.error, "dagdb_intake_rejected");
      },
      {
        INTELWAR_CORE_BIN: bin,
        INTELWAR_CORE_STATE_DIR: stateDir,
        INTELWAR_DAGDB_GATEWAY_URL: `http://127.0.0.1:${gwPort}`,
        INTELWAR_DAGDB_AUTH_TOKEN: "test-token",
        INTELWAR_DAGDB_TENANT_ID: "dag_db-local",
        INTELWAR_DAGDB_NAMESPACE: "dag_db",
        INTELWAR_DAGDB_OWNER_DID: "did:exo:owner",
        INTELWAR_DAGDB_CONTROLLER_DID: "did:exo:controller",
        INTELWAR_DAGDB_SUBMITTED_BY_DID: "did:exo:submitter",
        INTELWAR_DAGDB_WRITE_SIGNATURE: "test-sig",
      },
    );
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
    await new Promise((resolve) => gateway.close(resolve));
  }
});
