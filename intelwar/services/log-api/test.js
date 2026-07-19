import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { accessSync, constants, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { loadDagDbConfig } from "./dagdb-persist.js";

const root = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(root, "../../..");
const defaultAppendBin = path.join(repoRoot, "target/debug/intelwar-log-append");
const defaultVerifyBin = path.join(
  repoRoot,
  "target/debug/intelwar-crosscheck-verify",
);
const defaultSignBin = path.join(repoRoot, "target/debug/intelwar-crosscheck-sign");

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

function binsPresent() {
  try {
    accessSync(defaultAppendBin, constants.X_OK);
    accessSync(defaultVerifyBin, constants.X_OK);
    accessSync(defaultSignBin, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

test("missing CORE_BIN → health 503 and append 503 (no simulated)", async () => {
  await withServer(
    async (base) => {
      const health = await fetch(`${base}/health`);
      assert.equal(health.status, 503);
      const h = await health.json();
      assert.equal(h.kernel_bridge_configured, false);

      await fetch(`${base}/api/consent/grant`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      const ok = await fetch(`${base}/api/log/append`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ summary: "must fail closed" }),
      });
      assert.equal(ok.status, 503);
      const body = await ok.json();
      assert.equal(body.error, "core_bin_required");
      assert.notEqual(body.entry?.simulated, true);
    },
    {
      INTELWAR_CORE_BIN: "",
      INTELWAR_CROSSCHECK_BIN: "",
    },
  );
});

test("Kernel path append + mirror reload + crosscheck sign/verify", async (t) => {
  if (!binsPresent()) {
    t.skip("build bins: cargo build -p intelwar-core --bins");
    return;
  }

  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-kernel-it-"));
  try {
    await withServer(
      async (base) => {
        const healthRes = await fetch(`${base}/health`);
        assert.equal(healthRes.status, 200);
        const health = await healthRes.json();
        assert.equal(health.status, "ok");
        assert.equal(health.kernel_bridge_configured, true);

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
        assert.equal(body.entry.durable, "local_kernel");
        assert.equal(body.bridge.kernel_verdict, "permitted");

        const log1 = await fetch(`${base}/api/log`).then((r) => r.json());
        assert.equal(log1.simulated, false);
        assert.ok(log1.entries.length >= 1);

        // Second append chains.
        const res2 = await fetch(`${base}/api/log/append`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            summary: "second kernel append",
            entry_kind: "Observation",
            voice_kind: "human",
          }),
        });
        assert.equal(res2.status, 201);
        const b2 = await res2.json();
        assert.equal(b2.entry.previous_receipt_hash, body.entry.receipt_hash);

        // Sign + verify crosscheck for first entry hash.
        const subject = body.entry.content_hash;
        const signRes = await fetch(`${base}/api/crosscheck/sign`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            checker_did: "did:exo:checker-1",
            subject_entry_hash_hex: subject,
            verdict: "agree",
            evidence_hash_hex: subject,
            voice_kind: "human",
            // Use a fixed test key from a throwaway generation — sign bin accepts any 32-byte sk.
            secret_key_hex:
              "0101010101010101010101010101010101010101010101010101010101010101",
          }),
        });
        const signText = await signRes.text();
        assert.equal(signRes.status, 200, signText);
        const signed = JSON.parse(signText);
        assert.equal(signed.simulated, false);
        assert.equal(signed.signature_hex.length, 128);

        const verifyRes = await fetch(`${base}/api/crosscheck/verify`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            author_did: body.entry.author_did,
            subject_entry_hash_hex: subject,
            crosschecks: [
              {
                checker_did: signed.checker_did,
                subject_entry_hash_hex: subject,
                verdict: "agree",
                evidence_hash_hex: subject,
                voice_kind: "human",
                signature_hex: signed.signature_hex,
              },
            ],
            trusted_checker_keys_hex: {
              [signed.checker_did]: [signed.public_key_hex],
            },
          }),
        });
        const verifyText = await verifyRes.text();
        assert.equal(verifyRes.status, 200, verifyText);
        const verified = JSON.parse(verifyText);
        assert.equal(verified.ok, true);
        assert.notEqual(verified.simulated, true);
      },
      {
        INTELWAR_CORE_BIN: defaultAppendBin,
        INTELWAR_CROSSCHECK_BIN: defaultVerifyBin,
        INTELWAR_CROSSCHECK_SIGN_BIN: defaultSignBin,
        INTELWAR_CORE_STATE_DIR: stateDir,
      },
    );

    // Restart server — mirror must reload from state dir.
    await withServer(
      async (base) => {
        const log = await fetch(`${base}/api/log`).then((r) => r.json());
        assert.ok(log.entries.length >= 2, "mirror must survive restart");
        assert.equal(log.entries.every((e) => e.simulated === false), true);
      },
      {
        INTELWAR_CORE_BIN: defaultAppendBin,
        INTELWAR_CROSSCHECK_BIN: defaultVerifyBin,
        INTELWAR_CROSSCHECK_SIGN_BIN: defaultSignBin,
        INTELWAR_CORE_STATE_DIR: stateDir,
      },
    );
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("DAG DB incomplete config fail-closed", async (t) => {
  if (!binsPresent()) {
    t.skip("bins missing");
    return;
  }
  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-dag-"));
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
          body: JSON.stringify({ summary: "dag incomplete" }),
        });
        assert.equal(res.status, 503);
      },
      {
        INTELWAR_CORE_BIN: defaultAppendBin,
        INTELWAR_CROSSCHECK_BIN: defaultVerifyBin,
        INTELWAR_CROSSCHECK_SIGN_BIN: defaultSignBin,
        INTELWAR_CORE_STATE_DIR: stateDir,
        INTELWAR_DAGDB_GATEWAY_URL: "http://127.0.0.1:9",
      },
    );
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("DAG DB intake reject → 503 with bridge detail", async (t) => {
  if (!binsPresent()) {
    t.skip("bins missing");
    return;
  }
  const stateDir = mkdtempSync(path.join(tmpdir(), "iw-dag-rej-"));
  const stub = createServer((_req, res) => {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "denied" }));
  });
  await new Promise((r) => stub.listen(0, "127.0.0.1", r));
  const addr = stub.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
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
          body: JSON.stringify({ summary: "gateway reject" }),
        });
        assert.equal(res.status, 503);
        const body = await res.json();
        assert.equal(body.error, "dagdb_intake_rejected");
        assert.ok(body.bridge);
      },
      {
        INTELWAR_CORE_BIN: defaultAppendBin,
        INTELWAR_CROSSCHECK_BIN: defaultVerifyBin,
        INTELWAR_CROSSCHECK_SIGN_BIN: defaultSignBin,
        INTELWAR_CORE_STATE_DIR: stateDir,
        INTELWAR_DAGDB_GATEWAY_URL: `http://127.0.0.1:${port}`,
        INTELWAR_DAGDB_AUTH_TOKEN: "t",
        INTELWAR_DAGDB_TENANT_ID: "tenant",
        INTELWAR_DAGDB_NAMESPACE: "ns",
        INTELWAR_DAGDB_OWNER_DID: "did:exo:o",
        INTELWAR_DAGDB_CONTROLLER_DID: "did:exo:c",
        INTELWAR_DAGDB_SUBMITTED_BY_DID: "did:exo:s",
        INTELWAR_DAGDB_WRITE_SIGNATURE: "sig",
      },
    );
  } finally {
    stub.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("loadDagDbConfig null when URL unset", () => {
  assert.equal(loadDagDbConfig({}), null);
});
