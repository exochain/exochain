/**
 * Optional exo-gateway DAG DB persistence for Kernel-adjudicated entries (PM-002).
 *
 * When INTELWAR_DAGDB_GATEWAY_URL is unset → no-op (local multi-node only).
 * When set → all required vars must be present; write failure fails closed.
 */

const REQUIRED = [
  "INTELWAR_DAGDB_GATEWAY_URL",
  "INTELWAR_DAGDB_AUTH_TOKEN",
  "INTELWAR_DAGDB_TENANT_ID",
  "INTELWAR_DAGDB_NAMESPACE",
  "INTELWAR_DAGDB_OWNER_DID",
  "INTELWAR_DAGDB_CONTROLLER_DID",
  "INTELWAR_DAGDB_SUBMITTED_BY_DID",
  "INTELWAR_DAGDB_WRITE_SIGNATURE",
];

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {null | Record<string, string>}
 */
export function loadDagDbConfig(env = process.env) {
  const url = String(env.INTELWAR_DAGDB_GATEWAY_URL || "").trim();
  if (!url) {
    return null;
  }
  const missing = REQUIRED.filter((name) => !String(env[name] || "").trim());
  if (missing.length > 0) {
    const err = new Error(
      `INTELWAR_DAGDB_GATEWAY_URL is set but config incomplete: ${missing.join(", ")}`,
    );
    err.code = "dagdb_config_incomplete";
    throw err;
  }
  return {
    gatewayUrl: url.replace(/\/+$/, ""),
    authToken: String(env.INTELWAR_DAGDB_AUTH_TOKEN),
    tenantId: String(env.INTELWAR_DAGDB_TENANT_ID),
    namespace: String(env.INTELWAR_DAGDB_NAMESPACE),
    ownerDid: String(env.INTELWAR_DAGDB_OWNER_DID),
    controllerDid: String(env.INTELWAR_DAGDB_CONTROLLER_DID),
    submittedByDid: String(env.INTELWAR_DAGDB_SUBMITTED_BY_DID),
    writeSignature: String(env.INTELWAR_DAGDB_WRITE_SIGNATURE),
  };
}

/**
 * @param {Record<string, unknown>} bridgeResult
 * @param {NodeJS.ProcessEnv} [env]
 */
export async function persistBridgeEntryToGateway(bridgeResult, env = process.env) {
  const config = loadDagDbConfig(env);
  if (!config) {
    return { attempted: false, ok: true };
  }

  const entryId = String(bridgeResult.entry_id || "unknown");
  const contentHash = String(bridgeResult.content_hash || "");
  const receiptHash = String(bridgeResult.receipt_hash || "");
  const dagNodeHash = String(bridgeResult.dag_node_hash || "");
  const idempotencyKey = `intelwar:log:${entryId}:${contentHash.slice(0, 32)}`;

  const body = {
    tenant_id: config.tenantId,
    namespace: config.namespace,
    idempotency_key: idempotencyKey,
    source_type: "generated",
    source_hash: contentHash || receiptHash,
    payload_hash: contentHash || receiptHash,
    owner_did: config.ownerDid,
    controller_did: config.controllerDid,
    submitted_by_did: config.submittedByDid,
    consent_purpose: "writeback",
    requested_action: "intelwar:living-log:append",
    title_text: `IntelWar Living Log ${entryId}`,
    summary_text: String(bridgeResult.summary || entryId),
    payload_uri_hash: null,
    parent_memory_ids: null,
    edge_types: null,
    access_policy_hash: null,
    declared_rights_hash: null,
    keyword_texts: [
      "intelwar",
      "living-log",
      String(bridgeResult.dag_scope || "local-multi-node"),
      dagNodeHash.slice(0, 16),
    ],
  };

  const response = await fetch(`${config.gatewayUrl}/api/v1/dag-db/intake`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${config.authToken}`,
      "content-type": "application/json",
      "x-exo-tenant-id": config.tenantId,
      "x-exo-namespace": config.namespace,
      "x-exo-authority-scope": `dagdb:intake:${config.tenantId}:${config.namespace}`,
      "x-exo-write-signature": config.writeSignature,
    },
    body: JSON.stringify(body),
  });

  const text = await response.text();
  if (!response.ok) {
    const err = new Error(
      `DAG DB intake rejected Living Log append with status ${response.status}: ${text.slice(0, 400)}`,
    );
    err.code = "dagdb_intake_rejected";
    throw err;
  }

  return { attempted: true, ok: true, status: response.status };
}
