import {
  createReceiptedMcpProxy,
  hashProviderPayload,
  type FetchLike,
  type LlmProxyConfig,
} from "../src/index.js";

export const exampleMcpConfig = (fetchImpl: FetchLike): LlmProxyConfig => ({
  mode: "production",
  gatewayUrl: "https://exochain.example",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:lynk-adapter",
  custodyPolicyHash: hashProviderPayload("customer-custody-policy-v1"),
  storageMode: "receipt_minimized",
  validation: { action: "llm.usage.receipt.emit" },
  subjectSignature: "subject-signature-placeholder",
  adapterSignature: "adapter-signature-placeholder",
  fetch: fetchImpl,
});

export async function runMcpToolCallExample(fetchImpl: FetchLike): Promise<unknown> {
  const proxy = createReceiptedMcpProxy(exampleMcpConfig(fetchImpl), {
    serverUrl: "https://mcp.example",
  });

  return proxy.callTool(
    {
      name: "public_search",
      arguments: { topic: "public release notes" },
    },
    {
      idempotencyKey: "tenant-alpha-mcp-001",
      createdAt: { physical_ms: 1_770_000_000_000, logical: 0 },
    },
  );
}
