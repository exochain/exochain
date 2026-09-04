import {
  createReceiptedMcpProxy,
  hashProviderPayload,
  type FetchLike,
  type LlmProxyConfig,
} from "../src/index.js";
import type { ReceiptAuthority } from "./receipt-authority.js";

export const exampleMcpConfig = (
  fetchImpl: FetchLike,
  authority: ReceiptAuthority,
): LlmProxyConfig => ({
  mode: "production",
  gatewayUrl: "https://exochain.example",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:lynk-adapter",
  custodyPolicyHash: hashProviderPayload("customer-custody-policy-v1"),
  storageMode: "receipt_minimized",
  ...authority,
  fetch: fetchImpl,
});

export async function runMcpToolCallExample(
  fetchImpl: FetchLike,
  authority: ReceiptAuthority,
): Promise<unknown> {
  const proxy = createReceiptedMcpProxy(exampleMcpConfig(fetchImpl, authority), {
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
