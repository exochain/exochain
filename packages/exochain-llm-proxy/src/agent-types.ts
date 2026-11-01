// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import type { LynkAgentModel } from "./agent-model.js";
import type { ReceiptedMcpProxy } from "./mcp.js";
import type { HlcTimestamp, ReceiptPending } from "./types.js";

export interface AgentMission {
  id: string;
  objective: string;
  successCriteria: string[];
}

export interface AgentObservation {
  tool: string;
  output: unknown;
  receiptHash: string;
}

export interface AgentCompletionContext {
  mission: AgentMission;
  summary: string;
  observations: readonly AgentObservation[];
}

export interface AgentRuntimeConfig {
  planner: LynkAgentModel;
  reviewer: LynkAgentModel;
  tools: Array<{ name: string; description: string; proxy: ReceiptedMcpProxy }>;
  now(): HlcTimestamp;
  /** Deadline for each model, tool or host acceptance operation, up to 300000 ms. */
  operationTimeoutMs?: number;
  loop: {
    max_iterations: number;
    max_model_calls: number;
    max_tool_calls: number;
    stop_condition: "reviewed_verified_completion";
    escalation: "return_to_human";
  };
  /** Trusted acceptance check, e.g. inspect a receipted validation report. No authority grants. */
  verifyCompletion(context: AgentCompletionContext, signal: AbortSignal): boolean | Promise<boolean>;
}

export type AgentStopReason = "iteration_limit" | "model_call_limit" | "tool_call_limit"
  | "repeated_validation_failure" | "reviewer_escalation" | "model_receipt_unavailable"
  | "model_unavailable" | "execution_uncertain" | "execution_receipt_pending"
  | "execution_failed" | "authorization_denied" | "completion_verification_failed" | "human_stop";

export interface AgentRunResult {
  status: "completed" | "escalated" | "stopped";
  reason?: AgentStopReason;
  summary?: string;
  iterations: number;
  modelCalls: number;
  toolCalls: number;
  receiptHashes: string[];
  pending?: ReceiptPending;
}

export type AgentProposal = { kind: "tool"; tool: string; arguments: Record<string, unknown> }
  | { kind: "complete"; summary: string };

export interface AgentReview {
  kind: "review";
  proposal_hash: string;
  verdict: "approve" | "reject" | "escalate";
  reason: string;
}
