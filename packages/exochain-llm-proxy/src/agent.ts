// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import { isLynkAgentModel, readAgentModelJson, type LynkAgentModel } from "./agent-model.js";
import { isGovernedMcpProxy, McpAuthorizationError } from "./mcp.js";
import { withRequestDeadline } from "./http.js";
import { executionHash, requireHlc, snapshotJson } from "./action-authorization.js";
import { LynkConfigurationError, LynkValidationError } from "./evidence.js";
import type { AgentMission, AgentObservation, AgentProposal, AgentReview,
  AgentRunResult, AgentRuntimeConfig, AgentStopReason } from "./agent-types.js";
import type { ReceiptedResult } from "./types.js";

function nonempty(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= limit;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new LynkValidationError("invalid structured proposal");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: string[]): void {
  if (Object.keys(value).sort().join(",") !== keys.sort().join(",")) throw new LynkValidationError("unexpected proposal fields");
}

function proposalFrom(value: unknown, allowed: readonly string[]): AgentProposal {
  const proposal = object(value);
  if (proposal.kind === "tool") {
    exactKeys(proposal, ["kind", "tool", "arguments"]);
    if (typeof proposal.tool !== "string" || !allowed.includes(proposal.tool)) throw new LynkValidationError("tool not allowed");
    return { kind: "tool", tool: proposal.tool, arguments: object(proposal.arguments) };
  }
  exactKeys(proposal, ["kind", "summary"]);
  if (proposal.kind !== "complete" || !nonempty(proposal.summary, 8_192)) throw new LynkValidationError("invalid completion proposal");
  return { kind: "complete", summary: proposal.summary };
}

function reviewFrom(value: unknown, proposalHash: string): AgentReview {
  const review = object(value);
  exactKeys(review, ["kind", "proposal_hash", "verdict", "reason"]);
  if (review.kind !== "review" || review.proposal_hash !== proposalHash
    || !["approve", "reject", "escalate"].includes(String(review.verdict))
    || !nonempty(review.reason, 4_096)) throw new LynkValidationError("invalid or unbound review");
  return review as unknown as AgentReview;
}

export function createGovernedAgent(config: AgentRuntimeConfig): {
  run(mission: AgentMission, options?: { signal?: AbortSignal }): Promise<AgentRunResult>;
} {
  const { planner, reviewer, now, verifyCompletion } = config;
  const loop = Object.freeze({ ...config.loop });
  const deadline = { requestTimeoutMs: config.operationTimeoutMs ?? 30_000 };
  const tools = config.tools.map(tool => Object.freeze({ ...tool }));
  const names = tools.map(tool => tool.name);
  if (!isLynkAgentModel(planner) || !isLynkAgentModel(reviewer)
    || planner.id === reviewer.id || planner.modelId === reviewer.modelId || planner.actorDid === reviewer.actorDid
    || typeof now !== "function" || typeof verifyCompletion !== "function"
    || !Number.isSafeInteger(deadline.requestTimeoutMs) || deadline.requestTimeoutMs < 1 || deadline.requestTimeoutMs > 300_000
    || !Number.isSafeInteger(loop.max_iterations) || loop.max_iterations < 1 || loop.max_iterations > 25
    || !Number.isSafeInteger(loop.max_model_calls) || loop.max_model_calls < 1 || loop.max_model_calls > 50
    || !Number.isSafeInteger(loop.max_tool_calls) || loop.max_tool_calls < 0 || loop.max_tool_calls > 25
    || loop.stop_condition !== "reviewed_verified_completion" || loop.escalation !== "return_to_human"
    || tools.length > 64 || new Set(names).size !== names.length
    || tools.some(tool => !nonempty(tool.name, 256) || !nonempty(tool.description, 2_048) || !isGovernedMcpProxy(tool.proxy))) {
    throw new LynkConfigurationError("agent requires distinct receipted models, governed tools, finite limits and an explicit acceptance check");
  }

  return Object.freeze({ run: async (input: AgentMission, options: { signal?: AbortSignal } = {}): Promise<AgentRunResult> => {
    const mission = snapshotJson(input) as AgentMission;
    if (!nonempty(mission.id, 256) || !nonempty(mission.objective, 16_384)
      || !Array.isArray(mission.successCriteria) || mission.successCriteria.length < 1
      || mission.successCriteria.length > 25 || mission.successCriteria.some(value => !nonempty(value, 2_048))) {
      throw new LynkValidationError("mission requires an id, objective and concrete success criteria");
    }
    const state: AgentRunResult = { status: "escalated", iterations: 0, modelCalls: 0, toolCalls: 0, receiptHashes: [] };
    const observations: AgentObservation[] = [];
    const failures: Record<string, number> = Object.create(null) as Record<string, number>;
    let feedback = "";
    const stop = (reason: AgentStopReason): AgentRunResult => ({ ...state,
      status: options.signal?.aborted ? "stopped" : "escalated", reason });
    const failure = (code: string): boolean => {
      feedback = code;
      failures[code] = (failures[code] ?? 0) + 1;
      return failures[code]! >= 2;
    };
    const callOptions = (phase: string) => ({
      idempotencyKey: executionHash({ domain: "exo.agent.step.v1", mission_id: mission.id,
        iteration: state.iterations, phase }),
      createdAt: requireHlc(now()), signal: options.signal,
    });
    const invoke = async (model: LynkAgentModel, phase: string, extra: Record<string, unknown> = {}) => {
      state.modelCalls += 1;
      return withRequestDeadline(deadline, options.signal, "agent model operation", signal =>
        model.invoke({ phase, mission, observations, feedback,
          tools: tools.map(({ name, description }) => ({ name, description })), ...extra },
        { ...callOptions(phase), signal }));
    };
    const remember = (result: ReceiptedResult<unknown>): result is Extract<ReceiptedResult<unknown>, { status: "receipted" }> => {
      if (result.status !== "receipted" || !/^[0-9a-f]{64}$/.test(result.receipt.receipt_hash ?? "")) {
        if (result.status === "receipt_pending") state.pending = result;
        return false;
      }
      state.receiptHashes.push(result.receipt.receipt_hash!);
      return true;
    };

    for (let iteration = 1; iteration <= loop.max_iterations; iteration += 1) {
      if (options.signal?.aborted) return stop("human_stop");
      state.iterations = iteration;
      if (state.modelCalls >= loop.max_model_calls) return stop("model_call_limit");
      let planResponse: ReceiptedResult<unknown>;
      try { planResponse = await invoke(planner, "plan"); }
      catch { return stop(options.signal?.aborted ? "human_stop" : "model_unavailable"); }
      if (options.signal?.aborted) return stop("human_stop");
      if (!remember(planResponse)) return stop("model_receipt_unavailable");
      let proposal: AgentProposal;
      try { proposal = proposalFrom(readAgentModelJson(planResponse.output), names); }
      catch {
        if (failure("invalid_proposal")) return stop("repeated_validation_failure");
        continue;
      }
      if (proposal.kind === "tool" && state.toolCalls >= loop.max_tool_calls) return stop("tool_call_limit");
      if (state.modelCalls >= loop.max_model_calls) return stop("model_call_limit");
      const proposalHash = executionHash({ domain: "exo.agent.proposal.v1", mission, proposal,
        iteration, observation_receipts: observations.map(observation => observation.receiptHash) });
      let reviewResponse: ReceiptedResult<unknown>;
      try { reviewResponse = await invoke(reviewer, "review", { proposalHash, proposal }); }
      catch { return stop(options.signal?.aborted ? "human_stop" : "model_unavailable"); }
      if (options.signal?.aborted) return stop("human_stop");
      if (!remember(reviewResponse)) return stop("model_receipt_unavailable");
      let review: AgentReview;
      try { review = reviewFrom(readAgentModelJson(reviewResponse.output), proposalHash); }
      catch {
        if (failure("invalid_review")) return stop("repeated_validation_failure");
        continue;
      }
      if (review.verdict === "escalate") return stop("reviewer_escalation");
      if (review.verdict !== "approve") {
        if (failure("review_rejected")) return stop("repeated_validation_failure");
        continue;
      }
      if (proposal.kind === "complete") {
        const summary = proposal.summary;
        let accepted: boolean;
        try {
          accepted = await withRequestDeadline(deadline, options.signal, "agent acceptance check", async signal =>
            verifyCompletion(structuredClone({ mission, summary, observations }), signal));
        }
        catch { return stop("completion_verification_failed"); }
        if (options.signal?.aborted) return stop("human_stop");
        if (accepted === true) return { ...state, status: "completed", summary: proposal.summary };
        if (failure("acceptance_check_failed")) return stop("repeated_validation_failure");
        continue;
      }
      const toolName = proposal.tool;
      const toolArguments = proposal.arguments;
      const tool = tools.find(item => item.name === toolName)!;
      state.toolCalls += 1;
      let executed: ReceiptedResult<unknown>;
      try {
        executed = await withRequestDeadline(deadline, options.signal, "agent tool operation", signal =>
          tool.proxy.callTool({ name: toolName, arguments: toolArguments }, { ...callOptions("execute"), signal }));
      }
      catch (error) { return stop(error instanceof McpAuthorizationError
        ? (options.signal?.aborted ? "human_stop" : "authorization_denied") : "execution_uncertain"); }
      if (!remember(executed)) return stop(executed.status === "receipt_pending" ? "execution_receipt_pending" : "execution_failed");
      observations.push({ tool: proposal.tool, output: executed.output, receiptHash: executed.receipt.receipt_hash! });
      if (options.signal?.aborted) return stop("human_stop");
      feedback = "The prior tool result is receipted evidence. Check it against every success criterion.";
    }
    return stop("iteration_limit");
  } });
}
