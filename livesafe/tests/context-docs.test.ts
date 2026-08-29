import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();

function readDoc(relativePath: string): string {
  const absolutePath = path.join(root, relativePath);

  expect(existsSync(absolutePath)).toBe(true);

  return readFileSync(absolutePath, "utf8");
}

describe("LiveSafe context control documents", () => {
  it("documents Railway as the active deployment target and Fly as historical drift", () => {
    const relativePath = "README.md";
    const content = readDoc(relativePath);

    expect(content).toContain("Current deployment evidence points to Railway");
    expect(content).toContain("https://livesafe-production.up.railway.app/api/health");
    expect(content).not.toContain("https://livesafe-api-production.up.railway.app");
    expect(content).toContain("Railway project: `livesafe`");
    expect(content).toContain("ARMORCLOUD");
    expect(content).toContain("Railway Postgres");
    expect(content).toContain("Active Railway service: `livesafe`");
    expect(content).toContain("Runtime adapter status: verified");
    expect(content).toContain("Public trust posture: evaluated per environment and fail-closed");
    expect(content).toContain("Live Railway ids belong in closeout evidence");
    expect(content).toContain("Historical Fly.io artifacts remain in-repo");
    expect(content).not.toContain("**Backend / API:** Fly.io");
    expect(content).not.toContain("**Database:** Supabase");
    expect(content).not.toContain("372de75b-5f44-46c2-ab70-3c3185b5d81e");
  });

  it("defines a source-backed repository inventory for the active mapped repositories", () => {
    const relativePath = "docs/REPOSITORY_MAP.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# Repository Map");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Active Repository Intake Records");
    expect(content).toContain("github.com/bob-stewart/livesafe");
    expect(content).toContain("github.com/exochain/exochain");
    expect(content).toContain("/Users/bobstewart/dev/livesafe");
    expect(content).toContain("/Users/bobstewart/dev/exochain");
    expect(content).toContain("prototype");
    expect(content).toContain("read-only dependency evidence");
    expect(content).toContain("https://livesafe-api-production.up.railway.app/api/health");
    expect(content).toContain("Railway project `livesafe`");
    expect(content).toContain("project, environment, service, deployment, and instance ids are live Railway closeout evidence");
    expect(content).toContain(".github/workflows/quality.yml");
    expect(content).toContain(".github/workflows/ci.yml");
    expect(content).toContain("npm run quality");
    expect(content).toContain("npm --prefix server ci");
    expect(content).toContain("cargo test --workspace");
    expect(content).toContain("live health check on 2026-06-05");
    expect(content).toContain("returned `200 OK` on 2026-06-05");
    expect(content).toContain("railway/us-east4-eqdc4a");
    expect(content).toContain(
      "Keep `config/exochain-primitives.json` at `runtimeAdapterStatus: not-wired`",
    );
    expect(content).toContain("do not wire LiveSafe directly into EXOCHAIN core runtime paths");
    expect(content).not.toContain("372de75b-5f44-46c2-ab70-3c3185b5d81e");
  });

  it("defines a source-backed product architecture control document", () => {
    const relativePath = "docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Product Architecture");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Product Surfaces");
    expect(content).toContain("## Domain Contracts");
    expect(content).toContain("## Runtime And Deployment Posture");
    expect(content).toContain("## Current Boundaries");
    expect(content).toContain("## Open Architecture Constraints");
    expect(content).toContain("docs/context/LIVESAFE_CONTEXT_SEED.md");
    expect(content).toContain("docs/EXOCHAIN_APP_BOUNDARY.md");
    expect(content).toContain(
      "docs/context/LIVESAFE_HUMAN_SAFETY_OPPORTUNITY_MODEL.md",
    );
    expect(content).toContain(
      "docs/whitepapers/LIVESAFE_CREATE_CARD_INVITE_FOUR_PROTECT_PEOPLE.md",
    );
    expect(content).toContain("src/human_safety_opportunity.rs");
    expect(content).toContain("src/onboarding_pace.rs");
    expect(content).toContain("src/medical_jacket_custody.rs");
    expect(content).toContain("src/storage_entitlement.rs");
    expect(content).toContain("src/trust-signal.ts");
    expect(content).toContain("https://livesafe-api-production.up.railway.app/api/health");
    expect(content).toContain("live Railway probe stayed healthy on 2026-06-05");
    expect(content).toContain("service, deployment, and instance ids are release evidence");
    expect(content).not.toContain("3619c102-3781-419b-b8e8-a1f05ac46364");
    expect(content).not.toContain("aafd1013-6a29-4af4-b515-9cdaec4a4182");
    expect(content).toContain("Railway CLI verification is currently available");
    expect(content).toContain("config/exochain-production-trust.json");
    expect(content).toContain(
      "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
    );
    expect(content).toContain("379a45e1d9ab092ecd446d095a7b524570530efd");
    expect(content).toContain("public_claims_allowed: false");
    expect(content).not.toContain("2026-06-05T05:54:51.863Z");
    expect(content).not.toContain("372de75b-5f44-46c2-ab70-3c3185b5d81e");
  });

  it("defines the human-safety opportunity model as the parent first-loop doctrine", () => {
    const relativePath =
      "docs/context/LIVESAFE_HUMAN_SAFETY_OPPORTUNITY_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Human Safety Opportunity Model");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Product Doctrine");
    expect(content).toContain("## Fact / Inference Separation");
    expect(content).toContain("## Safety Circle Completion Grant Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "Create your card. Invite your four. Protect your people.",
    );
    expect(content).toContain("src/human_safety_opportunity.rs");
    expect(content).toContain("tests/human_safety_opportunity.rs");
    expect(content).toContain("cargo test --test human_safety_opportunity");
    expect(content).toContain("does not activate runtime behavior");
  });

  it("keeps the P.A.C.E. grant model narrower than the human-safety opportunity model", () => {
    const relativePath =
      "docs/context/LIVESAFE_PACE_READINESS_GRANT_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "docs/context/LIVESAFE_HUMAN_SAFETY_OPPORTUNITY_MODEL.md",
    );
    expect(content).toContain("## Relationship To Human Safety Opportunity");
    expect(content).toContain(
      "This P.A.C.E. Readiness Grant model is narrower.",
    );
    expect(content).toContain(
      "it implements one child incentive boundary",
    );
    expect(content).toContain("does not supersede the");
    expect(content).toContain(
      "human-safety opportunity model; it implements",
    );
  });

  it("defines a source-backed production trust activation gates control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Production Trust Activation Gates");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Runtime And Proof Gates");
    expect(content).toContain("## Current State");
    expect(content).toContain("## Required Public Display");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/EXOCHAIN_APP_BOUNDARY.md");
    expect(content).toContain(
      "docs/context/LIVESAFE_GENESIS_DEVELOPMENT_TRUST.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md",
    );
    expect(content).toContain("src/genesis-trust.ts");
    expect(content).toContain("src/trust-signal.ts");
    expect(content).toContain("src/exochain_adapter_activation.rs");
    expect(content).toContain("tests/genesis-trust.test.ts");
    expect(content).toContain("tests/trust-signal.test.ts");
    expect(content).toContain("tests/exochain_adapter_activation.rs");
    expect(content).toContain("config/exochain-production-trust.json");
    expect(content).toContain("server/utils/exochain-production-trust-evidence.js");
    expect(content).toContain("tests/exochain-production-trust-evidence.test.ts");
    expect(content).toContain("tests/public-exochain-copy-boundary.test.ts");
    expect(content).toContain("7-of-13 FROST");
    expect(content).toContain("exochain_root_evidence_verified");
    expect(content).toContain("exochain_production_evidence_state");
    expect(content).toContain("production_sentinel_quorum_health_below_bft_minimum");
    expect(content).toContain(
      "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
    );
    expect(content).toContain("379a45e1d9ab092ecd446d095a7b524570530efd");
    expect(content).toContain("livesafe_adapter_verified");
    expect(content).toContain("public_trust_claims_allowed");
    expect(content).toContain("THIS IS NOT YET VERIFIED");
    expect(content).toContain("public trust claims remain inactive");
    expect(content).toContain("remove the trust-bearing output");
  });

  it("defines a source-backed LiveSafe to EXOCHAIN integration map", () => {
    const relativePath = "docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe To EXOCHAIN Integration Map");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Runtime Integration Inventory");
    expect(content).toContain("## EXOCHAIN Evidence Inventory");
    expect(content).toContain("## Deployment Drift");
    expect(content).toContain("## Adapter Activation Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/context/LIVESAFE_CONTEXT_SEED.md");
    expect(content).toContain("docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md");
    expect(content).toContain("docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md");
    expect(content).toContain("src/exochain-boundary.ts");
    expect(content).toContain("src/exochain_adapter_activation.rs");
    expect(content).toContain("server/index.js");
    expect(content).toContain("config/exochain-production-trust.json");
    expect(content).toContain("server/utils/exochain-production-trust-evidence.js");
    expect(content).toContain("server/utils/device-response.js");
    expect(content).toContain("server/routes/devices.js");
    expect(content).toContain("tests/exochain-production-trust-evidence.test.ts");
    expect(content).toContain("tests/public-exochain-copy-boundary.test.ts");
    expect(content).toContain("railway.json");
    expect(content).toContain("fly.toml");
    expect(content).toContain("https://livesafe-api-production.up.railway.app/api/health");
    expect(content).toContain("Live health check on 2026-06-05");
    expect(content).toContain("live public probes stayed fail-closed on 2026-06-05");
    expect(content).toContain("project, service, deployment, and instance ids are closeout-only evidence");
    expect(content).toContain("device-management flows");
    expect(content).toContain("subscriber alert-settings and consent-defaults");
    expect(content).toContain("scan follow-up flag acknowledgements");
    expect(content).toContain("using `device_id` as the public");
    expect(content).toContain("revoke handle");
    expect(content).toContain("ARMORCLOUD");
    expect(content).toMatch(/deployment ids are volatile release\s+evidence/);
    expect(content).not.toContain("3619c102-3781-419b-b8e8-a1f05ac46364");
    expect(content).not.toContain("aafd1013-6a29-4af4-b515-9cdaec4a4182");
    expect(content).toContain("Railway CLI verification is currently available");
    expect(content).toContain("server: railway-hikari");
    expect(content).toContain("railway/us-east4-eqdc4a");
    expect(content).toContain("/api/trust/status");
    expect(content).toContain("getPaceStatus");
    expect(content).toContain("pace_alert_delivery.status: failed");
    expect(content).toContain("notification_delivery_failed");
    expect(content).toContain("trustee-directory route fail-closed");
    expect(content).toContain("research opt-in, audit, and trial-consent");
    expect(content).toContain("subscriber-facing P.A.C.E. alert-history route fail-closed");
    expect(content).toContain("GET /api/alerts/pace-alerts/:subscriberDid");
    expect(content).toContain("parse_error_stage");
    expect(content).toContain("EXOCHAIN_TIMEOUT");
    expect(content).toContain("EXOCHAIN_UNAVAILABLE");
    expect(content).toContain("EXOCHAIN_GATEWAY_REJECTED");
    expect(content).toContain("medical_records.extracted_data");
    expect(content).toContain("machine_state\":\"not_verified");
    expect(content).toContain("public_claims_allowed\":false");
    expect(content).toContain("EXOCHAIN root evidence verified");
    expect(content).toContain("LiveSafe adapter verified");
    expect(content).toContain("Public trust claims allowed");
    expect(content).toContain("3fb81ea457e727c010052beafcfe49735ebd0546");
    expect(content).toContain("379a45e1d9ab092ecd446d095a7b524570530efd");
    expect(content).toContain(
      "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
    );
    expect(content).toContain("exochain_production_evidence_state: verified");
    expect(content).toContain("exochain_root_trust_bundle_verified: true");
    expect(content).toContain("QuorumHealth");
    expect(content).toContain("Production-evidence rollback path");
    expect(content).toContain("crates/exo-root");
    expect(content).not.toContain("2026-06-05T05:54:51.863Z");
    expect(content).not.toContain("2026-06-05T05:54:52.418Z");
    expect(content).not.toContain("372de75b-5f44-46c2-ab70-3c3185b5d81e");
  });

  it("defines a source-backed storage entitlements and vault providers control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_STORAGE_ENTITLEMENTS_AND_VAULT_PROVIDERS.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe Storage Entitlements And Vault Providers",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Initial Storage Offering");
    expect(content).toContain("## Provider Boundaries");
    expect(content).toContain("## Safe EXOCHAIN Anchor Fields");
    expect(content).toContain("## Tier-0 Emergency Read Boundary");
    expect(content).toContain("## Commercial And Deployment Constraints");
    expect(content).toContain(
      "context/canon/2026-05-25-phase-17-storage-entitlement-offering.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_COMMERCIAL_ENTITLEMENTS_AND_MARKETPLACE.md",
    );
    expect(content).toContain("src/storage_entitlement.rs");
    expect(content).toContain("tests/storage_entitlement.rs");
    expect(content).toContain("IpfsContentAddressed");
    expect(content).toContain("Tier-0 emergency reads");
    expect(content).toContain("Stripe product ids");
  });

  it("defines a source-backed frontline eligibility policy control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_FRONTLINE_ELIGIBILITY_POLICY.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Frontline Eligibility Policy");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Qualifying Cohorts");
    expect(content).toContain("## Deterministic Eligibility Metadata");
    expect(content).toContain("## Disallowed Proof Handling");
    expect(content).toContain("## Entitlement And Runtime Boundary");
    expect(content).toContain("## Bob-Only Escalation Boundary");
    expect(content).toContain(
      "context/canon/2026-05-24-phase-9-enterprise-onboarding-commercial-architecture.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_COMMERCIAL_ENTITLEMENTS_AND_MARKETPLACE.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md",
    );
    expect(content).toContain("src/entitlement_marketplace.rs");
    expect(content).toContain("tests/entitlement_marketplace.rs");
    expect(content).toContain("FrontlineBasicFamily");
    expect(content).toContain("DeterministicMetadata");
    expect(content).toContain("Heroes");
    expect(content).toContain("PowerlineUtilityWorker");
    expect(content).toContain("FemaResponder");
    expect(content).toContain("EmergencyRoomPersonnel");
    expect(content).toContain("no raw proof documents");
  });

  it("defines a source-backed AI help, feedback, and agent system control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe AI Help, Feedback, And Agent System",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Feature-Gate And Dispatch Posture");
    expect(content).toContain("## Privacy And Redaction Boundary");
    expect(content).toContain("## Runtime And Persistence Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "context/canon/2026-05-24-phase-10-ai-help-feedback-agent-system.md",
    );
    expect(content).toContain(
      "docs/LIVESAFE_AI_HELP_FEEDBACK_AGENT_REQUIREMENTS.md",
    );
    expect(content).toContain("docs/TEST_PLAN.md");
    expect(content).toContain("src/ai_help_topics.rs");
    expect(content).toContain("src/feedback_mandated_reporter.rs");
    expect(content).toContain("tests/ai_help_topics.rs");
    expect(content).toContain("tests/feedback_mandated_reporter.rs");
    expect(content).toContain("disabled by default");
    expect(content).toContain("one dispatch per feedback item per hour");
    expect(content).toContain("redacted payload");
    expect(content).toContain("Live Railway probes on 2026-06-05");
    expect(content).toContain("/api/help/status");
    expect(content).toContain("/api/help/usage-summary/status");
    expect(content).toContain("/api/help/session-transcript/status");
    expect(content).toContain("/api/help/unanswered-topics/status");
    expect(content).toContain("/api/help/feedback-board/status");
    expect(content).toContain("/api/help/feedback-code-hints/status");
    expect(content).toContain("status\":\"inactive");
    expect(content).toContain("read_only\":true");
  });

  it("defines a source-backed AI help typed-route runtime truth document", () => {
    const relativePath =
      "docs/context/LIVESAFE_AI_HELP_TYPED_ROUTE_OPERATIONS.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe AI Help Typed-Route Operations");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Current Runtime Truth");
    expect(content).toContain("Live Railway probes on 2026-06-05");
    expect(content).toContain("/api/help/status");
    expect(content).toContain("/api/help/usage-summary/status");
    expect(content).toContain("/api/help/session-transcript/status");
    expect(content).toContain("/api/help/unanswered-topics/status");
    expect(content).toContain("/api/help/feedback-board/status");
    expect(content).toContain("/api/help/feedback-code-hints/status");
    expect(content).toContain("status\":\"inactive");
    expect(content).toContain("read_only\":true");
    expect(content).toContain("query-ai-help-usage-summary");
    expect(content).toContain("query-ai-help-session-transcript");
    expect(content).toContain("query-ai-help-unanswered-topics");
    expect(content).toContain("query-feedback-board");
  });

  it("records the validated Safety Circle slice while keeping the next real admin gap queued", () => {
    const relativePath = "docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md";
    const content = readDoc(relativePath);

    expect(content).toContain("## Active Slice");
    expect(content).toContain(
      "| Safety Circle onboarding and invitation delivery funnel (2026-06-05T04:40:47Z) | `client/src/pages/Home.jsx`, `client/src/pages/OnboardingWizard.jsx`, `client/src/pages/Pace.jsx`, `client/src/pages/Card.jsx`, `client/src/pages/Dashboard.jsx`, `client/src/pages/Login.jsx`, `client/src/pages/Register.jsx`, `client/src/pages/TrusteeAccept.jsx`, `server/routes/pace.js`, `server/routes/card.js`, `server/utils/pace-invitations.js`, `server/utils/pace-roles.js`, `server/db/schema.sql`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/livesafe-full-funnel-copy.test.ts`, `tests/pace-invitation-delivery.test.ts`, `tests/pace-role-normalization.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/livesafe-full-funnel-copy.test.ts tests/pace-invitation-delivery.test.ts tests/pace-role-normalization.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation failure redaction (2026-06-05T07:10:44Z) | `server/utils/pace-invitations.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-invitation-delivery.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-invitation-delivery.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. trustee nomination validation redaction (2026-06-05T07:57:09Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-trustee-validation.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-trustee-validation.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation resend acknowledgement redaction (2026-06-05T08:12:06Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-request-resend-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-request-resend-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation validate and decline response redaction (2026-06-05T08:26:27Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-invitation-response-redaction.test.ts`, `tests/pace-invitation-response-route.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-invitation-response-redaction.test.ts tests/pace-invitation-response-route.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. governance and recovery workflow response redaction (2026-06-05T08:44:13Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-response-redaction.test.ts`, `tests/pace-workflow-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-response-redaction.test.ts tests/pace-workflow-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. workflow initiation response redaction (2026-06-05T08:57:14Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-initiation-redaction.test.ts`, `tests/pace-workflow-initiation-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. emergency-override initiation acknowledgement redaction (2026-06-07T14:14:18Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-initiation-redaction.test.ts`, `tests/pace-workflow-initiation-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. recovery summary redaction (2026-06-05T09:11:08Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-response-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-response-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. VSS-status redaction (2026-06-05T09:42:00Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-vss-status-redaction.test.ts`, `tests/pace-vss-status-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-vss-status-redaction.test.ts tests/pace-vss-status-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Trustee-facing VSS summary redaction (2026-06-05T11:14:00Z) | `server/routes/pace.js`, `server/routes/auth.js`, `server/utils/trustee-vss-summary.js`, `client/src/pages/TrusteeDashboard.jsx`, `client/src/pages/TrusteeSubscriberDetail.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/trustee-vss-summary.test.ts`, `tests/trustee-vss-route-redaction.test.ts`, `tests/trustee-vss-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/trustee-vss-summary.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Trustee auth response redaction (2026-06-07T02:28:00Z) | `server/routes/auth.js`, `server/utils/auth-trustee-response.js`, `server/utils/trustee-vss-summary.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-trustee-response-redaction.test.ts`, `tests/auth-trustee-route-redaction.test.ts`, `tests/trustee-vss-route-redaction.test.ts`, `tests/trustee-vss-summary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-trustee-response-redaction.test.ts tests/auth-trustee-route-redaction.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan agency roster redaction (2026-06-05T11:26:36Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-agency-redaction.test.ts`, `tests/scan-agency-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber scan history and detail redaction (2026-06-06T05:57:24Z) | `server/routes/scan.js`, `client/src/pages/ScanHistory.jsx`, `client/src/pages/ScanDetail.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-history-response-redaction.test.ts`, `tests/scan-history-route-redaction.test.ts`, `tests/scan-history-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-history-response-redaction.test.ts tests/scan-history-route-redaction.test.ts tests/scan-history-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. trustee-directory redaction (2026-06-05T10:12:30Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-trustee-directory-redaction.test.ts`, `tests/pace-trustee-directory-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-trustee-directory-redaction.test.ts tests/pace-trustee-directory-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Trustee-facing VSS summary redaction (2026-06-05T11:14:00Z) | `server/routes/pace.js`, `server/routes/auth.js`, `server/utils/trustee-vss-summary.js`, `client/src/pages/TrusteeDashboard.jsx`, `client/src/pages/TrusteeSubscriberDetail.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/trustee-vss-summary.test.ts`, `tests/trustee-vss-route-redaction.test.ts`, `tests/trustee-vss-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/trustee-vss-summary.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-access workflow redaction (2026-06-05T09:56:41Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-access-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-access initiation acknowledgement redaction (2026-06-07T18:44:00Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-access-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-data response redaction (2026-06-07T01:58:00Z) | `server/routes/scan.js`, `server/utils/medical-record-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-data-response-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-data-response-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-data response redaction (2026-06-07T01:58:00Z) | `server/routes/scan.js`, `server/utils/medical-record-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-data-response-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-data-response-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan creation response redaction (2026-06-05T11:45:00Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-create-response-redaction.test.ts`, `tests/scan-create-route-redaction.test.ts`, `tests/scan-exochain-payload.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-create-response-redaction.test.ts tests/scan-create-route-redaction.test.ts tests/scan-exochain-payload.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Medical-record parse-error redaction (2026-06-05T07:27:00Z) | `server/routes/records.js`, `server/utils/record-extracted-data.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-extracted-data.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-extracted-data.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Record-request response redaction and live route alignment (2026-06-06T14:27:00Z) | `server/routes/records.js`, `server/utils/record-request-response.js`, `client/src/pages/Records.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-request-response-redaction.test.ts`, `tests/record-request-route-redaction.test.ts`, `tests/record-request-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-request-response-redaction.test.ts tests/record-request-route-redaction.test.ts tests/record-request-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Notification response redaction (2026-06-06T04:25:57Z) | `server/routes/notifications.js`, `server/utils/notification-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/notifications-response-redaction.test.ts`, `tests/notifications-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/notifications-response-redaction.test.ts tests/notifications-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Notification acknowledgement redaction (2026-06-07T05:30:00Z) | `server/routes/notifications.js`, `server/utils/notification-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/notifications-response-redaction.test.ts`, `tests/notifications-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/notifications-response-redaction.test.ts tests/notifications-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Alert response redaction (2026-06-06T04:57:57Z) | `server/routes/alerts.js`, `server/utils/alert-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/alerts-response-redaction.test.ts`, `tests/alerts-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber alert-event response redaction (2026-06-06T08:57:14Z) | `server/routes/alerts.js`, `server/utils/alert-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/alerts-response-redaction.test.ts`, `tests/alerts-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Consent provider-directory and access-request response redaction (2026-06-06T10:30:00Z) | `server/utils/consent-response.js`, `server/routes/consent.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/consent-response-redaction.test.ts`, `tests/consent-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/consent-response-redaction.test.ts tests/consent-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Consent provider request-create acknowledgement redaction (2026-06-07T14:45:00Z) | `server/utils/consent-response.js`, `server/routes/consent.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/consent-response-redaction.test.ts`, `tests/consent-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/consent-response-redaction.test.ts tests/consent-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin responder response redaction (2026-06-06T12:58:00Z) | `server/routes/admin.js`, `server/utils/admin-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-responder-response-redaction.test.ts`, `tests/admin-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-responder-response-redaction.test.ts tests/admin-responder-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin subscriber response redaction (2026-06-06T13:27:00Z) | `server/routes/admin.js`, `server/utils/admin-subscriber-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-subscriber-response-redaction.test.ts`, `tests/admin-subscriber-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-subscriber-response-redaction.test.ts tests/admin-subscriber-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin agency response redaction (2026-06-06T13:58:00Z) | `server/routes/admin.js`, `server/utils/admin-agency-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-agency-response-redaction.test.ts`, `tests/admin-agency-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-agency-response-redaction.test.ts tests/admin-agency-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin agency dashboard payload alignment (2026-06-06T18:26:00Z) | `client/src/pages/AdminDashboard.jsx`, `tests/admin-agency-dashboard-alignment.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-agency-dashboard-alignment.test.ts`, `tests/admin-agency-response-redaction.test.ts`, `tests/admin-agency-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-agency-dashboard-alignment.test.ts tests/admin-agency-response-redaction.test.ts tests/admin-agency-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin audit response redaction (2026-06-07T03:00:00Z) | `server/routes/admin.js`, `server/utils/admin-audit-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-audit-response-redaction.test.ts`, `tests/admin-audit-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-audit-response-redaction.test.ts tests/admin-audit-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Legacy subscriber management hardening (2026-06-06T18:58:00Z) | `server/routes/subscribers.js`, `tests/subscriber-management-route-hardening.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-management-route-hardening.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-management-route-hardening.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Legacy subscriber create/detail redaction (2026-06-07T00:26:00Z) | `server/routes/subscribers.js`, `tests/subscriber-management-route-hardening.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-management-route-hardening.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-management-route-hardening.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber profile response redaction (2026-06-06T22:27:00Z) | `server/routes/subscribers.js`, `server/utils/subscriber-profile-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-profile-response-redaction.test.ts`, `tests/subscriber-profile-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Emergency-contact response redaction (2026-06-06T22:58:00Z) | `server/routes/subscribers.js`, `server/utils/subscriber-profile-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-profile-response-redaction.test.ts`, `tests/subscriber-profile-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber delete-acknowledgement redaction (2026-06-07T04:28:00Z) | `server/routes/subscribers.js`, `server/utils/subscriber-profile-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-profile-response-redaction.test.ts`, `tests/subscriber-profile-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Credential update response redaction (2026-06-06T11:10:00Z) | `server/routes/credentials.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/credential-update-response-redaction.test.ts`, `tests/credential-update-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/credential-update-response-redaction.test.ts tests/credential-update-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Credential upload response redaction (2026-06-06T11:57:00Z) | `server/routes/credentials.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/credential-upload-response-redaction.test.ts`, `tests/credential-upload-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/credential-upload-response-redaction.test.ts tests/credential-upload-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan post-action alert failure redaction (2026-06-05T06:56:39Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-exochain-payload.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-exochain-payload.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan emergency-subset identifier redaction (2026-06-05T12:57:15Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-access-response-redaction.test.ts`, `tests/scan-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan responder emergency-subset redaction (2026-06-05T13:15:00Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-emergency-subset-response-redaction.test.ts`, `tests/scan-emergency-subset-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-emergency-subset-response-redaction.test.ts tests/scan-emergency-subset-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan token-access response redaction (2026-06-05T11:54:55Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-access-response-redaction.test.ts`, `tests/scan-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Health-route database error redaction (2026-06-05T06:26:08Z) | `server/utils/health-status.js`, `server/index.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/health-status.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/health-status.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity claims response redaction (2026-06-06T14:57:00Z) | `server/routes/odentity.js`, `server/utils/odentity-claim-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-claims-response-redaction.test.ts`, `tests/odentity-claims-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-claims-response-redaction.test.ts tests/odentity-claims-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity gated-features ownership (2026-06-06T15:28:00Z) | `server/routes/odentity.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-gated-features-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity score response redaction (2026-06-06T15:58:00Z) | `server/routes/odentity.js`, `server/utils/odentity-score-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-score-response-redaction.test.ts`, `tests/odentity-score-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-score-response-redaction.test.ts tests/odentity-score-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity export VC response redaction (2026-06-06T16:27:00Z) | `server/routes/odentity.js`, `server/utils/odentity-export-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-export-response-redaction.test.ts`, `tests/odentity-export-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-export-response-redaction.test.ts tests/odentity-export-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity claim-write and revoke response redaction (2026-06-06T16:58:00Z) | `server/routes/odentity.js`, `server/utils/odentity-claim-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-claim-write-response-redaction.test.ts`, `tests/odentity-claim-write-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-claim-write-response-redaction.test.ts tests/odentity-claim-write-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity claim-import ownership hardening (2026-06-06T19:58:00Z) | `server/routes/odentity.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-claim-write-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-claim-write-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity gated-features response redaction (2026-06-06T17:26:00Z) | `server/routes/odentity.js`, `server/utils/odentity-gated-features-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-gated-features-response-redaction.test.ts`, `tests/odentity-gated-features-response-route-redaction.test.ts`, `tests/odentity-gated-features-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-gated-features-response-redaction.test.ts tests/odentity-gated-features-response-route-redaction.test.ts tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity trust-event acknowledgement redaction (2026-06-06T17:56:00Z) | `server/routes/odentity.js`, `server/utils/odentity-trust-event-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-trust-event-response-redaction.test.ts`, `tests/odentity-trust-event-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-trust-event-response-redaction.test.ts tests/odentity-trust-event-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity trust-event authority hardening (2026-06-06T20:26:00Z) | `server/routes/odentity.js`, `tests/odentity-trust-event-route-redaction.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-trust-event-route-redaction.test.ts`, `tests/odentity-trust-event-response-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-trust-event-route-redaction.test.ts tests/odentity-trust-event-response-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Responder auth response redaction (2026-06-06T20:58:00Z) | `server/routes/auth.js`, `server/utils/auth-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-responder-response-redaction.test.ts`, `tests/auth-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber auth response redaction (2026-06-07T00:57:00Z) | `server/routes/auth.js`, `server/utils/auth-subscriber-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-subscriber-response-redaction.test.ts`, `tests/auth-subscriber-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-subscriber-response-redaction.test.ts tests/auth-subscriber-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Provider auth response redaction (2026-06-07T01:30:00Z) | `server/routes/auth.js`, `server/utils/auth-provider-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-provider-response-redaction.test.ts`, `tests/auth-provider-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin stats response redaction (2026-06-07T09:20:00Z) | `server/routes/admin.js`, `server/utils/admin-stats-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-stats-response-redaction.test.ts`, `tests/admin-stats-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-stats-response-redaction.test.ts tests/admin-stats-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Provider NPI lookup response redaction (2026-06-07T03:56:20Z) | `server/routes/auth.js`, `server/utils/auth-provider-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-provider-response-redaction.test.ts`, `tests/auth-provider-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Verification acknowledgement redaction (2026-06-07T03:29:00Z) | `server/routes/auth.js`, `server/routes/subscribers.js`, `server/utils/verification-response.js`, `client/src/pages/VerifyEmail.jsx`, `client/src/pages/Profile.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/verification-response-redaction.test.ts`, `tests/verification-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/verification-response-redaction.test.ts tests/verification-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Record provider-directory redaction (2026-06-06T22:00:00Z) | `server/routes/records.js`, `server/utils/record-provider-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-provider-response-redaction.test.ts`, `tests/medical-record-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-provider-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Public agency directory redaction (2026-06-06T21:26:00Z) | `server/routes/auth.js`, `server/utils/auth-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-responder-response-redaction.test.ts`, `tests/auth-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Responder auth session redaction (2026-06-07T18:15:00Z) | `server/routes/auth.js`, `server/utils/auth-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-responder-response-redaction.test.ts`, `tests/auth-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber profile response redaction (2026-06-06T22:27:00Z) | `server/routes/subscribers.js`, `server/utils/subscriber-profile-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-profile-response-redaction.test.ts`, `tests/subscriber-profile-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Emergency-card response redaction (2026-06-06T19:29:00Z) | `server/utils/card-response.js`, `server/routes/card.js`, `client/src/pages/Card.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/card-response-redaction.test.ts`, `tests/card-route-redaction.test.ts`, `tests/card-page-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/card-response-redaction.test.ts tests/card-route-redaction.test.ts tests/card-page-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber medical-entry response redaction (2026-06-06T23:28:00Z) | `server/routes/subscribers.js`, `server/utils/subscriber-profile-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-profile-response-redaction.test.ts`, `tests/subscriber-profile-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Name | No active unfinished implementation slice |",
    );
    expect(content).toContain(
      "| Classification | selector state awaiting integration-map re-rank |",
    );
    expect(content).toContain(
      "The completed-slice inventory includes the 2026-08-28 adjacent overflow and dependency remediation.",
    );
    expect(content).toContain(
      "promote the next smallest source-backed executable gap before any bounded truth pass.",
    );
    expect(content).toContain(
      "next selection should confirm whether any smaller adjacent auth, authenticated write, or response boundary gap remains before any truth-pass fallback",
    );
    expect(content).toContain(
      "Re-rank `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md` for any remaining smaller adjacent auth, authenticated write, or response boundary gap before allowing a truth pass.",
    );
    expect(content).toContain("P.A.C.E. invitation validate and decline response redaction");
    expect(content).toContain("P.A.C.E. governance and recovery workflow response redaction");
    expect(content).toContain("P.A.C.E. workflow initiation response redaction");
    expect(content).toContain("P.A.C.E. emergency-override initiation acknowledgement redaction");
    expect(content).toContain("P.A.C.E. recovery summary redaction");
    expect(content).toContain("P.A.C.E. VSS-status redaction");
    expect(content).toContain("Scan expanded-access workflow redaction");
    expect(content).toContain("Scan expanded-data response redaction");
    expect(content).toContain("Scan token-access response redaction");
    expect(content).toContain("Scan responder emergency-subset redaction");
    expect(content).toContain("Medical-record parse-error redaction");
    expect(content).toContain("## Next Slice Queue");
    expect(content).toContain(
      "The completed-slice inventory includes the 2026-08-28 adjacent overflow and dependency remediation.",
    );
    expect(content).toContain(
      "Re-rank `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md` for any remaining smaller adjacent auth, authenticated write, or response boundary gap before allowing a truth pass.",
    );
    expect(content).toContain("Workspace configuration contract");
    expect(content).toContain("Heroes registration copy and payload truth pass");
    expect(content).toContain("Subscriber hero registration schema truth pass");
    expect(content).toContain("Feedback code-hints status API contract");
  });

  it("keeps the test plan aligned with the validated Safety Circle and existing configuration coverage", () => {
    const relativePath = "docs/TEST_PLAN.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "Focused validation for the current EXOCHAIN-client transport redaction,",
    );
    expect(content).toContain(
      "### Adjacent Overflow And Dependency Security Slice",
    );
    expect(content).toContain(
      "`postcss ^8.5.23` and `react-router-dom ^7.18.0`",
    );
    expect(content).toContain(
      "npm test -- tests/exochain-client.test.ts tests/pace-invitation-delivery.test.ts tests/pace-trustee-validation.test.ts tests/pace-request-resend-redaction.test.ts tests/pace-create-response-redaction.test.ts tests/pace-create-response-route-redaction.test.ts tests/pace-send-response-redaction.test.ts tests/pace-send-route-redaction.test.ts tests/pace-invitation-response-redaction.test.ts tests/pace-invitation-response-route.test.ts tests/pace-workflow-response-redaction.test.ts tests/pace-workflow-route-redaction.test.ts tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts tests/pace-acceptance-response-redaction.test.ts tests/pace-acceptance-route-redaction.test.ts tests/pace-vss-status-redaction.test.ts tests/pace-vss-status-route-redaction.test.ts tests/pace-trustee-directory-redaction.test.ts tests/pace-trustee-directory-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-ui-redaction.test.ts tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/scan-expanded-data-response-redaction.test.ts tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts tests/scan-history-response-redaction.test.ts tests/scan-history-route-redaction.test.ts tests/scan-history-ui-redaction.test.ts tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts tests/scan-emergency-subset-response-redaction.test.ts tests/scan-emergency-subset-route-redaction.test.ts tests/record-extracted-data.test.ts",
    );
    expect(content).toContain(
      "The Safety Circle full-funnel copy contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. invitation delivery contract validates canonical Primary,",
    );
    expect(content).toContain(
      "The scan agency roster redaction contract validates that agency-admin scan",
    );
    expect(content).toContain(
      "The agency responder directory redaction contract validates that the",
    );
    expect(content).toContain(
      "The admin responder response redaction contract validates that agency-admin",
    );
    expect(content).toContain(
      "The admin subscriber response redaction contract validates that platform-admin",
    );
    expect(content).toContain(
      "The admin agency response redaction contract validates that platform-admin",
    );
    expect(content).toContain(
      "Focused validation for the scan follow-up acknowledgement redaction slice:",
    );
    expect(content).toContain(
      "npm test -- tests/admin-stats-response-redaction.test.ts tests/admin-stats-route-redaction.test.ts tests/context-docs.test.ts",
    );
    expect(content).toContain(
      "The admin audit response redaction contract validates that platform-admin",
    );
    expect(content).toContain(
      "The responder auth response redaction contract validates that responder",
    );
    expect(content).toContain(
      "The responder auth session redaction contract validates that responder login",
    );
    expect(content).toContain(
      "The provider auth response redaction contract validates that provider",
    );
    expect(content).toContain(
      "The verification acknowledgement redaction contract validates that email and",
    );
    expect(content).toContain(
      "The trustee auth response redaction contract validates that trustee",
    );
    expect(content).toContain(
      "The public agency directory redaction contract validates that",
    );
    expect(content).toContain(
      "The subscriber profile response redaction contract validates that",
    );
    expect(content).toContain(
      "The subscriber medical-entry response redaction contract validates that",
    );
    expect(content).toContain(
      "The emergency-contact response redaction contract validates that",
    );
    expect(content).toContain(
      "The subscriber delete-acknowledgement redaction contract validates that",
    );
    expect(content).toContain(
      "The legacy subscriber management hardening contract validates that legacy",
    );
    expect(content).toContain(
      "The legacy subscriber create/detail redaction contract validates that",
    );
    expect(content).toContain(
      "The subscriber scan history and detail redaction contract validates that",
    );
    expect(content).toContain("bounded `notification_delivery_failed` redaction");
    expect(content).toContain(
      "The P.A.C.E. trustee nomination validation contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. expired-invitation resend acknowledgement contract validates",
    );
    expect(content).toContain(
      "The trustee-facing VSS summary redaction contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. invitation acceptance response redaction contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. trustee nomination response contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. invitation validate and decline response contract validates",
    );
    expect(content).toContain(
      "The P.A.C.E. workflow response redaction contract validates that governance",
    );
    expect(content).toContain(
      "The P.A.C.E. invitation send response redaction contract validates that the",
    );
    expect(content).toContain(
      "The P.A.C.E. workflow initiation response redaction contract validates that",
    );
    expect(content).toContain(
      "trustee-replacement, emergency-override, and identity-recovery initiation",
    );
    expect(content).toContain(
      "The P.A.C.E. recovery summary redaction contract validates that public",
    );
    expect(content).toContain(
      "The P.A.C.E. VSS-status redaction contract validates that the unauthenticated",
    );
    expect(content).toContain(
      "The scan expanded-access workflow redaction contract validates that scan",
    );
    expect(content).toContain(
      "approvals-remaining counts, bounded",
    );
    expect(content).toContain(
      "The scan expanded-data response redaction contract validates that approved",
    );
    expect(content).toContain(
      "credential summaries, and medical-record metadata without reflecting raw",
    );
    expect(content).toContain(
      "The scan token-access response redaction contract validates that",
    );
    expect(content).toContain(
      "The scan responder emergency-subset redaction contract validates that",
    );
    expect(content).toContain("EXOCHAIN_TIMEOUT");
    expect(content).toContain("EXOCHAIN_UNAVAILABLE");
    expect(content).toContain("EXOCHAIN_GATEWAY_REJECTED");
    expect(content).toContain(
      "The medical-record extracted-data contract validates bounded XML, C-CDA,",
    );
    expect(content).toContain(
      "The clinical-note response redaction contract validates that provider-note",
    );
    expect(content).toContain(
      "keep both note payloads and route-level acknowledgement/list envelopes",
    );
    expect(content).toContain(
      "The medical-record response redaction contract validates that upload, list,",
    );
    expect(content).toContain(
      "Focused validation for the medical-record deletion-acknowledgement redaction slice:",
    );
    expect(content).toContain("tests/clinical-note-response-redaction.test.ts");
    expect(content).toContain("tests/clinical-note-route-redaction.test.ts");
    expect(content).toContain(
      "The record-request response redaction contract validates that HIPAA",
    );
    expect(content).toContain(
      "The alert response redaction contract validates that alert dispatch, history,",
    );
    expect(content).toContain(
      "The subscriber alert-event response redaction contract validates that",
    );
    expect(content).toContain(
      "The consent provider-directory and access-request response redaction",
    );
    expect(content).toContain(
      "The consent acknowledgement and status response redaction contract validates",
    );
    expect(content).toContain("tests/scan-agency-redaction.test.ts");
    expect(content).toContain("tests/scan-agency-route-redaction.test.ts");
    expect(content).toContain("tests/auth-responder-response-redaction.test.ts");
    expect(content).toContain("tests/auth-responder-route-redaction.test.ts");
    expect(content).toContain("The workspace configuration contract validates");
    expect(content).toContain(
      "The heroes registration copy and payload contract validates",
    );
    expect(content).toContain(
      "The subscriber registration schema contract validates",
    );
    expect(content).toContain(
      "The feedback code-hints status API contract validates",
    );
    expect(content).toContain(
      "feedback code-hints status path",
    );
    expect(content).toContain("tests/config.test.ts");
    expect(content).toContain("tests/heroes-registration-copy.test.ts");
    expect(content).toContain(
      "tests/schema-subscriber-registration.test.ts",
    );
    expect(content).toContain("tests/exochain-client.test.ts");
    expect(content).toContain("tests/pace-invitation-delivery.test.ts");
    expect(content).toContain("tests/record-extracted-data.test.ts");
  });

  it("records that no Bob-only escalation is currently narrowed for the repo snapshot", () => {
    const relativePath = "docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md";
    const content = readDoc(relativePath);

    expect(content).toContain("## Current Narrowed Escalation");
    expect(content).toContain(
      "No Bob-only escalation is currently narrowed for the current repo snapshot.",
    );
    expect(content).not.toContain(
      "No Bob-only escalation blocked the onboarding and P.A.C.E. contract slice.",
    );
  });

  it("defines a source-backed AI help persistence namespace control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_AI_HELP_PERSISTENCE_NAMESPACE.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe AI Help Persistence Namespace",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Required Storage Capabilities");
    expect(content).toContain("## Namespace Inventory");
    expect(content).toContain("## Backend Selection Boundary");
    expect(content).toContain("## TTL And Retention Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "docs/LIVESAFE_AI_HELP_FEEDBACK_AGENT_REQUIREMENTS.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md",
    );
    expect(content).toContain("docs/TEST_PLAN.md");
    expect(content).toContain("src/ai_help_usage_summary.rs");
    expect(content).toContain("src/ai_help_session_transcript.rs");
    expect(content).toContain("src/ai_help_unanswered_topic.rs");
    expect(content).toContain("tests/ai_help_usage_summary.rs");
    expect(content).toContain("tests/ai_help_session_transcript.rs");
    expect(content).toContain("tests/ai_help_unanswered_topic.rs");
    expect(content).toContain("livesafe:help:session:{sessionId}");
    expect(content).toContain("livesafe:help:session:{sessionId}:messages");
    expect(content).toContain("livesafe:help:sessions:recent");
    expect(content).toContain("livesafe:help:topic:unanswered:{topicId}");
    expect(content).toContain("seven-day TTL");
    expect(content).toContain("write operations remain disabled by default");
  });

  it("defines a source-backed feedback-board persistence namespace control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_FEEDBACK_BOARD_PERSISTENCE_NAMESPACE.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe Feedback Board Persistence Namespace",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Required Storage Capabilities");
    expect(content).toContain("## Namespace Inventory");
    expect(content).toContain("## Backend Selection Boundary");
    expect(content).toContain("## Identifier And Status Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "docs/LIVESAFE_AI_HELP_FEEDBACK_AGENT_REQUIREMENTS.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_AI_HELP_TYPED_ROUTE_OPERATIONS.md",
    );
    expect(content).toContain("docs/TEST_PLAN.md");
    expect(content).toContain("src/feedback-board-persistence.ts");
    expect(content).toContain("src/feedback-board-query.ts");
    expect(content).toContain("src/feedback_board_read_model.rs");
    expect(content).toContain("tests/feedback-board-persistence.test.ts");
    expect(content).toContain("tests/feedback-board-query.test.ts");
    expect(content).toContain("tests/feedback_board_read_model.rs");
    expect(content).toContain("livesafe:feedback:item:{id}");
    expect(content).toContain("livesafe:feedback:board:{status}");
    expect(content).toContain("livesafe:feedback:by_target:{type}:{id}");
    expect(content).toContain("livesafe:feedback:by_work_batch:{workBatchTag}");
    expect(content).toContain("livesafe:feedback:index:all");
    expect(content).toContain("livesafe:feedback:activities:{feedbackId}");
    expect(content).toContain("livesafe:feedback:votes:{id}");
    expect(content).toContain("livesafe:feedback:stats:by_category");
    expect(content).toContain("livesafe:feedback:stats:by_target_type");
    expect(content).toContain("livesafe:feedback:stats:by_status");
    expect(content).toContain("write routes remain disabled by default");
  });

  it("defines a source-backed AI help typed-route operations control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_AI_HELP_TYPED_ROUTE_OPERATIONS.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe AI Help Typed-Route Operations",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Runtime Truth");
    expect(content).toContain("## Required Typed Query Operations");
    expect(content).toContain("## Disabled Write Operations");
    expect(content).toContain("## Route Typing And Gate Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "docs/LIVESAFE_AI_HELP_FEEDBACK_AGENT_REQUIREMENTS.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_AI_HELP_PERSISTENCE_NAMESPACE.md",
    );
    expect(content).toContain("docs/TEST_PLAN.md");
    expect(content).toContain("server/index.js");
    expect(content).toContain("server/utils/ai-help-status.js");
    expect(content).toContain("server/utils/ai-help-usage-summary-status.js");
    expect(content).toContain("server/utils/ai-help-unanswered-topic-status.js");
    expect(content).toContain("src/ai-help-unanswered-topic-query.ts");
    expect(content).toContain("src/feedback-board-query.ts");
    expect(content).toContain("tests/ai-help-status.test.ts");
    expect(content).toContain("tests/ai-help-usage-summary-status.test.ts");
    expect(content).toContain("tests/ai-help-unanswered-topic-query.test.ts");
    expect(content).toContain("tests/ai-help-unanswered-topic-status.test.ts");
    expect(content).toContain("tests/feedback-board-query.test.ts");
    expect(content).toContain("src/feedback_board_read_model.rs");
    expect(content).toContain("src/ai_help_usage_summary.rs");
    expect(content).toContain("src/ai_help_unanswered_topic.rs");
    expect(content).toContain("GET /api/help/status");
    expect(content).toContain("GET /api/help/usage-summary/status");
    expect(content).toContain("GET /api/help/unanswered-topics/status");
    expect(content).toContain("read-status");
    expect(content).toContain("Query feedback board");
    expect(content).toContain("Query AI help usage summary");
    expect(content).toContain("Query AI help unanswered topics");
    expect(content).toContain("Create feedback");
    expect(content).toContain("Ask AI help with streamed or chunked responses");
    expect(content).toContain("default disabled");
    expect(content).toContain("405");
  });

  it("keeps the AI help and feedback control doc aligned with all verified status routes", () => {
    const relativePath =
      "docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe AI Help, Feedback, And Agent System",
    );
    expect(content).toContain("server/utils/ai-help-status.js");
    expect(content).toContain("server/utils/ai-help-usage-summary-status.js");
    expect(content).toContain(
      "server/utils/ai-help-session-transcript-status.js",
    );
    expect(content).toContain(
      "server/utils/ai-help-unanswered-topic-status.js",
    );
    expect(content).toContain("server/utils/feedback-board-status.js");
    expect(content).toContain("server/utils/feedback-code-hints-status.js");
    expect(content).toContain("tests/ai-help-status.test.ts");
    expect(content).toContain("tests/ai-help-usage-summary-status.test.ts");
    expect(content).toContain(
      "tests/ai-help-session-transcript-status.test.ts",
    );
    expect(content).toContain("tests/ai-help-unanswered-topic-query.test.ts");
    expect(content).toContain("tests/ai-help-unanswered-topic-status.test.ts");
    expect(content).toContain("tests/feedback-board-status.test.ts");
    expect(content).toContain("tests/feedback-code-hints-status.test.ts");
    expect(content).toContain("GET /api/help/status");
    expect(content).toContain("GET /api/help/usage-summary/status");
    expect(content).toContain("GET /api/help/session-transcript/status");
    expect(content).toContain("GET /api/help/unanswered-topics/status");
    expect(content).toContain("GET /api/help/feedback-board/status");
    expect(content).toContain("GET /api/help/feedback-code-hints/status");
    expect(content).not.toContain(
      "GET /api/help/status` as the only verified public AI-help route",
    );
  });

  it("defines a source-backed QR activation control document", () => {
    const relativePath = "docs/context/LIVESAFE_QR_ACTIVATION_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe QR Activation Model");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Pointer And Runtime Boundary");
    expect(content).toContain("## Responder Scope Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "context/canon/2026-05-24-phase-5-exo-safe-card-runtime.md",
    );
    expect(content).toContain(
      "context/canon/2026-05-24-phase-8-ice-card-images.md",
    );
    expect(content).toContain("docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md");
    expect(content).toContain("src/qr_pointer.rs");
    expect(content).toContain("src/qr_activation.rs");
    expect(content).toContain("tests/qr_pointer.rs");
    expect(content).toContain("tests/qr_activation.rs");
    expect(content).toContain("metadata-only activation payloads");
    expect(content).toContain("emergency subset");
    expect(content).toContain("verified adapter path returns permit");
  });

  it("defines a source-backed VitalLock vault control document", () => {
    const relativePath = "docs/context/LIVESAFE_VITALLOCK_VAULT_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe VitalLock Vault Model");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Storage And Custody Boundary");
    expect(content).toContain("## Responder And Delegated Access Boundary");
    expect(content).toContain("## Test Evidence");
    expect(content).toContain("## Boundaries");
    expect(content).toContain("docs/context/LIVESAFE_STORAGE_ENTITLEMENTS_AND_VAULT_PROVIDERS.md");
    expect(content).toContain("docs/context/LIVESAFE_MEDICAL_JACKET_AND_CUSTODY_MODEL.md");
    expect(content).toContain("docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md");
    expect(content).toContain("docs/LIVESAFE_AI_HELP_FEEDBACK_AGENT_REQUIREMENTS.md");
    expect(content).toContain("src/vitallock_vault.rs");
    expect(content).toContain("tests/vitallock_vault.rs");
    expect(content).toContain("EmergencySubset");
    expect(content).toContain("MetadataOnly");
    expect(content).toContain("full vault export remains blocked");
  });

  it("defines a source-backed Ambient signal control document", () => {
    const relativePath = "docs/context/LIVESAFE_AMBIENT_SIGNAL_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Ambient Signal Model");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Marketplace And Consent Boundary");
    expect(content).toContain("## Runtime Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/context/LIVESAFE_CONTEXT_SEED.md");
    expect(content).toContain("docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md");
    expect(content).toContain(
      "docs/context/LIVESAFE_COMMERCIAL_ENTITLEMENTS_AND_MARKETPLACE.md",
    );
    expect(content).toContain("docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md");
    expect(content).toContain(
      "context/canon/2026-05-24-phase-9-enterprise-onboarding-commercial-architecture.md",
    );
    expect(content).toContain("src/ambient_signal.rs");
    expect(content).toContain("src/entitlement_marketplace.rs");
    expect(content).toContain("tests/ambient_signal.rs");
    expect(content).toContain("recipient-visible Ambient delivery remains inactive");
    expect(content).toContain("Ambient signal acknowledgement");
    expect(content).toContain("metadata-only");
  });

  it("defines a source-backed responder access display control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_RESPONDER_ACCESS_DISPLAY_MODEL.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Responder Access Display Model");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Emergency Subset Boundary");
    expect(content).toContain("## Trust And Runtime Boundary");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/context/LIVESAFE_EMERGENCY_PROFILE_MODEL.md");
    expect(content).toContain("docs/context/LIVESAFE_QR_ACTIVATION_MODEL.md");
    expect(content).toContain("docs/context/LIVESAFE_VITALLOCK_VAULT_MODEL.md");
    expect(content).toContain("docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md");
    expect(content).toContain("src/responder_access_display.rs");
    expect(content).toContain("tests/responder_access_display.rs");
    expect(content).toContain("emergency-subset-only");
    expect(content).toContain("Expanded responder access displays remain blocked");
    expect(content).toContain("VerifiedPermit");
  });

  it("defines a source-backed legacy charter and exo-legacy dependency control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_LEGACY_CHARTER_AND_EXO_LEGACY_DEPENDENCY.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe Legacy Charter And Exo-Legacy Dependency",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## EXOCHAIN Dependency Boundary");
    expect(content).toContain("## Emergency Versus Posthumous Boundary");
    expect(content).toContain("## Data And Receipt Boundary");
    expect(content).toContain("## Activation And Copy Gates");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "context/canon/2026-05-24-phase-11-exo-legacy-build-package.md",
    );
    expect(content).toContain("docs/LIVESAFE_EXO_LEGACY_REQUIREMENTS.md");
    expect(content).toContain("docs/EXOCHAIN_APP_BOUNDARY.md");
    expect(content).toContain("src/legacy_dependency.rs");
    expect(content).toContain("tests/legacy_dependency.rs");
    expect(content).toContain("crates/exo-legacy");
    expect(content).toContain("Legacy capabilities remain inactive");
    expect(content).toContain("Emergency Tier-0");
    expect(content).toContain("key-destruction receipt");
  });

  it("defines a source-backed genesis development trust control document", () => {
    const relativePath = "docs/context/LIVESAFE_GENESIS_DEVELOPMENT_TRUST.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Genesis Development Trust");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## Allowed Genesis Development Uses");
    expect(content).toContain("## External Trust Signal Gate");
    expect(content).toContain("## FROST Ceremony Profile");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "context/canon/2026-05-25-phase-14-genesis-development-trust.md",
    );
    expect(content).toContain("docs/GENESIS_DEVELOPMENT_TRUST.md");
    expect(content).toContain("docs/EXOCHAIN_APP_BOUNDARY.md");
    expect(content).toContain("docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md");
    expect(content).toContain("src/genesis-trust.ts");
    expect(content).toContain("src/genesis_development_trust.rs");
    expect(content).toContain("tests/genesis-trust.test.ts");
    expect(content).toContain("tests/genesis_development_trust.rs");
    expect(content).toContain("ExoForge");
    expect(content).toContain("7-of-13 FROST");
    expect(content).toContain("External trust signaling remains disabled");
  });

  it("defines a source-backed trust signal visual language control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Trust Signal Visual Language");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## State Palette");
    expect(content).toContain("## Output Anatomy And CSS Contract");
    expect(content).toContain("## Surface And Homologation Requirements");
    expect(content).toContain("## Verified Green Gate");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain(
      "context/canon/2026-05-25-phase-15-outward-trust-visual-language.md",
    );
    expect(content).toContain("docs/TRUST_SIGNAL_VISUAL_LANGUAGE.md");
    expect(content).toContain(
      "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md",
    );
    expect(content).toContain("src/trust-signal.ts");
    expect(content).toContain("tests/trust-signal.test.ts");
    expect(content).toContain("tests/trust-signal-homologation.test.ts");
    expect(content).toContain("AVC");
    expect(content).toContain("THIS IS NOT YET VERIFIED");
    expect(content).toContain("Green verified treatment remains blocked");
    expect(content).toContain("machine-readable state");
  });

  it("defines a source-backed council review defaults control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_COUNCIL_REVIEW_FOR_OPEN_QUESTIONS.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe Council Review For Open Questions",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Automation-Resolvable Questions");
    expect(content).toContain("## Bob-Only Questions");
    expect(content).toContain("## Default Resolution Rules");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/LIVESAFE_AUTOMATION_READINESS.md");
    expect(content).toContain("docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md");
    expect(content).toContain("docs/context/LIVESAFE_ESCALATIONS_FOR_BOB.md");
    expect(content).toContain("docs/context/LIVESAFE_CONTEXT_SEED.md");
    expect(content).toContain("docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md");
    expect(content).toContain("source-backed defaults");
    expect(content).toContain("repo truth");
    expect(content).toContain("Public brand commitment");
    expect(content).toContain("Stripe product and price identifiers");
    expect(content).toContain("EXOCHAIN core modification");
  });

  it("marks every required LiveSafe control document as created in automation readiness", () => {
    const relativePath = "docs/LIVESAFE_AUTOMATION_READINESS.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "- `docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md` - created",
    );
  });

  it("keeps the implementation slice map aligned with completed trust work and a real next queue item", () => {
    const relativePath = "docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md";
    const content = readDoc(relativePath);

    expect(content).toContain("# LiveSafe Implementation Slice Map");
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Completed Slices");
    expect(content).toContain(
      "LiveSafe adjacent overflow and dependency remediation (2026-08-28)",
    );
    expect(content).toContain("Genesis trust contract");
    expect(content).toContain("tests/genesis-trust.test.ts");
    expect(content).toContain("EXOCHAIN boundary evaluator contract");
    expect(content).toContain("tests/exochain-boundary.test.ts");
    expect(content).toContain("IP boundary evaluator contract");
    expect(content).toContain("tests/ip-boundary.test.ts");
    expect(content).toContain("Trust-signal homologation contract");
    expect(content).toContain("tests/trust-signal-homologation.test.ts");
    expect(content).toContain("AI help usage summary status API contract");
    expect(content).toContain("tests/ai-help-usage-summary-status.test.ts");
    expect(content).toContain("AI help usage-summary typed-query contract");
    expect(content).toContain("tests/ai-help-usage-summary-query.test.ts");
    expect(content).toContain("AI help session transcript status API contract");
    expect(content).toContain("tests/ai-help-session-transcript-status.test.ts");
    expect(content).toContain("AI help unanswered-topic status API contract");
    expect(content).toContain("tests/ai-help-unanswered-topic-status.test.ts");
    expect(content).toContain("AI help unanswered-topic typed-query contract");
    expect(content).toContain("tests/ai-help-unanswered-topic-query.test.ts");
    expect(content).toContain("Feedback board read-model contract");
    expect(content).toContain("tests/feedback_board_read_model.rs");
    expect(content).toContain("Feedback board status API contract");
    expect(content).toContain("tests/feedback-board-status.test.ts");
    expect(content).toContain("Feedback-board persistence namespace contract");
    expect(content).toContain("tests/feedback-board-persistence.test.ts");
    expect(content).toContain("Feedback board typed-query contract");
    expect(content).toContain("tests/feedback-board-query.test.ts");
    expect(content).toContain("Onboarding and P.A.C.E. growth model control doc");
    expect(content).toContain(
      "docs/context/LIVESAFE_ONBOARDING_AND_PACE_GROWTH_MODEL.md",
    );
    expect(content).toContain(
      "Medical jacket and custody model control doc",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_MEDICAL_JACKET_AND_CUSTODY_MODEL.md",
    );
    expect(content).toContain("Emergency profile model control doc");
    expect(content).toContain(
      "docs/context/LIVESAFE_EMERGENCY_PROFILE_MODEL.md",
    );
    expect(content).toContain(
      "Commercial entitlements and marketplace control doc",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_COMMERCIAL_ENTITLEMENTS_AND_MARKETPLACE.md",
    );
    expect(content).toContain(
      "Human safety opportunity inception contract",
    );
    expect(content).toContain(
      "docs/context/LIVESAFE_HUMAN_SAFETY_OPPORTUNITY_MODEL.md",
    );
    expect(content).toContain("tests/human_safety_opportunity.rs");
    expect(content).toContain(
      "## Human Safety And P.A.C.E. Grant Relationship",
    );
    expect(content).toContain(
      "model does not supersede the human-safety model.",
    );
    expect(content).toContain("## Next Slice Queue");
    expect(content).not.toContain(
      "| Name | AI help unanswered-topic status API contract |",
    );
    expect(content).not.toContain(
      "Feedback board query typed-route read-only API contract pass",
    );
    expect(content).toContain(
      "| Feedback code-hints status API contract | `server/index.js`, `server/utils/feedback-code-hints-status.js`, `server/utils/status-route-contracts.js`, `docs/context/LIVESAFE_AI_HELP_FEEDBACK_AND_AGENT_SYSTEM.md`, `docs/context/LIVESAFE_AI_HELP_TYPED_ROUTE_OPERATIONS.md`, `docs/TEST_PLAN.md` | `tests/feedback-code-hints-status.test.ts`, `tests/status-route-contract.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/feedback-code-hints-status.test.ts`; `npm test -- tests/status-route-contract.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Implementation slice map rerank truth pass | `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/context-docs.test.ts` | `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Implementation slice map inventory truth pass | `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/context-docs.test.ts` | `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Implementation slice map model-doc inventory truth pass | `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/context-docs.test.ts` | `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Railway health evidence timestamp truth pass (2026-06-02T08:48:44.938Z) | `docs/REPOSITORY_MAP.md`, `docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/context-docs.test.ts` | `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client zero-valued timestamp preservation | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client identifier coercion hardening | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client optional authority-input hardening | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client missing consent-input hardening | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client audit-input hardening (2026-06-03T11:28:00Z) | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client missing consent-input hardening (2026-06-03T14:56:24Z) | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client explicit-location hardening (2026-06-03T11:42:00Z) | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan-route metadata-only EXOCHAIN payload boundary (2026-06-03T15:41:40Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-exochain-payload.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-exochain-payload.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. EXOCHAIN claim boundary hardening (2026-06-03T17:58:18Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-exochain-claim-boundary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-exochain-claim-boundary.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Deletion-audit EXOCHAIN claim boundary hardening (2026-06-03T18:16:00Z) | `server/utils/deletion-audit-metadata.js`, `server/routes/subscribers.js`, `server/routes/records.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/deletion-audit-metadata.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/deletion-audit-metadata.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Credential custody EXOCHAIN claim boundary hardening (2026-06-03T18:28:30Z) | `server/utils/credential-custody-receipt.js`, `server/routes/credentials.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/credential-custody-receipt.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/credential-custody-receipt.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Emergency-card issuance audit EXOCHAIN claim boundary hardening (2026-06-03T18:45:00Z) | `server/utils/card-issuance-audit-metadata.js`, `server/routes/card.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/card-issuance-audit-metadata.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/card-issuance-audit-metadata.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan local-audit EXOCHAIN claim boundary hardening (2026-06-03T18:56:45Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-exochain-payload.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-exochain-payload.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Audit immutability EXOCHAIN claim boundary hardening (2026-06-03T19:12:30Z) | `server/utils/audit-immutability-policy.js`, `server/routes/audit.js`, `server/routes/admin.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/audit-immutability-policy.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/audit-immutability-policy.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Audit trail response and copy redaction (2026-06-06T05:27:52Z) | `server/utils/audit-response.js`, `server/routes/audit.js`, `client/src/pages/AuditTrail.jsx`, `client/src/pages/Settings.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/audit-response-redaction.test.ts`, `tests/audit-route-redaction.test.ts`, `tests/public-exochain-copy-boundary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/audit-response-redaction.test.ts tests/audit-route-redaction.test.ts tests/public-exochain-copy-boundary.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Public EXOCHAIN copy fail-closed cleanup (2026-06-06T06:58:00Z) | `client/src/pages/Research.jsx`, `client/src/pages/ProviderAccess.jsx`, `client/src/pages/Settings.jsx`, `tests/public-exochain-copy-boundary.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/public-exochain-copy-boundary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/public-exochain-copy-boundary.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Device-management response redaction (2026-06-06T07:27:30Z) | `server/utils/device-response.js`, `server/routes/devices.js`, `client/src/pages/Settings.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/device-response-redaction.test.ts`, `tests/device-route-redaction.test.ts`, `tests/device-settings-public-handle.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/device-response-redaction.test.ts tests/device-route-redaction.test.ts tests/device-settings-public-handle.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Record-request response redaction and live route alignment (2026-06-06T14:27:00Z) | `server/routes/records.js`, `server/utils/record-request-response.js`, `client/src/pages/Records.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-request-response-redaction.test.ts`, `tests/record-request-route-redaction.test.ts`, `tests/record-request-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-request-response-redaction.test.ts tests/record-request-route-redaction.test.ts tests/record-request-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity claims response redaction (2026-06-06T14:57:00Z) | `server/routes/odentity.js`, `server/utils/odentity-claim-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-claims-response-redaction.test.ts`, `tests/odentity-claims-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-claims-response-redaction.test.ts tests/odentity-claims-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity gated-features ownership (2026-06-06T15:28:00Z) | `server/routes/odentity.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-gated-features-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity score response redaction (2026-06-06T15:58:00Z) | `server/routes/odentity.js`, `server/utils/odentity-score-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-score-response-redaction.test.ts`, `tests/odentity-score-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-score-response-redaction.test.ts tests/odentity-score-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity export VC response redaction (2026-06-06T16:27:00Z) | `server/routes/odentity.js`, `server/utils/odentity-export-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-export-response-redaction.test.ts`, `tests/odentity-export-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-export-response-redaction.test.ts tests/odentity-export-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity gated-features response redaction (2026-06-06T17:26:00Z) | `server/routes/odentity.js`, `server/utils/odentity-gated-features-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-gated-features-response-redaction.test.ts`, `tests/odentity-gated-features-response-route-redaction.test.ts`, `tests/odentity-gated-features-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-gated-features-response-redaction.test.ts tests/odentity-gated-features-response-route-redaction.test.ts tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Consent local-audit EXOCHAIN claim boundary hardening (2026-06-03T19:30:00Z) | `server/utils/consent-audit-metadata.js`, `server/routes/consent.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/consent-audit-metadata.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/consent-audit-metadata.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN production evidence and public-copy boundary (2026-06-03T21:24:50Z) | `config/exochain-production-trust.json`, `server/utils/exochain-production-trust-evidence.js`, `server/utils/trust-status.js`, `client/src`, `responder/src`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-production-trust-evidence.test.ts`, `tests/trust-status.test.ts`, `tests/public-exochain-copy-boundary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/trust-status.test.ts tests/exochain-production-trust-evidence.test.ts tests/public-exochain-copy-boundary.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Safety Circle onboarding and invitation delivery funnel (2026-06-05T04:40:47Z) | `client/src/pages/Home.jsx`, `client/src/pages/OnboardingWizard.jsx`, `client/src/pages/Pace.jsx`, `client/src/pages/Card.jsx`, `client/src/pages/Dashboard.jsx`, `client/src/pages/Login.jsx`, `client/src/pages/Register.jsx`, `client/src/pages/TrusteeAccept.jsx`, `server/routes/pace.js`, `server/routes/card.js`, `server/utils/pace-invitations.js`, `server/utils/pace-roles.js`, `server/db/schema.sql`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/livesafe-full-funnel-copy.test.ts`, `tests/pace-invitation-delivery.test.ts`, `tests/pace-role-normalization.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/livesafe-full-funnel-copy.test.ts tests/pace-invitation-delivery.test.ts tests/pace-role-normalization.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation failure redaction (2026-06-05T07:10:44Z) | `server/utils/pace-invitations.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-invitation-delivery.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-invitation-delivery.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. trustee nomination validation redaction (2026-06-05T07:57:09Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-trustee-validation.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-trustee-validation.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation resend acknowledgement redaction (2026-06-05T08:12:06Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-request-resend-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-request-resend-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation send response redaction (2026-06-05T09:28:00Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-send-response-redaction.test.ts`, `tests/pace-send-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-send-response-redaction.test.ts tests/pace-send-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation validate and decline response redaction (2026-06-05T08:26:27Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-invitation-response-redaction.test.ts`, `tests/pace-invitation-response-route.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-invitation-response-redaction.test.ts tests/pace-invitation-response-route.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. governance and recovery workflow response redaction (2026-06-05T08:44:13Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-response-redaction.test.ts`, `tests/pace-workflow-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-response-redaction.test.ts tests/pace-workflow-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. workflow initiation response redaction (2026-06-05T08:57:14Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-initiation-redaction.test.ts`, `tests/pace-workflow-initiation-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. emergency-override initiation acknowledgement redaction (2026-06-07T14:14:18Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-initiation-redaction.test.ts`, `tests/pace-workflow-initiation-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. invitation acceptance response redaction (2026-06-05T10:42:14Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-acceptance-response-redaction.test.ts`, `tests/pace-acceptance-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-acceptance-response-redaction.test.ts tests/pace-acceptance-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. recovery summary redaction (2026-06-05T09:11:08Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-workflow-response-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-workflow-response-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. VSS-status redaction (2026-06-05T09:42:00Z) | `server/routes/pace.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/pace-vss-status-redaction.test.ts`, `tests/pace-vss-status-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/pace-vss-status-redaction.test.ts tests/pace-vss-status-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan agency roster redaction (2026-06-05T11:26:36Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-agency-redaction.test.ts`, `tests/scan-agency-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber scan history and detail redaction (2026-06-06T05:57:24Z) | `server/routes/scan.js`, `client/src/pages/ScanHistory.jsx`, `client/src/pages/ScanDetail.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-history-response-redaction.test.ts`, `tests/scan-history-route-redaction.test.ts`, `tests/scan-history-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-history-response-redaction.test.ts tests/scan-history-route-redaction.test.ts tests/scan-history-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-access workflow redaction (2026-06-05T09:56:41Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-access-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan expanded-access initiation acknowledgement redaction (2026-06-07T18:44:00Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-expanded-access-redaction.test.ts`, `tests/scan-expanded-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan emergency-subset identifier redaction (2026-06-05T12:57:15Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-access-response-redaction.test.ts`, `tests/scan-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan responder emergency-subset redaction (2026-06-05T13:15:00Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-emergency-subset-response-redaction.test.ts`, `tests/scan-emergency-subset-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-emergency-subset-response-redaction.test.ts tests/scan-emergency-subset-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Scan token-access response redaction (2026-06-05T11:54:55Z) | `server/routes/scan.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/scan-access-response-redaction.test.ts`, `tests/scan-access-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Medical-record parse-error redaction (2026-06-05T07:27:00Z) | `server/routes/records.js`, `server/utils/record-extracted-data.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-extracted-data.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-extracted-data.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Medical-record response redaction (2026-06-06T11:28:00Z) | `server/routes/records.js`, `server/utils/medical-record-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/medical-record-response-redaction.test.ts`, `tests/medical-record-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/medical-record-response-redaction.test.ts tests/medical-record-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Clinical-note response redaction (2026-06-06T12:27:00Z) | `server/routes/records.js`, `server/utils/clinical-note-response.js`, `client/src/pages/Records.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/clinical-note-response-redaction.test.ts`, `tests/clinical-note-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/clinical-note-response-redaction.test.ts tests/clinical-note-route-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Medical-record deletion-acknowledgement redaction (2026-06-07T17:50:00Z) | `server/routes/records.js`, `server/utils/medical-record-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/medical-record-response-redaction.test.ts`, `tests/medical-record-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/medical-record-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Clinical-note wrapper acknowledgement redaction (2026-06-07T15:44:00Z) | `server/routes/records.js`, `server/utils/clinical-note-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/clinical-note-response-redaction.test.ts`, `tests/clinical-note-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/clinical-note-response-redaction.test.ts tests/clinical-note-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Alert response acknowledgement redaction (2026-06-07T16:20:00Z) | `server/routes/alerts.js`, `server/utils/alert-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/alerts-response-redaction.test.ts`, `tests/alerts-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| P.A.C.E. alert-history envelope redaction (2026-06-07T20:20:00Z) | `server/routes/alerts.js`, `server/utils/alert-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/alerts-response-redaction.test.ts`, `tests/alerts-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Record-request response redaction and live route alignment (2026-06-06T14:27:00Z) | `server/routes/records.js`, `server/utils/record-request-response.js`, `client/src/pages/Records.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/record-request-response-redaction.test.ts`, `tests/record-request-route-redaction.test.ts`, `tests/record-request-ui-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/record-request-response-redaction.test.ts tests/record-request-route-redaction.test.ts tests/record-request-ui-redaction.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| EXOCHAIN client identity DID hardening | `server/utils/exochain-client.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/exochain-client.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/exochain-client.test.ts`; `npm test -- tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity claim-write and revoke response redaction (2026-06-06T16:58:00Z) | `server/routes/odentity.js`, `server/utils/odentity-claim-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-claim-write-response-redaction.test.ts`, `tests/odentity-claim-write-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-claim-write-response-redaction.test.ts tests/odentity-claim-write-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity trust-event acknowledgement redaction (2026-06-06T17:56:00Z) | `server/routes/odentity.js`, `server/utils/odentity-trust-event-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-trust-event-response-redaction.test.ts`, `tests/odentity-trust-event-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-trust-event-response-redaction.test.ts tests/odentity-trust-event-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Legacy subscriber create/detail redaction (2026-06-07T00:26:00Z) | `server/routes/subscribers.js`, `tests/subscriber-management-route-hardening.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/subscriber-management-route-hardening.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/subscriber-management-route-hardening.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Admin audit response redaction (2026-06-07T03:00:00Z) | `server/routes/admin.js`, `server/utils/admin-audit-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/admin-audit-response-redaction.test.ts`, `tests/admin-audit-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/admin-audit-response-redaction.test.ts tests/admin-audit-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| 0dentity trust-event authority hardening (2026-06-06T20:26:00Z) | `server/routes/odentity.js`, `tests/odentity-trust-event-route-redaction.test.ts`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/odentity-trust-event-route-redaction.test.ts`, `tests/odentity-trust-event-response-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/odentity-trust-event-route-redaction.test.ts tests/odentity-trust-event-response-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Public agency directory redaction (2026-06-06T21:26:00Z) | `server/routes/auth.js`, `server/utils/auth-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-responder-response-redaction.test.ts`, `tests/auth-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Responder auth session redaction (2026-06-07T18:15:00Z) | `server/routes/auth.js`, `server/utils/auth-responder-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-responder-response-redaction.test.ts`, `tests/auth-responder-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Subscriber auth response redaction (2026-06-07T00:57:00Z) | `server/routes/auth.js`, `server/utils/auth-subscriber-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-subscriber-response-redaction.test.ts`, `tests/auth-subscriber-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-subscriber-response-redaction.test.ts tests/auth-subscriber-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Provider auth response redaction (2026-06-07T01:30:00Z) | `server/routes/auth.js`, `server/utils/auth-provider-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-provider-response-redaction.test.ts`, `tests/auth-provider-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Provider NPI lookup response redaction (2026-06-07T03:56:20Z) | `server/routes/auth.js`, `server/utils/auth-provider-response.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-provider-response-redaction.test.ts`, `tests/auth-provider-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Trustee auth response redaction (2026-06-07T02:28:00Z) | `server/routes/auth.js`, `server/utils/auth-trustee-response.js`, `server/utils/trustee-vss-summary.js`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/auth-trustee-response-redaction.test.ts`, `tests/auth-trustee-route-redaction.test.ts`, `tests/trustee-vss-route-redaction.test.ts`, `tests/trustee-vss-summary.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/auth-trustee-response-redaction.test.ts tests/auth-trustee-route-redaction.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Verification acknowledgement redaction (2026-06-07T03:29:00Z) | `server/routes/auth.js`, `server/routes/subscribers.js`, `server/utils/verification-response.js`, `client/src/pages/VerifyEmail.jsx`, `client/src/pages/Profile.jsx`, `docs/TEST_PLAN.md`, `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`, `docs/context/LIVESAFE_IMPLEMENTATION_SLICE_MAP.md` | `tests/verification-response-redaction.test.ts`, `tests/verification-route-redaction.test.ts`, `tests/context-docs.test.ts` | `npm test -- tests/verification-response-redaction.test.ts tests/verification-route-redaction.test.ts tests/context-docs.test.ts`; `npm run quality` |",
    );
    expect(content).toContain(
      "| Name | No active unfinished implementation slice |",
    );
    expect(content).toContain(
      "| Classification | selector state awaiting integration-map re-rank |",
    );
    expect(content).toContain(
      "The completed-slice inventory includes the 2026-08-28 adjacent overflow and dependency remediation.",
    );
    expect(content).toContain(
      "promote the next smallest source-backed executable gap before any bounded truth pass.",
    );
    expect(content).toContain(
      "next selection should confirm whether any smaller adjacent auth, authenticated write, or response boundary gap remains before any truth-pass fallback",
    );
    expect(content).toContain(
      "Record-request response redaction and live route alignment",
    );
    expect(content).toContain("Admin subscriber response redaction");
    expect(content).toContain("Admin agency dashboard payload alignment");
    expect(content).toContain(
      "Medical-record response redaction",
    );
    expect(content).toContain(
      "Clinical-note response redaction",
    );
    expect(content).toContain(
      "Admin responder response redaction",
    );
    expect(content).toContain(
      "Admin subscriber response redaction",
    );
    expect(content).toContain(
      "Subscriber scan history and detail redaction",
    );
    expect(content).toContain(
      "Admin agency response redaction",
    );
    expect(content).toContain(
      "Volatile Railway probe timestamps and live ids belong in automation closeout",
    );
    expect(content).not.toContain(
      "| Name | Feedback-board persistence namespace contract |",
    );
  });

  it("defines a source-backed consent and revocation receipts control document", () => {
    const relativePath =
      "docs/context/LIVESAFE_CONSENT_AND_REVOCATION_RECEIPTS.md";
    const content = readDoc(relativePath);

    expect(content).toContain(
      "# LiveSafe Consent And Revocation Receipts",
    );
    expect(content).toContain("## Source Basis");
    expect(content).toContain("## Ground Truth");
    expect(content).toContain("## Current Contract Coverage");
    expect(content).toContain("## EXOCHAIN Consent Boundary");
    expect(content).toContain("## Receipt Metadata Boundary");
    expect(content).toContain("## Activation And Copy Gates");
    expect(content).toContain("## Disablement And Rollback");
    expect(content).toContain("docs/EXOCHAIN_APP_BOUNDARY.md");
    expect(content).toContain(
      "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md",
    );
    expect(content).toContain("docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md");
    expect(content).toContain("src/consent_revocation_receipt.rs");
    expect(content).toContain("tests/consent_revocation_receipt.rs");
    expect(content).toContain("consent adapter is not wired");
    expect(content).toContain("must not mint, cache, or simulate");
    expect(content).toContain("commitments, references, policy ids, and hashes only");
    expect(content).toContain("verified consent or revocation proof");
  });
});
