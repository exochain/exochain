---
title: "EXOCHAIN Documentation Index"
status: active
created: 2026-03-18
updated: 2026-04-15
tags: [exochain, documentation, index]
---

# EXOCHAIN Documentation

**Constitutional Trust Fabric for Safe Superintelligence Governance**

122789 lines of Rust under `crates/` · 20 workspace packages · 2,975 listed tests · 40 MCP tools · 8 constitutional invariants

---

## Start here

| You are a... | Start with |
|---|---|
| **Developer** building on EXOCHAIN | [[GETTING-STARTED]] -> pick an SDK below |
| **Operator** running a node | [[GETTING-STARTED]] -> [[DEPLOYMENT]] |
| **Auditor** evaluating the fabric | [[ARCHITECTURE]] -> [[CONSTITUTIONAL-PROOFS]] -> [[THREAT-MODEL]] |
| **AI agent** acting via MCP | [MCP Integration](guides/mcp-integration.md) |
| **Contributor** sending PRs | [[GETTING-STARTED]] -> [Constitutional constraints](guides/GETTING-STARTED.md#constitutional-constraints) |

---

## Guides

- [[GETTING-STARTED]] — Build, run, contribute. The 5-minute entrypoint.
- [Rust SDK Quickstart](guides/sdk-quickstart-rust.md) — `exochain-sdk` crate, all 6 domains, end-to-end example.
- [TypeScript SDK Quickstart](guides/sdk-quickstart-typescript.md) — `@exochain/sdk`, Web Crypto Ed25519, browser + Node.
- [Python SDK Quickstart](guides/sdk-quickstart-python.md) — `exochain` package, Pydantic v2, asyncio.
- [MCP Integration Guide](guides/mcp-integration.md) — 40 tools, 6 resources, 4 prompts, Claude Code config, wire examples.
- [[ARCHON-INTEGRATION]] — ExoForge self-improvement cycle, AI-IRB council review, GitHub Issues integration.
- [[DEPLOYMENT]] — Production deployment: Docker, Nginx, SSL, systemd, PostgreSQL backup.
- [CGR Developer Guide](guides/cgr-developer-guide.md) — Constitutional Governance Runtime internals.
- [Production Deployment](guides/production-deployment.md) — Hardening and operations.

## Architecture

- [[ARCHITECTURE]] — System overview, dependency graph, data flow, design rationale.
- [[THREAT-MODEL]] — 12-threat taxonomy with mitigations, detection, and test coverage.

## Reference

- [[CRATE-REFERENCE]] — API reference for the workspace crates (types, traits, functions, invariants).

## Proofs

- [[CONSTITUTIONAL-PROOFS]] — 10 formal proofs that EXOCHAIN's constitutional properties hold.

## Project meta

- [CHANGELOG](../CHANGELOG.md) — All notable changes (Keep a Changelog format).
- [SECURITY](../SECURITY.md) — Vulnerability reporting, scope, security measures.
- [SUPPORT](../SUPPORT.md) — How to get help, report issues, contribute.
- [VERSIONING](../VERSIONING.md) — Semantic versioning, release process, constitutional constraint.

## Legal and compliance

- [Licensing Position](legal/LICENSING-POSITION.md) — Apache-2.0 rationale, dependency screening, downstream guidance.
- [National AI Policy Crosswalk](policy/NATIONAL-POLICY-FRAMEWORK-CROSSWALK-2026.md) — Mapping to March 2026 National Policy Framework.

## Audit and truth

- [Repo Truth Baseline](audit/REPO-TRUTH-BASELINE.md) — Audited metrics, build status, claim verification.
- [`tools/repo_truth.sh`](../tools/repo_truth.sh) — Regenerate truth baseline from source.

---

## By audience

### Developers

- [[GETTING-STARTED]] — Build + test the workspace.
- [Rust SDK Quickstart](guides/sdk-quickstart-rust.md) — Canonical SDK.
- [TypeScript SDK Quickstart](guides/sdk-quickstart-typescript.md) — Web + Node.
- [Python SDK Quickstart](guides/sdk-quickstart-python.md) — Async + Pydantic.
- [[CRATE-REFERENCE]] — Full API surface.
- [[ARCHITECTURE]] — System design.

### Operators

- [[GETTING-STARTED]] — Build the node binary.
- [[DEPLOYMENT]] — Docker, Nginx, systemd, PostgreSQL.
- [Production Deployment](guides/production-deployment.md) — Hardening.
- [SECURITY](../SECURITY.md) — Vulnerability reporting.

### Auditors

- [[ARCHITECTURE]] — Three-branch model + BCTS lifecycle.
- [[THREAT-MODEL]] — Twelve threats, mitigations, test coverage.
- [[CONSTITUTIONAL-PROOFS]] — Formal proofs.
- [Repo Truth Baseline](audit/REPO-TRUTH-BASELINE.md) — Verified metrics.
- [Licensing Position](legal/LICENSING-POSITION.md) — License posture.

### AI agents

- [MCP Integration Guide](guides/mcp-integration.md) — Canonical integration guide.
- Read at session start: `exochain://invariants`, `exochain://mcp-rules`, `exochain://tools`.
- Workflow templates: `governance_review`, `compliance_check`, `evidence_analysis`, `constitutional_audit`.

### Community contributors

- [[GETTING-STARTED]] -> [Contributing changes](guides/GETTING-STARTED.md#contributing-changes).
- [Constitutional constraints](guides/GETTING-STARTED.md#constitutional-constraints) — Rules every PR must obey.
- [Council process](guides/GETTING-STARTED.md#council-process-for-constitutional-changes) — When a resolution is required.
- [[AGENTS]] — AI development instructions and constitutional constraints.

---

## SDK packages

- `crates/exochain-sdk/` — Rust SDK (canonical).
- `packages/exochain-sdk/` — TypeScript SDK (`@exochain/sdk`, Node 20+).
- `packages/exochain-py/` — Python SDK (`exochain`, Python 3.11+).

## Governance

- [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] — Council Resolution defining AEGIS and SYBIL.
- [[COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN]] — 5-panel assessment driving the refactor.
- [[EXOCHAIN-REFACTOR-PLAN]] — Master plan: council -> Syntaxis -> assimilation.

## Council reports

- [[OPTIMIZED-SPEC]] — Optimized specification summary.
- [[PANEL-1-GOVERNANCE]] — Governance panel assessment.
- [[PANEL-2-LEGAL]] — Legal panel assessment.
- [[PANEL-3-ARCHITECTURE]] — Architecture panel assessment.
- [[PANEL-4-SECURITY]] — Security panel assessment.
- [[PANEL-5-OPERATIONS]] — Operations panel assessment.

## Decision Forum

- [[ASI-REPORT-DECISION-FORUM]] — ASI report on the Decision Forum application.
- [[SYSTEM-DOCUMENTATION]] — Decision Forum system documentation.
- [[USER-MANUAL]] — Decision Forum user manual.

## Demo platform

- [Demo README](../demo/README.md) — Quick start, architecture, widget system, services, WASM test suite.
- [Demo Web UI](../demo/web/) — React widget-grid configurator.
- [Gateway API](../demo/services/gateway-api/) — Rust -> WASM -> Node.js bridge with governance pipeline.
- [Infrastructure](../demo/infra/) — Docker Compose, PostgreSQL schema/seed, Dockerfile.

## ExoForge (Autonomous Implementation Engine)

- [ExoForge Repository](https://github.com/exochain/exoforge) — Archon-based autonomous coding platform.
- [[ARCHON-INTEGRATION]] — Integration guide (commands, workflows, council review, governance gate).
- [CommandBase Foundation Starter](commandbase-foundation/README.md) — portable starter package for the first ExoChain-powered operating business.

## Development

- [[AGENTS]] — AI development instructions and constitutional constraints.
- `tools/codegen/` — Crate scaffolding generator.
- `tools/syntaxis/` — Visual workflow -> Rust codegen bridge (23 node types).
- `tools/cross-impl-test/` — Cross-implementation consistency verification.

## CI/CD

- `.github/workflows/ci.yml` — 20 numbered quality gates plus required aggregator per CR-001 §8.8.
- `.github/workflows/release.yml` — Release with manual approval + provenance attestation.
- `.github/workflows/exoforge-triage.yml` — Automatic ExoForge triage for GitHub issues.
- `.github/ISSUE_TEMPLATE/` — Structured issue templates (bug report, feature request).
- `.github/CODEOWNERS` — Council panel review routing.
- `deny.toml` — Dependency license/advisory enforcement.

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
