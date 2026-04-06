---
title: "EXOCHAIN Documentation Index"
status: active
created: 2026-03-18
updated: 2026-03-20
tags: [exochain, documentation, index]
---

# EXOCHAIN Documentation

**Constitutional Trust Fabric for Safe Superintelligence Governance**

~31,000 lines of Rust · 16 crates · 1,846 tests · 0 failures

---

## Project Meta

- [CHANGELOG](../CHANGELOG.md) — All notable changes (Keep a Changelog format)
- [SECURITY](../SECURITY.md) — Vulnerability reporting, scope, security measures
- [SUPPORT](../SUPPORT.md) — How to get help, report issues, contribute
- [VERSIONING](../VERSIONING.md) — Semantic versioning policy, release process, constitutional constraint

## Legal & Compliance

- [Licensing Position](legal/LICENSING-POSITION.md) — Apache-2.0 rationale, dependency screening, downstream guidance
- [National AI Policy Crosswalk](policy/NATIONAL-POLICY-FRAMEWORK-CROSSWALK-2026.md) — Mapping to March 2026 National Policy Framework

## Audit & Truth

- [Repo Truth Baseline](audit/REPO-TRUTH-BASELINE.md) — Audited metrics, build status, claim verification
- [`tools/repo_truth.sh`](../tools/repo_truth.sh) — Regenerate truth baseline from source

## Architecture

- [[ARCHITECTURE]] — System overview, dependency graph, data flow, design rationale
- [[THREAT-MODEL]] — 12-threat taxonomy with mitigations, detection, and test coverage

## Proofs

- [[CONSTITUTIONAL-PROOFS]] — 10 formal proofs that EXOCHAIN's constitutional properties hold, with informal explanations for general audiences

## Reference

- [[CRATE-REFERENCE]] — Complete API reference for all 16 crates (types, traits, functions, invariants)

## Guides

- [[GETTING-STARTED]] — Build, test, contribute, and understand the constitutional constraints
- [[ARCHON-INTEGRATION]] — ExoForge integration: self-improvement cycle, AI-IRB council review, GitHub Issues integration, API endpoints
- [[DEPLOYMENT]] — Production deployment: Docker, Nginx, SSL, systemd, PostgreSQL backup

## Demo Platform

- [Demo README](../demo/README.md) — Quick start, architecture, widget system, services, WASM test suite
- [Demo Web UI](../demo/web/) — React widget-grid configurator (12-column drag-and-drop, AI help menus)
- [Gateway API](../demo/services/gateway-api/) — Rust→WASM→Node.js bridge with governance pipeline + ExoForge feedback endpoints
- [Infrastructure](../demo/infra/) — Docker Compose, PostgreSQL schema/seed, Dockerfile

## Council Reports

- [[OPTIMIZED-SPEC]] — Optimized specification summary
- [[PANEL-1-GOVERNANCE]] — Governance panel assessment
- [[PANEL-2-LEGAL]] — Legal panel assessment
- [[PANEL-3-ARCHITECTURE]] — Architecture panel assessment
- [[PANEL-4-SECURITY]] — Security panel assessment
- [[PANEL-5-OPERATIONS]] — Operations panel assessment

## Governance

- [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] — Council Resolution defining AEGIS and SYBIL
- [[COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN]] — 5-panel assessment driving the refactor
- [[EXOCHAIN-REFACTOR-PLAN]] — Master plan: council → Syntaxis → assimilation

## Decision Forum

- [[ASI-REPORT-DECISION-FORUM]] — ASI report on the Decision Forum application
- [[SYSTEM-DOCUMENTATION]] — Decision Forum system documentation
- [[USER-MANUAL]] — Decision Forum user manual

## ExoForge (Autonomous Implementation Engine)

- [ExoForge Repository](https://github.com/exochain/exoforge) — Archon-based autonomous coding platform customized for ExoChain
- [[ARCHON-INTEGRATION]] — Integration guide (commands, workflows, council review, governance gate)

## Development

- [[AGENTS]] — AI development instructions and constitutional constraints
- `tools/codegen/` — Crate scaffolding generator
- `tools/syntaxis/` — Visual workflow → Rust codegen bridge (23 node types)
- `tools/cross-impl-test/` — Cross-implementation consistency verification

## CI/CD

- `.github/workflows/ci.yml` — 9 quality gates per CR-001 §8.8
- `.github/workflows/release.yml` — Release with manual approval + provenance attestation
- `.github/workflows/exoforge-triage.yml` — Automatic ExoForge triage for GitHub issues
- `.github/ISSUE_TEMPLATE/` — Structured issue templates (bug report, feature request)
- `.github/CODEOWNERS` — Council panel review routing
- `deny.toml` — Dependency license/advisory enforcement
