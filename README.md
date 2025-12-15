# EXOCHAIN Fabric Platform

[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/exochain/exochain/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75-orange?logo=rust)](https://www.rust-lang.org/)
[![Build Status](https://github.com/exochain/exochain/workflows/CI/badge.svg)](https://github.com/exochain/exochain/actions)
[![Discord](https://img.shields.io/discord/1234567890?color=7289da&logo=discord&logoColor=white)](https://discord.gg/exochain)
[![Contributors](https://img.shields.io/github/contributors/exochain/exochain)](https://github.com/exochain/exochain/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/exochain/exochain?style=social)](https://github.com/exochain/exochain/stargazers)

The constitutional substrate for aligned superintelligence: EXOCHAIN enables adjudicated 0dentity, bailments, merits, and Holon agents with mathematical safety invariants. Deterministic finality, forensic audits, no PII on-ledger. Dive into our 65-page v2.1 spec PDF. Join the mission—Apache 2.0 licensed.

EXOCHAIN is a Rust-powered DAG-BFT platform for privacy-preserving identity, consented data sharing, and verifiable AI governance. Built for excellence and safety in the ASI era, it provides a trust fabric where actions are provably aligned via the CGR kernel—ensuring recursive self-improvement stays safe by design.

## Why EXOCHAIN?
In a world racing toward superintelligence, traditional infrastructure falls short. EXOCHAIN addresses this with:
- **Privacy by Physics**: No PII/PHI on the immutable ledger—only commitments and proofs.
- **Provable Alignment**: CGR kernel mathematically verifies invariants, solving the Divergence Problem for RSI.
- **Holon Agents**: Sovereign AI entities (did:exo:) operating in a fluid MCP mesh, bound by constitutional rules.
- **Forensic Evidence**: Court-admissible bundles for every interaction—human or AI.
- **Merit & Bailment Fabrics**: Verifiable contributions and time-bound data access, ideal for ethical AI training.
- **Open & Secure**: Apache 2.0 licensed, Rust secure-by-default, with BFT finality <2s.

Whether you're building regulated DAOs, safe ASI prototypes, or privacy-first apps, EXOCHAIN is your substrate. Fork us and join the mesh—we're building for humanity's future.

## Quickstart
Get a local node running in minutes:

1. **Install Rust**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. **Clone the Repo**: `git clone https://github.com/exochain/exochain.git && cd exochain`
3. **Build & Run**: `cargo build --release && cargo run --bin exo-node`
4. **Test an Event**: Use the CLI to create a sample IdentityCreated event: `cargo run --bin exo-cli -- create-identity --did did:exo:example`

For full setup, see [docs/QUICKSTART.md](docs/QUICKSTART.md). Dive deeper with our [v2.1 Specification PDF](docs/EXOCHAIN_Specification_v2.1_COMPLETE.pdf)—your guide to the architecture.

## Features
- **Ledger Core**: Merkle-DAG events with BFT finality (exo-core, exo-dag crates).
- **Identity & Governance**: Adjudicated 0dentity scoring, PACE recovery, AI-IRB integrations.
- **AI Safety**: Holon lifecycle events, CGR proofs for alignment, merit attestations.
- **Privacy Tools**: Bailments for time-bound access, off-ledger encrypted vaults.
- **Extensibility**: Pluggable modules for tokenomics (optional), MCP mesh discovery.

See the [Roadmap](#roadmap) for upcoming phases.

## Documentation
- **[Full Specification (PDF)](docs/EXOCHAIN_Specification_v2.1_COMPLETE.pdf)**: 65-page normative bible—start here.
- **[API Reference](docs/API.md)**: GraphQL/REST endpoints with OpenAPI spec.
- **[Developer Guide](docs/DEVELOPER.md)**: Tutorials for building Holons and extending the kernel.
- **[Security Overview](SECURITY.md)**: Reporting vulns and our hardening practices.
- Hosted Docs: Coming soon via mdBook at exochain.ai/docs.

## Community
We're a mission-driven community forging the future of safe ASI. Join us:
- **Discord**: [discord.gg/exochain](https://discord.gg/exochain) — chat with devs, share ideas.
- **Discussions**: [github.com/exochain/exochain/discussions](https://github.com/exochain/exochain/discussions) — Q&A, feature requests.
- **Issues**: [Report bugs or suggest features](https://github.com/exochain/exochain/issues/new/choose).
- **Twitter/X**: [@exochain_ai](https://twitter.com/exochain) — updates and announcements.
- **Reddit**: r/exochain — deeper dives into ASI safety.

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. First-timers: Start with docs fixes or small tests—your merit awaits.

## Roadmap
Phased from the spec:
- **Phase 1-2 (Core)**: Ledger and domain crates (in progress).
- **Phase 3-4 (Proofs & API)**: Inclusion proofs, GraphQL endpoints.
- **Phase 5 (Hardening)**: Audits, PACE full impl.
- **Phase 6+ (Extensions)**: MCP mesh, optional tokenomics.

Track progress in [docs/ROADMAP.md](docs/ROADMAP.md) or issues labeled "roadmap."

## License
Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments
Backed by visionaries, former Green Berets, and Gold Star Families—dedicated to excellence, safety, and service. Join us in securing humanity's future.

---

*Inspired by projects like Kubernetes and Rust—built for the ASI era.*
