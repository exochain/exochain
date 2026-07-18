# INTELWAR_INVARIANTS_v1

**Status**: Adopted on intelwar branch (dec9ddc8)  
**Substrate**: EXOCHAIN v0.2.3 (a50a15fd)  
**Purpose**: The eight constitutional invariants that govern all IntelWar participation, Log entries, and platform behavior. These are designed to be CGR-encodable and enforceable via the Kernel + decision-forum.

## IW-1: ConsentRequired
No participation, data contribution, evidence submission, or AI/agent involvement is permitted without an explicit, revocable, provenance-tracked consent receipt (bailment contract). Consent must be evaluated by the gatekeeper before any Log append or state change.

## IW-2: ProvenanceVerifiable
Every claim, evidence fragment, rebuttal, CrossCheckResult, resolution, reputation delta, and video reference must carry a cryptographic lineage (content hash, attester DID/AVC, consent receipt link, previous entry pointer). The Living Log is append-only and receipted.

## IW-3: MultiIntelligenceTransparent
All participants (human or attested AI/agent) must disclose their nature, model/version (where applicable), and any relevant training or sponsorship lineage. AI/agent contributions must be explicitly attested via AVC or equivalent and are subject to the same consent and provenance rules as human contributions.

## IW-4: EvidenceDisciplined
Bare assertion is inadmissible. Minimum evidence standards and linkage to the Living Log are required for any claim or argument that enters the permanent record.

## IW-5: HumanOverridePriority
On high-stakes, ambiguous, values-laden, or contested resolutions, qualified human override has priority. Machine proposals and CrossCheckResults may inform but do not dispose. Human override is exercised through governed authority paths without bypassing the Kernel.

## IW-6: FailClosedEnforcement
Any violation of these invariants, missing consent, failed provenance, or unauthorized role usage results in automatic rejection of the action. There is no admin or privileged bypass of the enforcement kernel.

## IW-7: StrategicUtility
Debates, analyses, and Log contributions should demonstrably advance understanding, strategic insight, narrative resilience, or truth-seeking. Pure combat or low-utility activity is discouraged and can be deprioritized by reputation and visibility mechanisms.

## IW-8: LogIntegrity
The Living Log is the canonical, append-only, cryptographically bound record. All queries, exports, reputation calculations, and downstream uses (including .ai crosscheck and .tv provenance) must derive from verified Log state.

---

## v0.2.3 Implementation Notes (Critical Learnings)

These notes capture real behavior observed while integrating with EXOCHAIN v0.2.3 and should be treated as binding constraints until the substrate evolves.

### Gatekeeper Role Names
Governed role names in the gatekeeper are **closed**. Using custom role strings (e.g. "moderator", "strategist", "crosschecker") can violate `SeparationOfPowers`. Prefer the predefined governed roles where possible. When custom roles are required, they must be registered through proper authority channels and validated against the invariant set.

### Preferred Kernel Paths
For consent evaluation and authority checks on the hot path, prefer `AuthorityLink` and `BailmentState` constructs directly on the Kernel rather than always routing through the deeper `exo-authority` and `exo-consent` adapter layers. The adapters remain available for richer or longer-lived operations.

### QuorumLegitimate Behavior
`QuorumLegitimate` evaluates to a no-op (effectively true) when `quorum_evidence` is `None`. This is acceptable for single-actor appends and simple consent flows. Any multi-party or multi-intelligence session that requires genuine quorum must supply explicit `quorum_evidence`.

### Simulated vs Kernel Paths
All adjacent/MVP surfaces (log-api, crosscheck simulations, video hooks, etc.) **must** be explicitly labeled `simulated: true` in metadata and configuration. These paths may only be promoted to `Permitted` status after the real WASM bridge + `exo-gateway` path has demonstrated successful Kernel enforcement of the invariants.

### Future Evolution
These implementation notes may be promoted into the core invariants or moved to a separate `IMPLEMENTATION_CONSTRAINTS.md` as the platform matures. Until then, all Cursor agents and human contributors must respect them.

---

**Ratification note**: These invariants (IW-1 through IW-8) plus the v0.2.3 Implementation Notes were adopted as part of the initial bootstrap commit (dec9ddc8) on the `intelwar` branch.
