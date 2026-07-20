import { useMemo, useState } from "react";
import {
  buildStandingRecord,
  canStake,
  collaboratorsForContext,
  detectEndorsementRing,
  fastSignalWeightBps,
  resolveStake,
  stakeRateAllowed,
} from "../../social/reputation.js";

const CONTEXT_OPTIONS = [
  ["general", "General collaboration"],
  ["evidence_review", "Evidence review"],
  ["adversarial_debate", "Adversarial debate"],
  ["synthesis_task", "Synthesis task"],
];

/**
 * Reputation mechanics UI — multi-dimensional standing, contribution graph,
 * stake/attestation. No global popularity leaderboard.
 */
export default function ReputationPanel({
  passports,
  viewer,
  edges,
  stakes: initialStakes,
}) {
  const [inspect, setInspect] = useState(false);
  const [context, setContext] = useState("general");
  const [stakes, setStakes] = useState(initialStakes || []);
  const [stakeTarget, setStakeTarget] = useState("");
  const [stakeKind, setStakeKind] = useState("endorse");
  const [stakeAmount, setStakeAmount] = useState(300);
  const [flash, setFlash] = useState(null);

  const records = useMemo(() => {
    return passports.map((p) =>
      buildStandingRecord(p, edges, passports),
    );
  }, [passports, edges]);

  const viewerRecord = useMemo(
    () => records.find((r) => r.passportId === viewer?.id) || null,
    [records, viewer],
  );

  const facing = viewerRecord
    ? inspect
      ? viewerRecord.inspect
      : viewerRecord.public
    : null;

  const collab = useMemo(
    () => collaboratorsForContext(records, context, 4),
    [records, context],
  );

  const rings = useMemo(() => detectEndorsementRing(stakes, 1), [stakes]);

  const onStake = () => {
    if (!viewer || !stakeTarget) return;
    const openStaked = stakes
      .filter((s) => s.stakerId === viewer.id && s.status === "open")
      .reduce((a, s) => a + s.stakeBps, 0);
    if (
      !canStake(viewerRecord?.standingBps || 0, stakeAmount, openStaked)
    ) {
      setFlash(
        "Stake rejected — need Contested+ standing, 100–1000 bps, within budget.",
      );
      return;
    }
    if (!stakeRateAllowed(stakes.filter((s) => s.stakerId === viewer.id), 20)) {
      setFlash("Rate limit — too many stakes in the current window.");
      return;
    }
    const next = {
      id: `st-live-${stakes.length + 1}`,
      stakerId: viewer.id,
      targetId: stakeTarget,
      kind: stakeKind,
      stakeBps: stakeAmount,
      status: "open",
      ordinal: 20 + stakes.length,
    };
    setStakes((prev) => [...prev, next]);
    setFlash(
      `Stake opened (${stakeKind}, ${stakeAmount} bps). Careless stakes burn standing.`,
    );
  };

  const onResolve = (stakeId, outcome) => {
    setStakes((prev) =>
      prev.map((s) => {
        if (s.id !== stakeId) return s;
        return resolveStake(s, outcome).stake;
      }),
    );
    setFlash(`Stake ${stakeId} → ${outcome}`);
  };

  if (!viewer || !facing) return null;

  return (
    <section
      className="section section-muted"
      id="reputation-mechanics"
      aria-labelledby="reputation-heading"
    >
      <div className="section-head">
        <h2 id="reputation-heading">Reputation mechanics</h2>
        <p className="support">
          Slow, multi-dimensional, hard to game. Answers: whose work improved
          the shared strategic record? Fast engagement weight:{" "}
          {fastSignalWeightBps()}. No public global leaderboard.
        </p>
      </div>

      <div className="rep-stance">
        <p>
          <strong>Provisional stance.</strong> Standing is a record of
          contribution quality — subordinate to the Living Log itself. Resist
          popularity capture and compliance capture.
        </p>
      </div>

      <div className="rep-toolbar">
        <button
          type="button"
          className={inspect ? "primary" : "ghost"}
          onClick={() => setInspect((v) => !v)}
        >
          {inspect ? "Inspecting basis (exact bps)" : "Public view (qualitative)"}
        </button>
        <label className="viewer-pick rep-context">
          Collaboration context
          <select
            value={context}
            onChange={(e) => setContext(e.target.value)}
          >
            {CONTEXT_OPTIONS.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <article className="rep-card">
        <header>
          <div>
            <p className="passport-handle">@{viewer.handle}</p>
            <h3>
              {viewer.displayName} · {facing.band}
            </h3>
            <p className="rep-trajectory">
              Trajectory · {facing.trajectory}
              {inspect && facing.exactStandingPercent != null
                ? ` · standing ${facing.exactStandingPercent}`
                : ""}
            </p>
          </div>
        </header>
        <ul className="rep-dimensions">
          {facing.dimensions.map((d) => (
            <li key={d.key}>
              <strong>{d.label}</strong>
              <span className={`rep-strength strength-${d.strength}`}>
                {d.strength}
              </span>
              {inspect && d.bps != null ? (
                <span className="rep-bps">{Math.floor(d.bps / 100)}</span>
              ) : null}
            </li>
          ))}
        </ul>
        <details className="rep-basis">
          <summary>Inspect basis (legible merit)</summary>
          <ul>
            {facing.basis.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
          <p className="social-note">{facing.note}</p>
        </details>
      </article>

      <div className="rep-split">
        <div>
          <h3>Contribution graph (inbound)</h3>
          <p className="support">
            Reputation from what is built upon and challenged — closer to
            citation with adversarial filtering than to likes.
          </p>
          <ul className="rep-edges">
            {(edges || [])
              .filter((e) => e.toId === viewer.id)
              .map((e) => {
                const from = passports.find((p) => p.id === e.fromId);
                return (
                  <li key={e.id}>
                    <span className="discovery-kind">{e.kind}</span>
                    <strong>{from?.displayName || e.fromId}</strong>
                    <span>weight {Math.floor(e.weightBps / 100)}</span>
                  </li>
                );
              })}
            {(edges || []).filter((e) => e.toId === viewer.id).length === 0 ? (
              <li className="heat-empty">No inbound edges yet</li>
            ) : null}
          </ul>
        </div>
        <div>
          <h3>Context collaborators</h3>
          <p className="support">
            Suggested nodes for this task — dimension-weighted, not a popularity
            board.
          </p>
          <ol className="merit-rank">
            {collab.map((r) => {
              const p = passports.find((x) => x.id === r.passportId);
              return (
                <li key={r.passportId}>
                  <div className="rep-collab-row">
                    <span className="heat-score">{r.public.band.slice(0, 3)}</span>
                    <span>
                      <strong>{p?.displayName || r.passportId}</strong>
                      <em>
                        primary strength ·{" "}
                        {
                          r.public.dimensions.find((d) =>
                            context === "evidence_review"
                              ? d.key === "evidence"
                              : context === "adversarial_debate"
                                ? d.key === "adversarial"
                                : context === "synthesis_task"
                                  ? d.key === "synthesis"
                                  : d.key === "judgment",
                          )?.strength
                        }
                      </em>
                    </span>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      </div>

      <div className="rep-stake">
        <h3>Stake + attestation</h3>
        <p className="support">
          Higher standing can stake when endorsing or challenging. Failed stakes
          burn the staker — cost for tribal or careless behavior.
        </p>
        <div className="rep-stake-form">
          <label>
            Target
            <select
              value={stakeTarget}
              onChange={(e) => setStakeTarget(e.target.value)}
            >
              <option value="">Select…</option>
              {passports
                .filter((p) => p.id !== viewer.id)
                .map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.displayName}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Kind
            <select
              value={stakeKind}
              onChange={(e) => setStakeKind(e.target.value)}
            >
              <option value="endorse">Endorse</option>
              <option value="challenge">Challenge</option>
            </select>
          </label>
          <label>
            Stake (bps)
            <input
              type="number"
              min={100}
              max={1000}
              step={50}
              value={stakeAmount}
              onChange={(e) => setStakeAmount(Number(e.target.value) || 0)}
            />
          </label>
          <button type="button" className="primary" onClick={onStake}>
            Open stake
          </button>
        </div>
        {flash ? <p className="bind-flash rep-flash">{flash}</p> : null}
        <ul className="rep-stake-list">
          {stakes.map((s) => {
            const staker = passports.find((p) => p.id === s.stakerId);
            const target = passports.find((p) => p.id === s.targetId);
            return (
              <li key={s.id}>
                <span className="discovery-kind">{s.kind}</span>
                <span>
                  {staker?.displayName} → {target?.displayName} · {s.stakeBps}{" "}
                  bps · {s.status}
                </span>
                {s.status === "open" ? (
                  <span className="rep-stake-actions">
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => onResolve(s.id, "resolved_valid")}
                    >
                      Resolve valid
                    </button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => onResolve(s.id, "resolved_failed")}
                    >
                      Resolve failed
                    </button>
                  </span>
                ) : null}
              </li>
            );
          })}
        </ul>
        {rings.length ? (
          <p className="passport-warn">
            Endorsement-ring heuristic flagged: {rings.join(", ")}
          </p>
        ) : (
          <p className="social-note">No endorsement rings detected in ledger.</p>
        )}
      </div>

      <div className="pillars pillars-tight">
        <article>
          <h3>Speed vs rigor</h3>
          <p>
            Core weight accrues slowly. Views and emotional velocity have weight
            zero in standing.
          </p>
        </article>
        <article>
          <h3>Forgiveness vs memory</h3>
          <p>
            Trajectory tracks updates under pressure. Mind-change is not a
            status tax when the basis is inspectable.
          </p>
        </article>
        <article>
          <h3>Anti-gaming</h3>
          <p>
            Prefer long-term citation, adversarial survival, stake cost, rate
            limits, and ring detection. Highest-status strategies must align
            with real contribution.
          </p>
        </article>
      </div>
    </section>
  );
}
