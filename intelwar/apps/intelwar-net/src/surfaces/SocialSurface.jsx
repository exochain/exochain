import { useMemo, useState } from "react";
import ArenaMark from "../components/ArenaMark.jsx";
import ReputationPanel from "../components/social/ReputationPanel.jsx";
import {
  activeCoalitions,
  discoverByMerit,
  dissolveCoalition,
  filterNotices,
  joinCoalition,
  meritBand,
  meritPercent,
  peerRecognitionValid,
  windDownCoalition,
} from "../social/merit.js";
import { buildSocialSeed, passportById } from "../social/social-data.js";

const TIER_LABEL = {
  exploratory: "Exploratory",
  coalition: "Coalition",
  public_contest: "Public contest",
  record: "Record",
};

const SURFACE_JUMP = {
  net: "Living Log",
  press: "Press",
  ai: "CrossCheck",
  tv: "Filmstrip",
  org: "Theatre",
};

/**
 * Operational social + reputation surface for intelwar.net.
 * Not hosted on intelwar.org (theatre entrance only).
 */
export default function SocialSurface({ onNavigate, embedded = false }) {
  const seed = useMemo(() => buildSocialSeed(), []);
  const [passports] = useState(seed.passports);
  const [coalitions, setCoalitions] = useState(seed.coalitions);
  const contributionEdges = seed.contributionEdges;
  const seedStakes = seed.stakes;
  const [viewerId, setViewerId] = useState("p-observer");
  const [noticeViewer, setNoticeViewer] = useState("self");
  const [domainFilter, setDomainFilter] = useState([]);
  const [ordinal, setOrdinal] = useState(11);

  const viewer = passportById(passports, viewerId);
  const ranked = useMemo(
    () => discoverByMerit(passports, domainFilter, 8),
    [passports, domainFilter],
  );
  const liveCoalitions = useMemo(
    () => activeCoalitions(coalitions),
    [coalitions],
  );
  const dissolved = coalitions.filter((c) => c.status === "dissolved");
  const notices = useMemo(
    () => filterNotices(seed.notices, noticeViewer),
    [seed.notices, noticeViewer],
  );

  const toggleDomain = (d) => {
    setDomainFilter((prev) =>
      prev.includes(d) ? prev.filter((x) => x !== d) : [...prev, d].sort(),
    );
  };

  const onJoin = (coalitionId) => {
    if (!viewer) return;
    setCoalitions((prev) =>
      prev.map((c) =>
        c.id === coalitionId ? joinCoalition(c, viewer.id) : c,
      ),
    );
  };

  const onWindDown = (coalitionId) => {
    setCoalitions((prev) =>
      prev.map((c) =>
        c.id === coalitionId ? windDownCoalition(c, ordinal) : c,
      ),
    );
    setOrdinal((o) => o + 1);
  };

  const onDissolve = (coalitionId) => {
    setCoalitions((prev) =>
      prev.map((c) =>
        c.id === coalitionId ? dissolveCoalition(c, ordinal) : c,
      ),
    );
    setOrdinal((o) => o + 1);
  };

  return (
    <div id="social-layer" className={embedded ? "social-embedded" : ""}>
      {!embedded ? (
      <section className="hero hero-compact hero-social">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.net · Social + Reputation</p>
          <h1 className="brand brand-sm">Merit</h1>
          <p className="headline headline-social">
            Social structure in service of rigorous intellectual combat —
            recognition and alliance without recreating the engagement trap.
          </p>
          <p className="lede">
            Merit before visibility. Coalitions over tribes. Context preserved.
            0dentity portable across surfaces. The user is not the product.
          </p>
          <p className="press-supporting">
            Demanding. Less addictive. Deliberately.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() =>
                document
                  .getElementById("social-passport")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Open 0dentity Passport
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() =>
                document
                  .getElementById("social-coalitions")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              View Coalitions
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("org")}
            >
              Theatre entrance (.org)
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>
      ) : (
        <div className="section-head social-embedded-head">
          <h2>Social layer · 0dentity</h2>
          <p className="support">
            Operational reputation, coalitions, and discovery — merit before
            visibility. Theatre entrance remains on{" "}
            <button type="button" className="inline-link" onClick={() => onNavigate("org")}>
              intelwar.org
            </button>
            .
          </p>
        </div>
      )}

      <section className="section" aria-labelledby="principles-heading">
        <div className="section-head">
          <h2 id="principles-heading">First principles</h2>
          <p className="support">
            Desired third order: rigorous work gains influence; tribal signaling
            loses status; mind-change gets cheaper when evidence warrants.
            Fourth order: shared reality under cognitive pressure.
          </p>
        </div>
        <div className="social-principles">
          {seed.principles.map((p) => (
            <article key={p.id}>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section
        className="section section-muted"
        id="social-passport"
        aria-labelledby="passport-heading"
      >
        <div className="section-head">
          <h2 id="passport-heading">0dentity Passport</h2>
          <p className="support">
            Portable merit across .org / .press / .net / .ai / .tv. Status is
            legible; social secondary signals are hard-capped.
          </p>
        </div>
        <label className="viewer-pick">
          View as
          <select
            value={viewerId}
            onChange={(e) => setViewerId(e.target.value)}
          >
            {passports.map((p) => (
              <option key={p.id} value={p.id}>
                {p.displayName} (@{p.handle}) · {meritBand(p.meritBps)}
              </option>
            ))}
          </select>
        </label>
        {viewer ? <PassportCard passport={viewer} /> : null}
        <div className="passport-rail" role="list">
          {passports.map((p) => (
            <button
              key={p.id}
              type="button"
              role="listitem"
              className={`passport-chip ${p.id === viewerId ? "is-active" : ""}`}
              onClick={() => setViewerId(p.id)}
            >
              <span className="passport-chip-band">{meritBand(p.meritBps)}</span>
              <strong>{p.displayName}</strong>
              <span>{meritPercent(p.meritBps)} merit</span>
              {!p.accountabilityBound ? (
                <span className="passport-warn">weak accountability</span>
              ) : null}
            </button>
          ))}
        </div>
        <p className="social-note">
          Illustrative: <code>signalnoise</code> has high secondary social
          scores but remains Observer-band — performers cannot buy Architect
          status.
        </p>
      </section>

      {viewer ? (
        <ReputationPanel
          passports={passports}
          viewer={viewer}
          edges={contributionEdges}
          stakes={seedStakes}
        />
      ) : null}

      <section
        className="section"
        id="social-coalitions"
        aria-labelledby="coalitions-heading"
      >
        <div className="section-head">
          <h2 id="coalitions-heading">Mission coalitions</h2>
          <p className="support">
            Form and dissolve around campaigns. Harder to become permanent
            identity fortresses. Join as current viewer.
          </p>
        </div>
        <div className="coalition-board">
          {liveCoalitions.map((c) => (
            <article key={c.id} className="coalition-card" data-status={c.status}>
              <div className="coalition-meta">
                <span className="coalition-status">{c.status}</span>
                <span className="coalition-tier">
                  {TIER_LABEL[c.defaultTier]}
                </span>
              </div>
              <h3>{c.name}</h3>
              <p className="coalition-mission">{c.mission}</p>
              <p className="coalition-campaign">Campaign · {c.campaignRef}</p>
              <ul className="coalition-members">
                {c.memberIds.map((id) => {
                  const m = passportById(passports, id);
                  return (
                    <li key={id}>
                      {m ? `${m.displayName} · ${meritBand(m.meritBps)}` : id}
                    </li>
                  );
                })}
              </ul>
              <div className="cta-row">
                <button
                  type="button"
                  className="primary"
                  disabled={!viewer || c.memberIds.includes(viewer.id)}
                  onClick={() => onJoin(c.id)}
                >
                  {viewer && c.memberIds.includes(viewer.id)
                    ? "Joined"
                    : "Join coalition"}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => onWindDown(c.id)}
                >
                  Wind down
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => onDissolve(c.id)}
                >
                  Dissolve
                </button>
              </div>
            </article>
          ))}
        </div>
        {dissolved.length ? (
          <div className="dissolved-block">
            <h3>Dissolved (not tribes)</h3>
            <ul>
              {dissolved.map((c) => (
                <li key={c.id}>
                  <strong>{c.name}</strong> — {c.mission}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      <section
        className="section section-muted"
        id="social-discovery"
        aria-labelledby="discovery-heading"
      >
        <div className="section-head">
          <h2 id="discovery-heading">Discovery without a feed</h2>
          <p className="support">
            Explicit campaign / contest / Log surfaces. Ranking by merit and
            relevance — not emotional velocity. No infinite scroll.
          </p>
        </div>
        <div className="domain-filters" role="group" aria-label="Relevance domains">
          {["org", "press", "net", "ai", "tv"].map((d) => (
            <button
              key={d}
              type="button"
              className={domainFilter.includes(d) ? "is-on" : ""}
              onClick={() => toggleDomain(d)}
            >
              .{d}
            </button>
          ))}
        </div>
        <div className="discovery-split">
          <div>
            <h3>People by merit</h3>
            <ol className="merit-rank">
              {ranked.map(({ passport: p, scoreBps }) => (
                <li key={p.id}>
                  <button type="button" onClick={() => setViewerId(p.id)}>
                    <span className="heat-score">{meritPercent(scoreBps)}</span>
                    <span>
                      <strong>
                        {p.displayName}{" "}
                        <em>@{p.handle}</em>
                      </strong>
                      <em>
                        {meritBand(p.meritBps)} · mind-changed{" "}
                        {p.mindChangedCount}×
                      </em>
                    </span>
                  </button>
                </li>
              ))}
            </ol>
          </div>
          <div>
            <h3>High-signal chronological</h3>
            <ul className="discovery-chrono">
              {seed.discovery
                .slice()
                .sort((a, b) => b.ordinal - a.ordinal)
                .map((item) => {
                  const author = passportById(passports, item.by);
                  return (
                    <li key={item.id} data-tier={item.tier}>
                      <span className="discovery-kind">{item.kind}</span>
                      <strong>{item.title}</strong>
                      <span>
                        {author?.displayName || item.by} ·{" "}
                        {TIER_LABEL[item.tier]}
                      </span>
                      <span className="discovery-domains">
                        {item.domains.map((d) => `.${d}`).join(" ")}
                      </span>
                      {item.kind === "recognition" && item.about ? (
                        <span className="discovery-peer">
                          Recognizer merit valid:{" "}
                          {peerRecognitionValid(
                            passportById(passports, item.by)?.meritBps || 0,
                          )
                            ? "yes"
                            : "no"}
                        </span>
                      ) : null}
                    </li>
                  );
                })}
            </ul>
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="tiers-heading">
        <div className="section-head">
          <h2 id="tiers-heading">Graduated visibility</h2>
          <p className="support">
            Not every interaction needs the same audience or permanence.
            Exploratory talk is not forced into public contest.
          </p>
        </div>
        <div className="tier-grid">
          {[
            [
              "exploratory",
              "High-trust draft space. Visible to self and coalition members. Not the Record.",
            ],
            [
              "coalition",
              "Mission group context. High-signal collaboration without low-context invasion.",
            ],
            [
              "public_contest",
              "Arena-visible intellectual combat under rules. May later bind to Log.",
            ],
            [
              "record",
              "Living Log bound — consent, provenance, Kernel adjudication. Endures.",
            ],
          ].map(([tier, body]) => (
            <article key={tier}>
              <h3>{TIER_LABEL[tier]}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section
        className="section section-muted"
        id="social-notices"
        aria-labelledby="notices-heading"
      >
        <div className="section-head">
          <h2 id="notices-heading">Notification philosophy</h2>
          <p className="support">
            Sparse and consequential. Public viewers only see actionable
            notices — no dopamine drip of low-context noise.
          </p>
        </div>
        <div className="theatre-mode" role="group" aria-label="Notice viewer">
          {["self", "coalition_member", "public"].map((v) => (
            <button
              key={v}
              type="button"
              className={noticeViewer === v ? "is-on" : ""}
              onClick={() => setNoticeViewer(v)}
            >
              {v.replace("_", " ")}
            </button>
          ))}
        </div>
        <ul className="notice-list">
          {notices.length === 0 ? (
            <li className="heat-empty">No notices for this viewer posture.</li>
          ) : (
            notices.map((n) => (
              <li key={n.id} data-kind={n.kind}>
                <span className="notice-kind">{n.kind}</span>
                <span>{n.summary}</span>
                <span className="notice-tier">{TIER_LABEL[n.tier]}</span>
                {n.actionable ? (
                  <span className="notice-action">actionable</span>
                ) : null}
              </li>
            ))
          )}
        </ul>
      </section>

      <section className="section section-deploy" aria-labelledby="social-deploy">
        <div className="deploy-panel">
          <h2 id="social-deploy">Enter through the intellectual system</h2>
          <p className="deploy-lede">
            Earn merit in the arena.
            <br />
            Form coalitions around missions.
            <br />
            Bind what endures to the Log.
          </p>
          <div className="deploy-actions">
            {Object.entries(SURFACE_JUMP).map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={id === "net" ? "primary" : "ghost"}
                onClick={() => onNavigate(id)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-deep">
        <details className="engine-details">
          <summary>What we explicitly reject</summary>
          <div className="engine-body">
            <ul className="reject-list">
              <li>Engagement as the primary optimization target</li>
              <li>Followers as the main status currency</li>
              <li>Algorithmic amplification of emotional reactivity</li>
              <li>Treating the social graph as the core product</li>
              <li>Monetization that requires users to be the product</li>
              <li>
                Pure anonymity without accountability <em>and</em> pure real-name
                systems that create chilling effects
              </li>
            </ul>
          </div>
        </details>
      </section>
    </div>
  );
}

function PassportCard({ passport: p }) {
  const m = p.merit;
  return (
    <article className="passport-card">
      <header>
        <div>
          <p className="passport-handle">@{p.handle}</p>
          <h3>{p.displayName}</h3>
        </div>
        <div className="passport-score">
          <span className="metrics-value">{meritPercent(p.meritBps)}</span>
          <span>{meritBand(p.meritBps)}</span>
        </div>
      </header>
      <p className="passport-stance">{p.stance}</p>
      <dl className="merit-breakdown">
        <div>
          <dt>Log references</dt>
          <dd>{meritPercent(m.logRefsBps)}</dd>
        </div>
        <div>
          <dt>Contests</dt>
          <dd>{meritPercent(m.contestBps)}</dd>
        </div>
        <div>
          <dt>Adversarial</dt>
          <dd>{meritPercent(m.adversarialBps)}</dd>
        </div>
        <div>
          <dt>Peer merit</dt>
          <dd>{meritPercent(m.peerMeritBps)}</dd>
        </div>
        <div>
          <dt>Social secondary (capped)</dt>
          <dd>{meritPercent(m.socialSecondaryBps)}</dd>
        </div>
      </dl>
      <p className="passport-meta">
        Mind-changed when warranted: <strong>{p.mindChangedCount}</strong>
        {" · "}
        Accountability bound:{" "}
        <strong>{p.accountabilityBound ? "yes" : "no"}</strong>
        {" · "}
        Surfaces: {p.surfacesActive.map((s) => `.${s}`).join(" ")}
      </p>
    </article>
  );
}
