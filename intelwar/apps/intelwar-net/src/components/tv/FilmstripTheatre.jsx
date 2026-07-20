import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createForkBranch,
  emergingContestedTerritories,
  fastestGrowingForks,
  heatLabel,
  heatPercent,
  hottestScenes,
  markCriticalNode,
  mostBranchedScenes,
  orderedScenes,
  productLeadingMetrics,
  reviseTag,
  scenePhaseAt,
  truncatePath,
} from "../../tv/filmstrip.js";
import { buildSeedCampaign } from "../../tv/campaign-data.js";
import { stageAdversarialHandoff } from "../../ai/adversarial.js";
import CampaignMap from "./CampaignMap.jsx";
import SceneCutaway from "./SceneCutaway.jsx";

const MOVE_LABEL = {
  assertion: "Assertion",
  rebuttal: "Rebuttal",
  evidence: "Evidence",
  reframe: "Reframe",
  synthesis: "Synthesis",
  concession: "Concession",
  fork: "Fork",
};

const LIVE_PACK_LINES = [
  "Packaging key moment…",
  "Atomizing intellectual move…",
  "Attaching provisional tags…",
  "Emerging filmstrip updated.",
];

export default function FilmstripTheatre({ onNavigate }) {
  const seed = useMemo(() => buildSeedCampaign(), []);
  const [strips, setStrips] = useState(seed.strips);
  const [scenes, setScenes] = useState(seed.scenes);
  const [filmstripId, setFilmstripId] = useState(seed.rootId);
  const [activeId, setActiveId] = useState(seed.strips[seed.rootId].sceneIds[0]);
  const [path, setPath] = useState([
    {
      filmstripId: seed.rootId,
      sceneId: seed.strips[seed.rootId].sceneIds[0],
      title: seed.strips[seed.rootId].title,
    },
  ]);
  const [mode, setMode] = useState("async");
  const [forkOpen, setForkOpen] = useState(false);
  const [branchPicker, setBranchPicker] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [liveNote, setLiveNote] = useState("");
  const [liveVisibleCount, setLiveVisibleCount] = useState(3);
  const [engagement, setEngagement] = useState({
    depthVisits: 0,
    linearWatches: 1,
    forksOpened: 0,
  });
  const [bindFlash, setBindFlash] = useState(null);
  const railRef = useRef(null);
  const forkSalt = useRef(0);
  const rootId = seed.rootId;

  const strip = strips[filmstripId];
  const fullRail = orderedScenes(strips, scenes, filmstripId);
  const rail =
    mode === "live" && strip?.kind === "root"
      ? fullRail.slice(0, Math.min(liveVisibleCount, fullRail.length))
      : fullRail;
  const active = scenes[activeId] || rail[0];

  const selectScene = useCallback(
    (sceneId, opts = {}) => {
      const scene = scenes[sceneId];
      if (!scene) return;
      setActiveId(sceneId);
      setElapsed(0);
      if (!opts.auto) setPlaying(true);
      if (!opts.auto) {
        setEngagement((e) => ({
          ...e,
          linearWatches: e.linearWatches + 1,
        }));
      }
      setPath((prev) => {
        const next = prev.slice();
        const last = next[next.length - 1];
        if (last && last.filmstripId === scene.filmstripId) {
          next[next.length - 1] = {
            ...last,
            sceneId: scene.id,
            title: scene.title,
          };
          return next;
        }
        return next;
      });
      requestAnimationFrame(() => {
        const el = railRef.current?.querySelector(`[data-scene-id="${sceneId}"]`);
        el?.scrollIntoView({
          behavior: "smooth",
          inline: "center",
          block: "nearest",
        });
      });
    },
    [scenes],
  );

  useEffect(() => {
    if (!playing || !active) return undefined;
    const id = window.setInterval(() => {
      setElapsed((t) => {
        const next = t + 1;
        if (next >= active.durationSec) {
          const idx = rail.findIndex((s) => s.id === active.id);
          if (idx >= 0 && idx < rail.length - 1) {
            selectScene(rail[idx + 1].id, { auto: true });
            return 0;
          }
          setPlaying(false);
          return active.durationSec;
        }
        return next;
      });
    }, 1000);
    return () => window.clearInterval(id);
  }, [playing, active, rail, selectScene]);

  useEffect(() => {
    if (mode !== "live") return undefined;
    setLiveVisibleCount(3);
    let tick = 0;
    const id = window.setInterval(() => {
      tick += 1;
      setLiveNote(LIVE_PACK_LINES[tick % LIVE_PACK_LINES.length]);
      setLiveVisibleCount((n) => Math.min(fullRail.length, n + 1));
      setStrips((prev) => {
        const root = prev[rootId];
        if (!root) return prev;
        return {
          ...prev,
          [rootId]: { ...root, mode: "live" },
        };
      });
    }, 4200);
    return () => window.clearInterval(id);
  }, [mode, fullRail.length, rootId]);

  const enterStrip = useCallback(
    (childId, fromScene) => {
      const child = strips[childId];
      if (!child) return;
      const first = child.sceneIds[0];
      setFilmstripId(childId);
      setActiveId(first);
      setElapsed(0);
      setPlaying(true);
      setEngagement((e) => ({ ...e, depthVisits: e.depthVisits + 1 }));
      setPath((prev) => [
        ...prev,
        {
          filmstripId: childId,
          sceneId: first,
          title: fromScene ? `${fromScene.title} → ${child.title}` : child.title,
        },
      ]);
      setBranchPicker(null);
    },
    [strips],
  );

  const goDeeper = useCallback(
    (scene) => {
      const ids = scene.branchFilmstripIds || [];
      if (ids.length === 0) return;
      if (ids.length === 1) {
        enterStrip(ids[0], scene);
        return;
      }
      setBranchPicker({
        scene,
        options: ids.map((id) => strips[id]).filter(Boolean),
      });
    },
    [enterStrip, strips],
  );

  const goToPath = useCallback(
    (index) => {
      const frame = path[index];
      if (!frame) return;
      setPath(truncatePath(path, index));
      setFilmstripId(frame.filmstripId);
      const sid =
        frame.sceneId || strips[frame.filmstripId]?.sceneIds[0] || activeId;
      setActiveId(sid);
      setElapsed(0);
      setPlaying(true);
    },
    [path, strips, activeId],
  );

  const returnParent = useCallback(() => {
    if (path.length <= 1) return;
    goToPath(path.length - 2);
  }, [goToPath, path.length]);

  const returnRoot = useCallback(() => {
    goToPath(0);
  }, [goToPath]);

  const submitFork = useCallback(
    ({ challenge, forkMode }) => {
      if (!active) return;
      forkSalt.current += 1;
      const { strip: newStrip, scenes: newScenes, entrySceneId } =
        createForkBranch({
          parentScene: active,
          challenge,
          mode: forkMode,
          salt: String(forkSalt.current),
        });

      setStrips((prev) => ({ ...prev, [newStrip.id]: newStrip }));
      setScenes((prev) => {
        const next = { ...prev };
        for (const s of newScenes) next[s.id] = s;
        const parent = { ...next[active.id] };
        parent.branchFilmstripIds = [
          ...parent.branchFilmstripIds,
          newStrip.id,
        ];
        parent.forkCount = (parent.forkCount || 0) + 1;
        next[active.id] = parent;
        return next;
      });
      setEngagement((e) => ({ ...e, forksOpened: e.forksOpened + 1 }));
      setForkOpen(false);

      if (forkMode === "ai") {
        const claim = [
          active.core || active.title || "",
          challenge ? `Challenge: ${challenge}` : "",
        ]
          .filter(Boolean)
          .join("\n\n");
        stageAdversarialHandoff({
          claim,
          source: "tv",
          sceneId: active.id,
          mode: "stress",
        });
        onNavigate?.("ai");
        return;
      }

      setFilmstripId(newStrip.id);
      setActiveId(entrySceneId);
      setElapsed(0);
      setPlaying(true);
      setPath((prev) => [
        ...prev,
        {
          filmstripId: newStrip.id,
          sceneId: entrySceneId,
          title: newStrip.title,
        },
      ]);
    },
    [active, onNavigate],
  );

  const onCritical = useCallback(() => {
    if (!active) return;
    setScenes((prev) => ({
      ...prev,
      [active.id]: markCriticalNode(prev[active.id]),
    }));
  }, [active]);

  const onReviseTag = useCallback(
    (action, dimension) => {
      if (!active) return;
      setScenes((prev) => ({
        ...prev,
        [active.id]: reviseTag(prev[active.id], action, dimension),
      }));
    },
    [active],
  );

  const bindToLog = useCallback(() => {
    if (!active) return;
    setScenes((prev) => ({
      ...prev,
      [active.id]: { ...prev[active.id], logBound: true },
    }));
    setBindFlash(
      "Marked for Living Log bind — consent + Kernel adjudication required on .net before durable write.",
    );
    window.setTimeout(() => setBindFlash(null), 5000);
  }, [active]);

  const openStripFromMap = useCallback(
    (stripId) => {
      const target = strips[stripId];
      if (!target) return;
      const first = target.sceneIds[0];
      setFilmstripId(stripId);
      setActiveId(first);
      setElapsed(0);
      setPlaying(true);
      setPath([
        {
          filmstripId: stripId,
          sceneId: first,
          title: target.title,
        },
      ]);
      document
        .getElementById("filmstrip-theatre")
        ?.scrollIntoView({ behavior: "smooth" });
    },
    [strips],
  );

  const hot = useMemo(() => hottestScenes(scenes, 5), [scenes]);
  const branched = useMemo(() => mostBranchedScenes(scenes, 4), [scenes]);
  const growing = useMemo(() => fastestGrowingForks(scenes, 4), [scenes]);
  const territories = useMemo(
    () => emergingContestedTerritories(scenes, 6),
    [scenes],
  );
  const metrics = useMemo(
    () => productLeadingMetrics(scenes, engagement),
    [scenes, engagement],
  );
  const phase = active ? scenePhaseAt(elapsed, active.durationSec) : "open";
  const phaseText =
    phase === "open"
      ? active?.openHook
      : phase === "close"
        ? active?.closeHook
        : active?.core;

  const jump = (id) =>
    jumpToScene(
      id,
      strips,
      scenes,
      setFilmstripId,
      setActiveId,
      setPath,
      setElapsed,
      setPlaying,
    );

  return (
    <div className="filmstrip-theatre">
      <div className="theatre-toolbar">
        <div className="theatre-mode" role="group" aria-label="Playback mode">
          <button
            type="button"
            className={mode === "async" ? "is-on" : ""}
            onClick={() => setMode("async")}
          >
            Asynchronous
          </button>
          <button
            type="button"
            className={mode === "live" ? "is-on" : ""}
            onClick={() => setMode("live")}
          >
            Live feed
          </button>
        </div>
        <p className="theatre-mode-note">
          {mode === "live"
            ? `Live mode: ${liveNote || "emerging strip forming"} · limited forking under governance.`
            : "Async mode: full recursive branching, forking, heat + merit accumulation."}
        </p>
      </div>

      <nav className="filmstrip-path" aria-label="Recursion path">
        {path.map((frame, i) => (
          <button
            key={`${frame.filmstripId}-${i}`}
            type="button"
            className={`path-crumb ${i === path.length - 1 ? "is-here" : ""}`}
            onClick={() => goToPath(i)}
          >
            <span className="path-depth">D{i}</span>
            <span className="path-title">{frame.title}</span>
          </button>
        ))}
        <div className="path-actions">
          {path.length > 1 ? (
            <button type="button" className="ghost path-up" onClick={returnParent}>
              ↑ Parent
            </button>
          ) : null}
          {path.length > 1 ? (
            <button type="button" className="ghost path-up" onClick={returnRoot}>
              Root debate
            </button>
          ) : null}
        </div>
      </nav>

      <div className="theatre-stage" data-phase={phase}>
        <div className="stage-visual" aria-hidden="true">
          <div className="stage-grid" />
          <SceneCutaway
            phase={phase}
            move={active?.move}
            heatLabel={heatLabel(active?.heatBps || 0)}
          />
          <div
            className="stage-orb"
            data-heat={heatLabel(active?.heatBps || 0)}
          />
          <div className="stage-scan" />
        </div>
        <div className="stage-copy">
          <div className="stage-meta">
            <span className="dispatch-kind">
              {MOVE_LABEL[active?.move] || "Scene"}
            </span>
            <span
              className={`heat-pill heat-${heatLabel(active?.heatBps || 0).toLowerCase()}`}
            >
              Heat {heatPercent(active?.heatBps || 0)} ·{" "}
              {heatLabel(active?.heatBps || 0)}
            </span>
            {active?.criticalNode ? (
              <span className="critical-node">Critical node</span>
            ) : null}
            {active?.logBound ? (
              <span className="log-bound">Bound to Living Log</span>
            ) : (
              <span className="log-unbound">Preview · not yet bound</span>
            )}
            <span className="stage-speaker">{active?.speaker}</span>
          </div>
          <h2 className="stage-title">{active?.title}</h2>
          <p className="stage-phase-label">
            {phase === "open"
              ? "Open hook"
              : phase === "close"
                ? "Close hook"
                : "Intellectual core"}
            <span className="stage-clock">
              {elapsed}s / {active?.durationSec || 0}s · ideal 45–75s
            </span>
          </p>
          <p className="stage-body" key={`${active?.id}-${phase}`}>
            {phaseText}
          </p>
          <div className="stage-progress" aria-hidden="true">
            <div
              className="stage-progress-fill"
              style={{
                width: `${Math.min(
                  100,
                  Math.floor(
                    ((elapsed || 0) * 100) /
                      Math.max(1, active?.durationSec || 1),
                  ),
                )}%`,
              }}
            />
          </div>
          <div className="stage-actions">
            <button
              type="button"
              className="ghost"
              onClick={() => setPlaying((p) => !p)}
            >
              {playing ? "Pause" : "Play"}
            </button>
            {active?.branchFilmstripIds?.length ? (
              <button
                type="button"
                className="primary"
                onClick={() => goDeeper(active)}
              >
                Go Deeper →
              </button>
            ) : null}
            <button
              type="button"
              className="ghost"
              disabled={mode === "live"}
              onClick={() => setForkOpen(true)}
            >
              Fork this Scene
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                if (active) {
                  stageAdversarialHandoff({
                    claim: active.core || active.title || "",
                    source: "tv",
                    sceneId: active.id,
                    mode: "stress",
                  });
                }
                onNavigate("ai");
              }}
            >
              AI adversarial →
            </button>
            <button type="button" className="ghost" onClick={onCritical}>
              Mark critical (0dentity)
            </button>
            <button
              type="button"
              className="ghost"
              onClick={bindToLog}
              disabled={active?.logBound}
            >
              {active?.logBound ? "Already bound" : "Propose Log bind"}
            </button>
          </div>
          {bindFlash ? <p className="bind-flash">{bindFlash}</p> : null}
          {active ? (
            <TagCloud
              tags={active.tags}
              revisions={active.tagRevisions}
              onRevise={onReviseTag}
            />
          ) : null}
        </div>
      </div>

      <section className="filmstrip-rail-wrap" aria-label="Filmstrip">
        <div className="rail-head">
          <h3>{strip?.title}</h3>
          <p>
            {strip?.campaign} · {strip?.kind}
            {mode === "live" && strip?.kind === "root"
              ? ` · live packaging ${rail.length}/${fullRail.length}`
              : ""}{" "}
            · horizontal = time · depth = recursion · fork = sideways
          </p>
        </div>
        <div className="filmstrip-rail" ref={railRef} tabIndex={0}>
          {rail.map((scene, index) => (
            <button
              key={scene.id}
              type="button"
              data-scene-id={scene.id}
              className={`scene-card ${scene.id === active?.id ? "is-active" : ""} ${scene.criticalNode ? "is-critical" : ""}`}
              onClick={() => selectScene(scene.id)}
              style={{ "--heat": `${heatPercent(scene.heatBps)}` }}
            >
              <span className="scene-index">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="scene-heatbar" aria-hidden="true">
                <span
                  style={{
                    height: `${Math.max(8, heatPercent(scene.heatBps))}%`,
                  }}
                />
              </span>
              <span className="scene-card-body">
                <span className="scene-move">{MOVE_LABEL[scene.move]}</span>
                <strong>{scene.title}</strong>
                <span className="scene-dur">{scene.durationSec}s</span>
                {scene.branchFilmstripIds.length ? (
                  <span className="scene-branches">
                    {scene.branchFilmstripIds.length} branch
                    {scene.branchFilmstripIds.length > 1 ? "es" : ""}
                  </span>
                ) : (
                  <span className="scene-branches scene-branches-none">
                    leaf
                  </span>
                )}
                {scene.forkCount > 0 ? (
                  <span className="scene-forks">{scene.forkCount} forks</span>
                ) : null}
                {scene.criticalNode ? (
                  <span className="scene-critical">critical</span>
                ) : null}
              </span>
            </button>
          ))}
        </div>
      </section>

      {branchPicker ? (
        <BranchPicker
          picker={branchPicker}
          onClose={() => setBranchPicker(null)}
          onPick={(id) => enterStrip(id, branchPicker.scene)}
        />
      ) : null}

      {forkOpen ? (
        <ForkStudio
          scene={active}
          onClose={() => setForkOpen(false)}
          onSubmit={submitFork}
          liveLocked={mode === "live"}
        />
      ) : null}

      <CampaignMap
        strips={strips}
        scenes={scenes}
        onOpenStrip={openStripFromMap}
      />

      <section className="heat-board" id="tv-heat" aria-labelledby="heat-heading">
        <div className="section-head">
          <h2 id="heat-heading">Heat & bubbling topics</h2>
          <p className="support">
            Composite attention + rigor — not automated truth scores. Hot nodes
            invite scrutiny; cold nodes may still be correct.
          </p>
        </div>
        <div className="heat-columns heat-columns-4">
          <HeatColumn title="Hottest Scenes" items={hot} onPick={jump} />
          <HeatColumn
            title="Most branched claims"
            items={branched}
            onPick={jump}
          />
          <HeatColumn
            title="Fastest-growing forks"
            items={growing}
            onPick={jump}
          />
          <TerritoryColumn territories={territories} />
        </div>
      </section>

      <MetricsPanel metrics={metrics} engagement={engagement} />
      <MeritPanel onNavigate={onNavigate} />
    </div>
  );
}

function jumpToScene(
  sceneId,
  strips,
  scenes,
  setFilmstripId,
  setActiveId,
  setPath,
  setElapsed,
  setPlaying,
) {
  const scene = scenes[sceneId];
  if (!scene) return;
  const strip = strips[scene.filmstripId];
  if (!strip) return;
  setFilmstripId(strip.id);
  setActiveId(scene.id);
  setElapsed(0);
  setPlaying(true);
  setPath([
    {
      filmstripId: strip.id,
      sceneId: scene.id,
      title: strip.kind === "root" ? strip.title : scene.title,
    },
  ]);
}

function TagCloud({ tags, revisions, onRevise }) {
  if (!tags) return null;
  const chips = [
    ...tags.claims.map((c) => ({ k: "claim", v: c })),
    ...tags.entities.map((c) => ({ k: "entity", v: c })),
    { k: "function", v: tags.function },
    { k: "epistemic", v: tags.epistemic },
    { k: "temp", v: tags.temperature },
    ...tags.domains.map((c) => ({ k: "domain", v: c })),
  ].filter((c) => c.v);
  return (
    <div className="tag-block">
      <ul className="tag-cloud">
        {chips.map((c) => (
          <li key={`${c.k}-${c.v}`} data-kind={c.k}>
            <span>{c.k}</span> {c.v}
          </li>
        ))}
      </ul>
      <div className="tag-revise">
        <span className="tag-revise-label">High-merit tag review</span>
        <button
          type="button"
          className="ghost"
          onClick={() => onRevise("strengthen", "epistemic")}
        >
          Strengthen epistemic
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => onRevise("challenge", "epistemic")}
        >
          Challenge epistemic
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => onRevise("challenge", "claim")}
        >
          Contest claim tag
        </button>
      </div>
      {revisions?.length ? (
        <p className="tag-revision-note">
          {revisions.length} revision{revisions.length > 1 ? "s" : ""} · last:{" "}
          {revisions[revisions.length - 1].action}{" "}
          {revisions[revisions.length - 1].dimension}
        </p>
      ) : null}
    </div>
  );
}

function HeatColumn({ title, items, onPick }) {
  return (
    <div className="heat-col">
      <h3>{title}</h3>
      <ul>
        {items.length === 0 ? (
          <li className="heat-empty">No signals yet</li>
        ) : (
          items.map((s) => (
            <li key={s.id}>
              <button type="button" onClick={() => onPick(s.id)}>
                <span className="heat-score">{heatPercent(s.heatBps)}</span>
                <span>
                  <strong>{s.title}</strong>
                  <em>
                    {MOVE_LABEL[s.move]} · {heatLabel(s.heatBps)}
                  </em>
                </span>
              </button>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}

function TerritoryColumn({ territories }) {
  return (
    <div className="heat-col">
      <h3>Emerging contested territories</h3>
      <ul>
        {territories.map((t) => (
          <li key={t.domain}>
            <div className="territory-row">
              <span className="heat-score">{heatPercent(t.heatBps)}</span>
              <span>
                <strong>{t.domain}</strong>
                <em>
                  {t.contested} contested/emerging · {t.sceneIds.length} scenes
                </em>
              </span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function MetricsPanel({ metrics, engagement }) {
  return (
    <section className="metrics-panel" aria-labelledby="metrics-heading">
      <div className="section-head">
        <h2 id="metrics-heading">Product leading indicators</h2>
        <p className="support">
          Session-local demo metrics. Leading indicators from the PRD — not
          surveillance scores.
        </p>
      </div>
      <div className="metrics-grid">
        <article>
          <h3>Recursive depth</h3>
          <p className="metrics-value">
            {Math.floor(metrics.recursiveDepthBps / 100)}%
          </p>
          <p>
            {engagement.depthVisits} deep / {engagement.linearWatches} linear
            navigations
          </p>
        </article>
        <article>
          <h3>Forks opened</h3>
          <p className="metrics-value">{engagement.forksOpened}</p>
          <p>Quality judged later by sustained engagement + Log bind.</p>
        </article>
        <article>
          <h3>Heat distribution spread</h3>
          <p className="metrics-value">
            {heatPercent(metrics.heatDistributionSpreadBps)}
          </p>
          <p>Top − median heat (bps/100). Avoid pure theatrical concentration.</p>
        </article>
        <article>
          <h3>Heat ↔ merit alignment</h3>
          <p className="metrics-value">{metrics.heatMeritCorrelationCount}</p>
          <p>
            Hot scenes also carrying high merit · {metrics.highMeritSceneCount}{" "}
            high-merit scenes total
          </p>
        </article>
      </div>
    </section>
  );
}

function BranchPicker({ picker, onClose, onPick }) {
  return (
    <div className="fork-studio" role="dialog" aria-modal="true">
      <div className="fork-panel">
        <h3>Choose a branch</h3>
        <p className="fork-from">
          From <strong>{picker.scene.title}</strong> — {picker.options.length}{" "}
          nested filmstrips
        </p>
        <ul className="branch-pick-list">
          {picker.options.map((opt) => (
            <li key={opt.id}>
              <button type="button" className="primary" onClick={() => onPick(opt.id)}>
                {opt.title}
                <span>{opt.campaign}</span>
              </button>
            </li>
          ))}
        </ul>
        <button type="button" className="ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function ForkStudio({ scene, onClose, onSubmit, liveLocked }) {
  const [challenge, setChallenge] = useState("");
  const [forkMode, setForkMode] = useState("challenge");

  if (liveLocked) {
    return (
      <div className="fork-studio" role="dialog" aria-modal="true">
        <div className="fork-panel">
          <h3>Live forking limited</h3>
          <p>
            Under live governance rules, forking is constrained. Switch to
            Asynchronous for full in-situ forks.
          </p>
          <button type="button" className="primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="fork-studio"
      role="dialog"
      aria-modal="true"
      aria-labelledby="fork-title"
    >
      <div className="fork-panel">
        <h3 id="fork-title">In-situ Fork</h3>
        <p className="fork-from">
          From scene: <strong>{scene?.title}</strong>
        </p>
        <p className="support">
          Atomized into new Scenes and attached as a Fork Branch. High-quality
          forks may bind to the Living Log under consent.
        </p>
        <label className="fork-label">
          Mode
          <select
            value={forkMode}
            onChange={(e) => setForkMode(e.target.value)}
          >
            <option value="challenge">Direct challenge</option>
            <option value="ai">AI adversarial analysis</option>
            <option value="micro">Structured micro-debate</option>
            <option value="frame">New framing / evidence</option>
          </select>
        </label>
        <label className="fork-label">
          Your move
          <textarea
            rows={4}
            value={challenge}
            onChange={(e) => setChallenge(e.target.value)}
            placeholder="State the challenge, framing, or evidence request…"
          />
        </label>
        <div className="cta-row">
          <button type="button" className="ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="primary"
            onClick={() =>
              onSubmit({
                challenge:
                  challenge.trim() ||
                  "Fork opened without prose — pressure the premise.",
                forkMode: forkMode === "ai" ? "ai" : "human",
              })
            }
          >
            Open Fork Branch
          </button>
        </div>
      </div>
    </div>
  );
}

function MeritPanel({ onNavigate }) {
  return (
    <section className="merit-panel" aria-labelledby="merit-heading">
      <div className="section-head">
        <h2 id="merit-heading">0dentity Merit</h2>
        <p className="support">
          Reputation as merit — not audit theatre, not social credit. Portable
          across the IntelWar ecosystem. Resistant to simple gaming. Negative
          signals handled carefully to avoid chilling legitimate dissent.
        </p>
      </div>
      <div className="pillars pillars-tight">
        <article>
          <h3>Positive signals</h3>
          <p>
            Scenes and forks that attract sustained high-quality engagement;
            contributions that survive adversarial scrutiny; constructive deep
            exploration; recognition from high-merit peers.
          </p>
        </article>
        <article>
          <h3>Not popularity</h3>
          <p>
            Heat can concentrate on theatrical moments. Merit weights survival
            under pressure and rigor of engagement — not mere volume or
            conformity.
          </p>
        </article>
        <article>
          <h3>Legible surfacing</h3>
          <p>
            Users should understand, at a high level, why a contribution is
            surfaced. Opaque ranking is rejected as a design goal.
          </p>
        </article>
      </div>
      <div className="cta-row section-cta">
        <button type="button" className="ghost" onClick={() => onNavigate("ai")}>
          Earn merit via CrossCheck
        </button>
        <button type="button" className="ghost" onClick={() => onNavigate("net")}>
          Social + Log (.net)
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => onNavigate("press")}
        >
          Publish via Press
        </button>
      </div>
    </section>
  );
}
