import { campaignHeatMap, heatLabel, heatPercent } from "../../tv/filmstrip.js";

export default function CampaignMap({ strips, scenes, onOpenStrip }) {
  const rows = campaignHeatMap(strips, scenes);

  return (
    <section className="campaign-map" aria-labelledby="campaign-map-heading">
      <div className="section-head">
        <h2 id="campaign-map-heading">Campaign heat map</h2>
        <p className="support">
          Strategist overview — where intellectual energy concentrates across
          strips. Preferential discovery without blocking chronological
          navigation.
        </p>
      </div>
      <div className="campaign-map-grid" role="list">
        {rows.map((row) => (
          <button
            key={row.id}
            type="button"
            role="listitem"
            className="campaign-map-cell"
            style={{ "--heat": `${heatPercent(row.heatBps)}` }}
            onClick={() => onOpenStrip(row.id)}
          >
            <span className="campaign-map-kind">{row.kind}</span>
            <strong>{row.title}</strong>
            <span className="campaign-map-heat">
              {heatPercent(row.heatBps)} · {heatLabel(row.heatBps)}
            </span>
            <span className="campaign-map-meta">
              {row.sceneCount} scenes · {row.branchCount} branches ·{" "}
              {row.forkCount} forks
              {row.criticalCount
                ? ` · ${row.criticalCount} critical`
                : ""}
            </span>
            <span
              className="campaign-map-bar"
              aria-hidden="true"
              style={{ width: `${Math.max(8, heatPercent(row.heatBps))}%` }}
            />
          </button>
        ))}
      </div>
    </section>
  );
}
