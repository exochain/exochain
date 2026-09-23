import { useEffect, useState } from "react";

const apiBase = (import.meta.env.VITE_LOG_API_URL || "").replace(/\/$/, "");

/**
 * Campaign Zero rail on .tv — the founding campaign, live from the Living
 * Log. Distinct from the seeded demonstration filmstrip: these rows are
 * Kernel-adjudicated entries, not scripted Scenes.
 */
export default function CampaignZeroRail({ onNavigate }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    if (!apiBase) return undefined;
    let cancelled = false;
    fetch(`${apiBase}/api/campaign-zero`)
      .then((r) => r.json())
      .then((body) => {
        if (!cancelled && body?.ok) setData(body);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  if (!data || !data.entries?.length) return null;

  return (
    <section className="section" id="campaign-zero-rail" aria-labelledby="cz-rail-heading">
      <div className="section-head">
        <h2 id="cz-rail-heading">Campaign Zero — live from the Living Log</h2>
        <p className="support">
          The founding campaign is real: {data.status.seeded} Kernel-adjudicated
          entries recording the design contest of this system. The filmstrip
          above is a demonstration; these receipts are not.
        </p>
      </div>
      <div className="cz-rail">
        {data.entries.map((e) => (
          <article key={e.entry_id} className="cz-rail-card">
            <header>
              <span className="rail-label">
                {String(e.summary).slice(0, 5)}
              </span>
              <span className="dispatch-kind">{e.voice_kind}</span>
              <span className="badge badge-real">Kernel</span>
            </header>
            <p>{String(e.summary).replace(/^CZ-\d\d · /, "")}</p>
            <code className="cz-rail-receipt">
              receipt {String(e.receipt_hash).slice(0, 14)}…
            </code>
          </article>
        ))}
      </div>
      <div className="cta-row">
        <button type="button" className="ghost" onClick={() => onNavigate("net")}>
          Full founding record on .net →
        </button>
      </div>
    </section>
  );
}
