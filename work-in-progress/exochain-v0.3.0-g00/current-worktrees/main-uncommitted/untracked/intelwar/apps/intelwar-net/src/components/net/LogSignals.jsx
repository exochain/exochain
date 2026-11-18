import { useEffect, useState } from "react";

/**
 * Live 0dentity signals derived from the Kernel mirror — counts, not scores.
 * Honest label: computed_from kernel_local_mirror; never a merit claim.
 */
export default function LogSignals({ apiBase }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    if (!apiBase) return undefined;
    let cancelled = false;
    fetch(`${apiBase}/api/0dentity/summary`)
      .then((r) => r.json())
      .then((body) => {
        if (!cancelled && body?.ok) setData(body);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  if (!data) return null;
  const d = data.summary.dimensions;

  return (
    <div className="log-signals" aria-label="Log-derived signals">
      <span className="status-pill is-neutral">
        signals · {d.log_entries} entries
      </span>
      <span className="status-pill is-neutral">
        {d.human_entries} human · {d.synthetic_entries} synthetic
      </span>
      <span className="status-pill is-neutral">
        {d.analysis_events} analysis · {d.campaign_zero_founding} founding
      </span>
      <span
        className={`status-pill ${data.summary.chain_linked ? "is-kernel" : "is-neutral"}`}
      >
        receipt chain: {data.summary.chain_linked ? "linked" : "broken/empty"}
      </span>
      <span className="log-signals-note">
        counts from the Kernel mirror — signals, not scores; founding merit
        sandboxed
      </span>
    </div>
  );
}
