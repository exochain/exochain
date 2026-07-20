import { formatMicroUsd } from "../../ai/adversarial.js";

/**
 * Shared cost-meter + Log-write status strip for adversarial results.
 * Transparency, not scarcity: shows spend against the binding ceiling and
 * whether the analysis event reached the Living Log.
 */
export default function RunMeta({ result }) {
  if (!result?.ok) return null;
  const cost = result.cost;
  const logWrite = result.log_write;

  return (
    <div className="adv-run-meta">
      {cost ? (
        <p
          className={`adv-cost ${cost.hard_stopped ? "is-stopped" : cost.downgraded ? "is-downgraded" : ""}`}
        >
          Session {formatMicroUsd(cost.spent_micro_usd)} of{" "}
          {formatMicroUsd(cost.ceiling_micro_usd)} ceiling (
          {Math.floor((cost.spent_bps || 0) / 100)}%)
          {cost.downgraded
            ? " — switched to efficient tier to stay within ceiling"
            : ""}
          {cost.hard_stopped
            ? " — ceiling reached: Command Review (transcript retained, no further calls this session)"
            : ""}
        </p>
      ) : null}
      {logWrite ? (
        logWrite.ok ? (
          <p className="adv-logwrite is-ok">
            Living Log: {logWrite.event_type} appended · entry{" "}
            <code>{String(logWrite.entry_id).slice(0, 18)}…</code>
          </p>
        ) : (
          <p className="adv-logwrite is-warn">
            Living Log: not written —{" "}
            {logWrite.note || logWrite.message || logWrite.error}
          </p>
        )
      ) : null}
      {result.disclosure ? (
        <p className="adv-disclosure">{result.disclosure}</p>
      ) : null}
    </div>
  );
}
