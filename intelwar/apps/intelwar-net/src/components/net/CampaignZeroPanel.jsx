import { useCallback, useEffect, useState } from "react";

/**
 * Campaign Zero — the founding campaign panel on intelwar.net.
 * Shows the planned founding entries, their Kernel-seeded status, the
 * sandboxed-merit rule, and the transition rule to external campaigns.
 */
export default function CampaignZeroPanel({ apiBase, consentActive, onSeeded }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [seeding, setSeeding] = useState(false);
  const [flash, setFlash] = useState(null);

  const refresh = useCallback(async () => {
    if (!apiBase) {
      setError("log-api unconfigured (VITE_LOG_API_URL)");
      return;
    }
    try {
      const res = await fetch(`${apiBase}/api/campaign-zero`);
      const body = await res.json();
      if (!res.ok || !body.ok) {
        setError(body.message || body.error || `HTTP ${res.status}`);
        return;
      }
      setError(null);
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : "fetch failed");
    }
  }, [apiBase]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onSeed() {
    setSeeding(true);
    setFlash(null);
    try {
      const res = await fetch(`${apiBase}/api/campaign-zero/seed`, {
        method: "POST",
      });
      const body = await res.json();
      if (!res.ok || !body.ok) {
        setFlash(
          body.error === "consent_required"
            ? "Consent required — grant Active consent in the section below, then seed."
            : `Seed failed: ${body.message || body.error}`,
        );
      } else {
        setFlash(
          body.appended.length
            ? `Appended ${body.appended.length} founding entries through the Kernel bridge.`
            : "All founding entries already seeded.",
        );
        onSeeded?.();
      }
    } catch (err) {
      setFlash(err instanceof Error ? err.message : "seed failed");
    } finally {
      setSeeding(false);
      refresh();
    }
  }

  const status = data?.status;
  const seededSummaries = new Set(
    (data?.entries || []).map((e) => String(e.summary)),
  );

  return (
    <div className="cz-panel">
      <div className="adv-attribution">
        <span
          className={`status-pill ${status?.complete ? "is-kernel" : "is-neutral"}`}
        >
          {status
            ? `Founding entries: ${status.seeded}/${status.planned} Kernel-seeded`
            : "Loading campaign…"}
        </span>
        <span className="status-pill is-neutral">merit: sandboxed</span>
      </div>

      {error ? <p className="adv-error">{error}</p> : null}
      {flash ? <p className="bind-flash">{flash}</p> : null}

      {data ? (
        <>
          <p className="support">
            The design of IntelWar is itself the founding campaign. These are
            the real architectural decisions and tensions of the build —
            recorded cleanly, not dramatized. Founding merit is sandboxed and
            non-portable until diluted by external contribution.
          </p>
          <ol className="cz-list">
            {data.planned.map((p) => {
              const seeded = seededSummaries.has(p.summary);
              return (
                <li key={p.code} className={seeded ? "is-seeded" : ""}>
                  <header>
                    <span className="rail-label">{p.code}</span>
                    <span className="dispatch-kind">{p.voice_kind}</span>
                    <span
                      className={`status-pill ${seeded ? "is-kernel" : "is-neutral"}`}
                    >
                      {seeded ? "Kernel-seeded" : "pending"}
                    </span>
                  </header>
                  <strong>{p.summary.replace(/^CZ-\d\d · /, "")}</strong>
                  <p>{p.decision}</p>
                  {p.counters?.length ? (
                    <ul>
                      {p.counters.map((c) => (
                        <li key={c}>{c}</li>
                      ))}
                    </ul>
                  ) : null}
                  {p.model_id ? (
                    <p className="cz-attest">attestation: {p.model_id}</p>
                  ) : null}
                </li>
              );
            })}
          </ol>
          <p className="cz-transition">
            <strong>Transition rule.</strong> {data.campaign.transition_rule}
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              disabled={seeding || status?.complete}
              onClick={onSeed}
            >
              {status?.complete
                ? "Founding entries seeded"
                : seeding
                  ? "Seeding via Kernel…"
                  : consentActive
                    ? "Seed founding entries → Living Log"
                    : "Seed (requires Active consent below)"}
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}
