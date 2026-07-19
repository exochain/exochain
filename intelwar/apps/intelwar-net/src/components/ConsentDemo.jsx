import { useState } from "react";

export default function ConsentDemo({
  apiBase,
  consent,
  onConsentChange,
  onAppended,
}) {
  const [summary, setSummary] = useState("");
  const [voiceKind, setVoiceKind] = useState("human");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  async function grant() {
    setBusy(true);
    setStatus("Granting Active consent for Kernel bridge…");
    try {
      const res = await fetch(`${apiBase}/api/consent/grant`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      onConsentChange(data.consent);
      setStatus("Active consent stored for Kernel bridge wire.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    setBusy(true);
    try {
      const res = await fetch(`${apiBase}/api/consent/revoke`, { method: "POST" });
      const data = await res.json();
      onConsentChange(data.consent);
      setStatus("Consent revoked.");
    } finally {
      setBusy(false);
    }
  }

  async function appendEntry(event) {
    event.preventDefault();
    setBusy(true);
    setStatus("Appending via Kernel…");
    try {
      const res = await fetch(`${apiBase}/api/log/append`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          summary: summary || "Consent-gated Kernel observation",
          voice_kind: voiceKind,
          model_id: "cursor-bootstrap",
          session_id: "intelwar-net-mvp",
          tool: "intelwar-net",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || data.error || "Append denied");
        return;
      }
      setSummary("");
      const sim = data.entry?.simulated === true;
      const durable = data.entry?.durable || "unknown";
      if (sim) {
        setStatus("ERROR: API returned simulated:true — forbidden");
        return;
      }
      setStatus(
        `Appended (Kernel). durable=${durable}; receipt=${String(data.entry?.receipt_hash || "").slice(0, 16)}…`,
      );
      onAppended();
    } finally {
      setBusy(false);
    }
  }

  const active = Boolean(consent?.active);

  return (
    <div className="panel consent-panel" data-panel="consent">
      <div className={`consent-meter ${active ? "is-active" : ""}`}>
        <span className="consent-dot" aria-hidden="true" />
        <div>
          <p className="consent-state">
            Consent {active ? "active" : "inactive"}
          </p>
          <p className="status-line">
            scope {consent?.scope || "log:append"} · Kernel bridge wire (IW-1)
          </p>
        </div>
      </div>
      <div className="actions">
        <button type="button" className="ink" disabled={busy} onClick={grant}>
          Grant consent
        </button>
        <button
          type="button"
          className="ink secondary"
          disabled={busy}
          onClick={revoke}
        >
          Revoke
        </button>
      </div>
      <form className="form-grid" onSubmit={appendEntry}>
        <label className="span-2">
          Summary
          <input
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            placeholder="What should enter the Living Log?"
            disabled={busy}
          />
        </label>
        <label>
          Voice
          <select
            value={voiceKind}
            onChange={(e) => setVoiceKind(e.target.value)}
            disabled={busy}
          >
            <option value="human">human</option>
            <option value="synthetic">synthetic (signed attestation)</option>
            <option value="system">system</option>
          </select>
        </label>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy || !active}>
            {busy ? "Working…" : "Append to Log"}
          </button>
        </div>
      </form>
      {status ? <p className="status-line status-toast">{status}</p> : null}
    </div>
  );
}
