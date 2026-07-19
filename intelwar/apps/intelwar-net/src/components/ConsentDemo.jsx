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

  async function grant() {
    setStatus("Granting demo consent…");
    const res = await fetch(`${apiBase}/api/consent/grant`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    onConsentChange(data.consent);
    setStatus("Demo consent active (not exo-consent bailment).");
  }

  async function revoke() {
    const res = await fetch(`${apiBase}/api/consent/revoke`, { method: "POST" });
    const data = await res.json();
    onConsentChange(data.consent);
    setStatus("Consent revoked.");
  }

  async function appendEntry(event) {
    event.preventDefault();
    setStatus("Appending…");
    const res = await fetch(`${apiBase}/api/log/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        summary: summary || "Consent-gated demo observation",
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
    setStatus("Appended (simulated). Constitutional path: cargo test -p intelwar-core");
    onAppended();
  }

  return (
    <div className="panel">
      <p className="status-line">
        Consent:{" "}
        <strong>{consent?.active ? "active" : "inactive"}</strong> · scope{" "}
        {consent?.scope || "log:append"}
      </p>
      <div className="actions">
        <button type="button" className="ink" onClick={grant}>
          Grant consent
        </button>
        <button type="button" className="ink secondary" onClick={revoke}>
          Revoke
        </button>
      </div>
      <form className="form-row" onSubmit={appendEntry}>
        <label>
          Summary
          <input
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            placeholder="What should enter the Living Log?"
          />
        </label>
        <label>
          Voice
          <select
            value={voiceKind}
            onChange={(e) => setVoiceKind(e.target.value)}
          >
            <option value="human">human</option>
            <option value="synthetic">synthetic (requires attestation)</option>
            <option value="system">system</option>
          </select>
        </label>
        <button type="submit" className="ink">
          Append (consent-gated)
        </button>
      </form>
      {status ? <p className="status-line">{status}</p> : null}
    </div>
  );
}
