export default function LivingLogViewer({ entries, loading, error }) {
  if (loading) {
    return <p className="status-line">Reading log stream…</p>;
  }
  if (error) {
    return (
      <p className="status-line">
        Log stream unavailable — {error}. Start intelwar/services/log-api or set
        VITE_LOG_API_URL.
      </p>
    );
  }
  if (!entries?.length) {
    return <p className="status-line">No entries recorded yet.</p>;
  }

  return (
    <ul className="log-list">
      {entries.map((entry) => (
        <li className="log-item" key={entry.entry_id}>
          <div>
            {entry.simulated ? <span className="badge">Simulated</span> : null}{" "}
            <strong>{entry.summary}</strong>
          </div>
          <div className="meta">
            <span>{entry.entry_kind}</span>
            <span>{entry.author_did}</span>
            <span>voice: {entry.voice_kind}</span>
            <span>scope: {entry.consent_scope}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}
