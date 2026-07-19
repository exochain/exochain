export default function LivingLogViewer({ entries, loading, error }) {
  if (loading) {
    return (
      <div className="skeleton-stack" aria-busy="true" aria-label="Loading log">
        <div className="skeleton-row" />
        <div className="skeleton-row" />
        <div className="skeleton-row short" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="empty-state">
        <p className="empty-title">Log stream unavailable</p>
        <p className="status-line">
          {error}. Start <code>intelwar/services/log-api</code> or set{" "}
          <code>VITE_LOG_API_URL</code>.
        </p>
      </div>
    );
  }
  if (!entries?.length) {
    return (
      <div className="empty-state">
        <p className="empty-title">No entries yet</p>
        <p className="status-line">
          Grant demo consent below, then append the first observation.
        </p>
      </div>
    );
  }

  return (
    <ul className="log-list">
      {entries.map((entry) => (
        <li className="log-item" key={entry.entry_id}>
          <div className="log-item-head">
            {entry.simulated ? <span className="badge">Simulated</span> : (
              <span className="badge badge-real">Kernel</span>
            )}
            <strong>{entry.summary}</strong>
          </div>
          <div className="meta">
            <span>{entry.entry_kind}</span>
            <span className="mono">{entry.author_did}</span>
            <span>voice: {entry.voice_kind}</span>
            <span>scope: {entry.consent_scope}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}
