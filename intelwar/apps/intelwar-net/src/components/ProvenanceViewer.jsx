import { useMemo, useState } from "react";
import { buildReceiptChain, summarizeProvenance } from "../tv/provenance.js";

export default function ProvenanceViewer({ entries }) {
  const selectable = useMemo(
    () => (Array.isArray(entries) ? entries : []),
    [entries],
  );
  const [selectedId, setSelectedId] = useState(
    () => selectable[0]?.entry_id || "",
  );

  const activeId = selectable.some((e) => e.entry_id === selectedId)
    ? selectedId
    : selectable[0]?.entry_id || "";

  const selected = selectable.find((e) => e.entry_id === activeId);
  const summary = selected ? summarizeProvenance(selected) : null;
  const chain = activeId
    ? buildReceiptChain(selectable, activeId)
    : { ok: false, error: "no_selection" };

  if (!selectable.length) {
    return (
      <div className="empty-state">
        <p className="empty-title">No entries for provenance</p>
        <p className="status-line">Append on .net first, then inspect the chain here.</p>
      </div>
    );
  }

  return (
    <div className="prov-viewer">
      <label className="prov-select">
        <span>Entry</span>
        <select
          value={activeId}
          onChange={(e) => setSelectedId(e.target.value)}
        >
          {selectable.map((e) => (
            <option key={e.entry_id} value={e.entry_id}>
              {e.entry_id}: {String(e.summary || "").slice(0, 48)}
            </option>
          ))}
        </select>
      </label>

      {summary?.ok ? (
        <dl className="prov-summary">
          <div>
            <dt>Simulated</dt>
            <dd>{String(summary.simulated)}</dd>
          </div>
          <div>
            <dt>Kernel adjudicated</dt>
            <dd>{String(summary.kernel_adjudicated)}</dd>
          </div>
          <div>
            <dt>Voice</dt>
            <dd>{summary.voice_kind}</dd>
          </div>
          <div>
            <dt>Receipt</dt>
            <dd className="mono">{summary.receipt_hash || "—"}</dd>
          </div>
          <div>
            <dt>Content hash</dt>
            <dd className="mono">{summary.content_hash || "—"}</dd>
          </div>
          <div>
            <dt>DAG scope</dt>
            <dd>{summary.dag_scope || "—"}</dd>
          </div>
        </dl>
      ) : null}

      {chain.ok ? (
        <>
          <p className="status-line">
            Receipt chain depth {chain.depth}
            {chain.broken ? " · chain broken / incomplete" : " · intact walk"}
          </p>
          <ol className="prov-chain">
            {chain.chain.map((node, idx) => (
              <li key={`${node.entry_id}-${idx}`}>
                <div className="log-item-head">
                  <strong>{node.entry_id}</strong>
                  {node.simulated ? (
                    <span className="badge">Simulated</span>
                  ) : (
                    <span className="badge badge-real">Kernel</span>
                  )}
                </div>
                <div className="meta">
                  <span>{node.summary}</span>
                  <span className="mono">
                    receipt: {node.receipt_hash || "none"}
                  </span>
                  <span className="mono">
                    prev: {node.previous_receipt_hash || "genesis"}
                  </span>
                </div>
              </li>
            ))}
          </ol>
        </>
      ) : (
        <p className="status-line">Cannot build chain ({chain.error}).</p>
      )}
    </div>
  );
}
