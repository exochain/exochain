import { useState } from "react";
import { getOperatorToken, setOperatorToken } from "../../lib/operator.js";

/**
 * Operator token entry for the guarded write surface. Session-only.
 * Public visitors can read everything; trust-mutating writes require this.
 */
export default function OperatorTokenField() {
  const [value, setValue] = useState(getOperatorToken());
  const [saved, setSaved] = useState(Boolean(getOperatorToken()));

  return (
    <div className="operator-token" data-panel="operator-token">
      <label className="adv-label">
        Operator token (write surface)
        <input
          type="password"
          value={value}
          autoComplete="off"
          onChange={(e) => {
            setValue(e.target.value);
            setSaved(false);
          }}
          placeholder="Paste INTELWAR_ADMIN_TOKEN to enable writes…"
        />
      </label>
      <div className="cta-row">
        <button
          type="button"
          className="ghost"
          onClick={() => {
            setOperatorToken(value);
            setSaved(Boolean(value.trim()));
          }}
        >
          {saved ? "Token set (this session)" : "Use token"}
        </button>
        {saved ? (
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setOperatorToken("");
              setValue("");
              setSaved(false);
            }}
          >
            Clear
          </button>
        ) : null}
      </div>
      <p className="status-line">
        Reads are public. Consent, appends, seeding, and signing require the
        operator token — session-only, never stored durably in this browser.
      </p>
    </div>
  );
}
