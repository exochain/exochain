import { useEffect, useState } from "react";
import { formatMicroUsd } from "../../ai/adversarial.js";
import {
  claimPassFromUrl,
  fetchJoinEconomics,
  getPassToken,
  startJoinCheckout,
} from "../../lib/join.js";

function cents(c) {
  const v = Math.max(0, Math.floor(Number(c) || 0));
  return `$${Math.floor(v / 100)}.${String(v % 100).padStart(2, "0")}`;
}

/**
 * Join — Frontier Pass ($3.68 via Stripe Checkout).
 * Transparent fee math; fail-closed when Stripe is unconfigured.
 * Charter: baseline access stays free — the pass buys session volume only.
 */
export default function JoinPanel({ apiBase }) {
  const [econ, setEcon] = useState(null);
  const [flash, setFlash] = useState(null);
  const [busy, setBusy] = useState(false);
  const [hasPass, setHasPass] = useState(Boolean(getPassToken()));

  useEffect(() => {
    let cancelled = false;
    fetchJoinEconomics(apiBase).then((e) => {
      if (!cancelled) setEcon(e);
    });
    claimPassFromUrl(apiBase).then((claim) => {
      if (cancelled || !claim) return;
      setFlash(claim.message);
      if (claim.claimed) setHasPass(true);
    });
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  async function onJoin() {
    setBusy(true);
    setFlash(null);
    const out = await startJoinCheckout(apiBase);
    if (out.ok && out.url) {
      window.location.assign(out.url);
      return;
    }
    setBusy(false);
    setFlash(
      out.error === "stripe_unconfigured"
        ? "Checkout locked server-side — set STRIPE_SECRET_KEY on log-api."
        : out.message || out.error || "Checkout failed.",
    );
  }

  const fees = econ?.fees;

  return (
    <section className="section section-muted" id="join">
      <div className="section-head">
        <h2>Join — Frontier Pass</h2>
        <p className="support">
          Reads, the Living Log, and rate-limited baseline runs stay free for
          everyone. The pass raises your daily frontier budget{" "}
          {econ?.pass?.budget_multiplier || 5}× for{" "}
          {econ?.pass?.valid_days || 30} days.
        </p>
      </div>
      <div className="join-panel">
        <div className="join-price">
          <strong>{cents(econ?.price_cents ?? 369)}</strong>
          <span>one-time · 30 days · 3·6·9</span>
        </div>
        {fees ? (
          <p className="join-econ">
            Transparent math: {cents(fees.amount_cents)} − Stripe fee{" "}
            {cents(fees.stripe_fee_cents)} → {cents(fees.net_cents)} funds
            frontier runs. Free tier stays{" "}
            {formatMicroUsd(econ?.pass?.free_daily_budget_micro_usd || 2_000_000)}
            /day; pass tier{" "}
            {formatMicroUsd(econ?.pass?.pass_daily_budget_micro_usd || 10_000_000)}
            /day. <em>{fees.basis}.</em>
          </p>
        ) : null}
        <div className="cta-row">
          <button
            type="button"
            className="primary"
            disabled={busy || hasPass || econ?.configured === false}
            onClick={onJoin}
          >
            {hasPass
              ? "Frontier Pass active on this browser"
              : econ?.configured === false
                ? "Checkout locked (Stripe unconfigured)"
                : busy
                  ? "Opening Stripe Checkout…"
                  : `Join now — ${cents(econ?.price_cents ?? 369)}`}
          </button>
        </div>
        {flash ? <p className="bind-flash">{flash}</p> : null}
        <p className="status-line">
          Payment handled by Stripe Checkout — card data never touches
          IntelWar. Pass is claimed server-side against the paid session and
          stored only in this browser.
        </p>
      </div>
    </section>
  );
}
