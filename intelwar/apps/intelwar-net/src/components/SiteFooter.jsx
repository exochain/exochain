export default function SiteFooter({ onNavigate }) {
  return (
    <footer className="site-footer">
      <div className="footer-grid">
        <div>
          <p className="footer-brand">IntelWar</p>
          <p className="footer-lede">
            Constitutional arena and compounding memory for rigorous intellectual
            combat. Adjacent shell — enforcement lives in{" "}
            <code>intelwar-core</code>, not by proximity.
          </p>
        </div>
        <div>
          <p className="footer-heading">Surfaces</p>
          <ul className="footer-links">
            <li>
              <button type="button" onClick={() => onNavigate("net")}>
                .net Living Log
              </button>
            </li>
            <li>
              <button type="button" onClick={() => onNavigate("ai")}>
                .ai CrossCheck
              </button>
            </li>
            <li>
              <button type="button" onClick={() => onNavigate("tv")}>
                .tv Provenance
              </button>
            </li>
          </ul>
        </div>
        <div>
          <p className="footer-heading">Constitution</p>
          <ul className="footer-links">
            <li>
              <span>Invariants IW-1…IW-8</span>
            </li>
            <li>
              <span>Substrate EXOCHAIN v0.2.3</span>
            </li>
            <li>
              <span>trust_claim: none (this shell)</span>
            </li>
          </ul>
        </div>
      </div>
      <div className="footer-bar">
        <span>Where arguments earn their survival.</span>
        <span>© 2026 IntelWar / Exochain Foundation</span>
      </div>
    </footer>
  );
}
