import { surfaceHref } from "../lib/surface.js";

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
              <a href={surfaceHref("net")} onClick={(e) => { e.preventDefault(); onNavigate("net"); }}>
                .net Living Log
              </a>
            </li>
            <li>
              <a href={surfaceHref("ai")} onClick={(e) => { e.preventDefault(); onNavigate("ai"); }}>
                .ai CrossCheck
              </a>
            </li>
            <li>
              <a href={surfaceHref("tv")} onClick={(e) => { e.preventDefault(); onNavigate("tv"); }}>
                .tv Provenance
              </a>
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
