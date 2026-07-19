import { surfaceHref } from "../lib/surface.js";

const LINKS = [
  { id: "org", label: ".org Home" },
  { id: "press", label: ".press Spine" },
  { id: "net", label: ".net Living Log" },
  { id: "ai", label: ".ai CrossCheck" },
  { id: "tv", label: ".tv Provenance" },
];

export default function SiteFooter({ onNavigate }) {
  return (
    <footer className="site-footer">
      <div className="footer-grid">
        <div>
          <p className="footer-brand">IntelWar</p>
          <p className="footer-lede">
            <strong>intelwar.org</strong> is home. <strong>intelwar.press</strong>{" "}
            is spine. The instruments (.net / .ai / .tv) hang from that frame.
            Adjacent shell — enforcement lives in <code>intelwar-core</code>, not
            by proximity.
          </p>
        </div>
        <div>
          <p className="footer-heading">Surfaces</p>
          <ul className="footer-links">
            {LINKS.map((l) => (
              <li key={l.id}>
                <a
                  href={surfaceHref(l.id)}
                  onClick={(e) => {
                    e.preventDefault();
                    onNavigate(l.id);
                  }}
                >
                  {l.label}
                </a>
              </li>
            ))}
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
