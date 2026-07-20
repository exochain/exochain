import { surfaceHref } from "../lib/surface.js";

const LINKS = [
  { id: "org", label: ".org Theatre" },
  { id: "press", label: ".press Fourth Estate" },
  { id: "net", label: ".net Social + Log" },
  { id: "ai", label: ".ai Adversary" },
  { id: "tv", label: ".tv Filmstrip" },
];

export default function SiteFooter({ onNavigate }) {
  return (
    <footer className="site-footer">
      <div className="footer-grid">
        <div>
          <p className="footer-brand">IntelWar</p>
          <p className="footer-lede">
            Built under constitutional rules.{" "}
            <strong>intelwar.org</strong> is the theatre;{" "}
            <strong>intelwar.press</strong> is the protected publishing and
            contest layer. <strong>intelwar.net</strong> is the operational
            social, reputation, and Living Log layer. Instruments hang from
            that frame. Adjacent shell — enforcement lives in{" "}
            <code>intelwar-core</code>, not by proximity.
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
          <p className="footer-heading">Channel & constitution</p>
          <ul className="footer-links">
            <li>
              <a
                href="https://x.com/intelwar"
                target="_blank"
                rel="noopener noreferrer"
              >
                @intelwar on X
              </a>
            </li>
            <li>
              <button type="button" onClick={() => onNavigate("org")}>
                Review the Constitution
              </button>
            </li>
            <li>
              <span>Invariants IW-1…IW-8</span>
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
