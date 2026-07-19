import { surfaceHref } from "../lib/surface.js";

const SURFACES = [
  { id: "net", label: ".net", title: "Living Log" },
  { id: "ai", label: ".ai", title: "CrossCheck" },
  { id: "tv", label: ".tv", title: "Provenance" },
];

export default function SiteNav({ surface, onNavigate }) {
  return (
    <header className="site-nav">
      <a
        className="nav-brand"
        href={surfaceHref("net")}
        onClick={(e) => {
          e.preventDefault();
          onNavigate("net");
        }}
      >
        <span className="nav-mark" aria-hidden="true" />
        IntelWar
      </a>
      <nav className="nav-surfaces" aria-label="IntelWar surfaces">
        {SURFACES.map((s) => (
          <a
            key={s.id}
            href={surfaceHref(s.id)}
            className={`nav-surface ${surface === s.id ? "is-active" : ""}`}
            aria-current={surface === s.id ? "page" : undefined}
            onClick={(e) => {
              e.preventDefault();
              onNavigate(s.id);
            }}
          >
            <span className="nav-surface-label">{s.label}</span>
            <span className="nav-surface-title">{s.title}</span>
          </a>
        ))}
      </nav>
      <a className="nav-skip" href="#main">
        Skip to content
      </a>
    </header>
  );
}

export { SURFACES };
