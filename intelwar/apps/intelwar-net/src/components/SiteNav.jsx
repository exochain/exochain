import { surfaceHref } from "../lib/surface.js";

const HOME = { id: "org", label: ".org", title: "Foundation" };
const SPINE = { id: "press", label: ".press", title: "Spine" };
const INSTRUMENTS = [
  { id: "net", label: ".net", title: "Log" },
  { id: "ai", label: ".ai", title: "Check" },
  { id: "tv", label: ".tv", title: "Prov" },
];

export default function SiteNav({ surface, onNavigate }) {
  return (
    <header className="site-nav">
      <a
        className="nav-brand"
        href={surfaceHref("org")}
        onClick={(e) => {
          e.preventDefault();
          onNavigate("org");
        }}
      >
        <span className="nav-mark" aria-hidden="true" />
        IntelWar
      </a>
      <nav className="nav-surfaces" aria-label="IntelWar surfaces">
        <div className="nav-group" aria-label="Home and spine">
          {[HOME, SPINE].map((s) => (
            <SurfaceLink
              key={s.id}
              surface={s}
              active={surface === s.id}
              onNavigate={onNavigate}
            />
          ))}
        </div>
        <div className="nav-divider" aria-hidden="true" />
        <div className="nav-group" aria-label="Instruments">
          {INSTRUMENTS.map((s) => (
            <SurfaceLink
              key={s.id}
              surface={s}
              active={surface === s.id}
              onNavigate={onNavigate}
            />
          ))}
        </div>
      </nav>
      <a className="nav-skip" href="#main">
        Skip to content
      </a>
    </header>
  );
}

function SurfaceLink({ surface, active, onNavigate }) {
  return (
    <a
      href={surfaceHref(surface.id)}
      className={`nav-surface ${active ? "is-active" : ""}`}
      aria-current={active ? "page" : undefined}
      onClick={(e) => {
        e.preventDefault();
        onNavigate(surface.id);
      }}
    >
      <span className="nav-surface-label">{surface.label}</span>
      <span className="nav-surface-title">{surface.title}</span>
    </a>
  );
}
