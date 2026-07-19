const SURFACES = [
  { id: "net", label: ".net", title: "Living Log", hint: "Compounding memory" },
  { id: "ai", label: ".ai", title: "CrossCheck", hint: "Multi-intelligence verify" },
  { id: "tv", label: ".tv", title: "Provenance", hint: "Receipt chain view" },
];

export default function SiteNav({ surface, onNavigate }) {
  return (
    <header className="site-nav">
      <a
        className="nav-brand"
        href="#net"
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
          <button
            key={s.id}
            type="button"
            className={`nav-surface ${surface === s.id ? "is-active" : ""}`}
            onClick={() => onNavigate(s.id)}
            aria-current={surface === s.id ? "page" : undefined}
          >
            <span className="nav-surface-label">{s.label}</span>
            <span className="nav-surface-title">{s.title}</span>
          </button>
        ))}
      </nav>
      <a className="nav-skip" href="#main">
        Skip to content
      </a>
    </header>
  );
}

export { SURFACES };
