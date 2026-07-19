import { useCallback, useEffect, useState } from "react";
import SiteFooter from "./components/SiteFooter.jsx";
import SiteNav from "./components/SiteNav.jsx";
import {
  isProductionHost,
  resolveSurface,
  surfaceHref,
  surfaceTitle,
} from "./lib/surface.js";
import AiSurface from "./surfaces/AiSurface.jsx";
import NetSurface from "./surfaces/NetSurface.jsx";
import OrgSurface from "./surfaces/OrgSurface.jsx";
import PressSurface from "./surfaces/PressSurface.jsx";
import TvSurface from "./surfaces/TvSurface.jsx";

const apiBase = (import.meta.env.VITE_LOG_API_URL || "").replace(/\/$/, "");

export default function App() {
  const [surface, setSurface] = useState(() => resolveSurface());
  const [entries, setEntries] = useState([]);
  const [consent, setConsent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const navigate = useCallback((next) => {
    if (isProductionHost(window.location.hostname)) {
      const href = surfaceHref(next);
      if (href.startsWith("http") && !href.includes(window.location.host)) {
        window.location.assign(href);
        return;
      }
    }
    setSurface(next);
    const hash = next === "net" ? "net" : next;
    if (window.location.hash.replace(/^#/, "") !== hash) {
      window.history.replaceState(null, "", `#${hash}`);
    }
    document.title = surfaceTitle(next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  useEffect(() => {
    document.title = surfaceTitle(surface);
    const onHash = () => setSurface(resolveSurface());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [surface]);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [logRes, consentRes] = await Promise.all([
        fetch(`${apiBase}/api/log`),
        fetch(`${apiBase}/api/consent`),
      ]);
      if (!logRes.ok) throw new Error(`log ${logRes.status}`);
      const log = await logRes.json();
      const c = consentRes.ok ? await consentRes.json() : null;
      setEntries(log.entries || []);
      setConsent(c);
    } catch (err) {
      setError(err instanceof Error ? err.message : "fetch_failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className={`app surface-${surface}`}>
      <SiteNav surface={surface} onNavigate={navigate} />

      <main id="main">
        {surface === "org" ? <OrgSurface onNavigate={navigate} /> : null}
        {surface === "press" ? <PressSurface onNavigate={navigate} /> : null}
        {surface === "net" ? (
          <NetSurface
            entries={entries}
            loading={loading}
            error={error}
            consent={consent}
            setConsent={setConsent}
            onAppended={refresh}
            onNavigate={navigate}
          />
        ) : null}
        {surface === "ai" ? (
          <AiSurface apiBase={apiBase} entries={entries} onNavigate={navigate} />
        ) : null}
        {surface === "tv" ? (
          <TvSurface entries={entries} onNavigate={navigate} />
        ) : null}
      </main>

      <SiteFooter onNavigate={navigate} />
    </div>
  );
}
