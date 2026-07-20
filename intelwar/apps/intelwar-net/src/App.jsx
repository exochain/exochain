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
    // Social aliases to operational .net
    const target = next === "social" ? "net" : next;

    if (isProductionHost(window.location.hostname)) {
      const href =
        next === "social"
          ? surfaceHref("social")
          : surfaceHref(target);
      if (href.startsWith("http") && !href.includes(window.location.host)) {
        window.location.assign(href);
        return;
      }
      // Already on .net and asking for social — stay, set hash for scroll anchor
      if (
        next === "social" &&
        /^(www\.)?intelwar\.net$/i.test(window.location.hostname)
      ) {
        setSurface("net");
        if (window.location.hash.replace(/^#/, "") !== "social") {
          window.history.replaceState(null, "", "#social");
        }
        document.title = surfaceTitle("net");
        window.scrollTo({ top: 0, behavior: "smooth" });
        requestAnimationFrame(() => {
          document
            .getElementById("social-layer")
            ?.scrollIntoView({ behavior: "smooth" });
        });
        return;
      }
    }

    setSurface(target);
    const hash =
      next === "social" ? "social" : target === "net" ? "net" : target;
    if (window.location.hash.replace(/^#/, "") !== hash) {
      window.history.replaceState(null, "", `#${hash}`);
    }
    document.title = surfaceTitle(target);
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (next === "social") {
      requestAnimationFrame(() => {
        document
          .getElementById("social-layer")
          ?.scrollIntoView({ behavior: "smooth" });
      });
    }
  }, []);

  useEffect(() => {
    document.title = surfaceTitle(surface);
    const onHash = () => setSurface(resolveSurface());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [surface]);

  useEffect(() => {
    if (surface !== "net") return undefined;
    const hash = window.location.hash.replace(/^#/, "").toLowerCase();
    if (hash === "social" || hash === "merit") {
      requestAnimationFrame(() => {
        document
          .getElementById("social-layer")
          ?.scrollIntoView({ behavior: "smooth" });
      });
    }
    return undefined;
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
