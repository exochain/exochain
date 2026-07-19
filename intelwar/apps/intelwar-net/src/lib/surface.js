/** Resolve which IntelWar surface to show from host + hash. */
export function resolveSurface() {
  if (typeof window === "undefined") return "net";

  const host = (window.location.hostname || "").toLowerCase();
  if (host.endsWith(".ai") || host.startsWith("ai.")) return "ai";
  if (host.endsWith(".tv") || host.startsWith("tv.")) return "tv";

  const hash = (window.location.hash || "").replace(/^#/, "").toLowerCase();
  if (hash === "ai" || hash.startsWith("ai/")) return "ai";
  if (hash === "tv" || hash.startsWith("tv/") || hash === "provenance") {
    return "tv";
  }
  if (hash === "net" || hash === "log" || hash === "") return "net";

  return "net";
}

export function surfaceTitle(surface) {
  switch (surface) {
    case "ai":
      return "IntelWar.ai — CrossCheck";
    case "tv":
      return "IntelWar.tv — Provenance";
    default:
      return "IntelWar.net — Living Log";
  }
}
