/** Resolve which IntelWar surface to show from host + hash. */

const SURFACE_HOST = {
  net: "intelwar.net",
  ai: "intelwar.ai",
  tv: "intelwar.tv",
};

export function hostSurface(hostname) {
  const host = String(hostname || "").toLowerCase();
  if (host === "intelwar.ai" || host === "www.intelwar.ai" || host.endsWith(".ai")) {
    return "ai";
  }
  if (host === "intelwar.tv" || host === "www.intelwar.tv" || host.endsWith(".tv")) {
    return "tv";
  }
  if (host === "intelwar.net" || host === "www.intelwar.net" || host.endsWith(".net")) {
    // Only claim .net for our brand hosts — railway.app falls through to hash.
    if (host.includes("intelwar")) return "net";
  }
  return null;
}

export function isProductionHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  return (
    host === "intelwar.net" ||
    host === "www.intelwar.net" ||
    host === "intelwar.ai" ||
    host === "www.intelwar.ai" ||
    host === "intelwar.tv" ||
    host === "www.intelwar.tv"
  );
}

export function resolveSurface(locationLike = typeof window !== "undefined" ? window.location : null) {
  if (!locationLike) return "net";

  const locked = hostSurface(locationLike.hostname);
  if (locked) return locked;

  const hash = String(locationLike.hash || "")
    .replace(/^#/, "")
    .toLowerCase();
  if (hash === "ai" || hash.startsWith("ai/")) return "ai";
  if (hash === "tv" || hash.startsWith("tv/") || hash === "provenance") return "tv";
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

/** Prefer real sibling domains in production; hash routing on Railway/local. */
export function surfaceHref(surface, locationLike = typeof window !== "undefined" ? window.location : null) {
  if (!locationLike) return `#${surface}`;
  if (isProductionHost(locationLike.hostname)) {
    const host = SURFACE_HOST[surface] || SURFACE_HOST.net;
    const proto = locationLike.protocol === "http:" ? "http:" : "https:";
    return `${proto}//${host}/`;
  }
  return `#${surface}`;
}

export { SURFACE_HOST };
