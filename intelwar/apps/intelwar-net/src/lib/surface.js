/** Resolve which IntelWar surface to show from host + hash. */

const SURFACE_HOST = {
  org: "intelwar.org",
  press: "intelwar.press",
  net: "intelwar.net",
  ai: "intelwar.ai",
  tv: "intelwar.tv",
};

const BRAND_HOSTS = new Set([
  "intelwar.org",
  "www.intelwar.org",
  "intelwar.press",
  "www.intelwar.press",
  "intelwar.net",
  "www.intelwar.net",
  "intelwar.ai",
  "www.intelwar.ai",
  "intelwar.tv",
  "www.intelwar.tv",
]);

export function hostSurface(hostname) {
  const host = String(hostname || "").toLowerCase();
  if (host === "intelwar.org" || host === "www.intelwar.org") return "org";
  if (host === "intelwar.press" || host === "www.intelwar.press") return "press";
  if (host === "intelwar.ai" || host === "www.intelwar.ai") return "ai";
  if (host === "intelwar.tv" || host === "www.intelwar.tv") return "tv";
  if (host === "intelwar.net" || host === "www.intelwar.net") return "net";
  return null;
}

export function isProductionHost(hostname) {
  return BRAND_HOSTS.has(String(hostname || "").toLowerCase());
}

export function resolveSurface(
  locationLike = typeof window !== "undefined" ? window.location : null,
) {
  if (!locationLike) return "org";

  const locked = hostSurface(locationLike.hostname);
  if (locked) return locked;

  const hash = String(locationLike.hash || "")
    .replace(/^#/, "")
    .toLowerCase();
  if (hash === "org" || hash === "home" || hash === "") return "org";
  if (hash === "press" || hash.startsWith("press/")) return "press";
  if (hash === "ai" || hash.startsWith("ai/")) return "ai";
  if (hash === "tv" || hash.startsWith("tv/") || hash === "provenance") {
    return "tv";
  }
  if (hash === "net" || hash === "log") return "net";
  return "org";
}

export function surfaceTitle(surface) {
  switch (surface) {
    case "org":
      return "IntelWar.org — Home";
    case "press":
      return "IntelWar.press — Spine";
    case "ai":
      return "IntelWar.ai — CrossCheck";
    case "tv":
      return "IntelWar.tv — Provenance";
    case "net":
      return "IntelWar.net — Living Log";
    default:
      return "IntelWar.org — Home";
  }
}

/** Prefer real sibling domains in production; hash routing on Railway/local. */
export function surfaceHref(
  surface,
  locationLike = typeof window !== "undefined" ? window.location : null,
) {
  if (!locationLike) return `#${surface}`;
  if (isProductionHost(locationLike.hostname)) {
    const host = SURFACE_HOST[surface] || SURFACE_HOST.org;
    const proto = locationLike.protocol === "http:" ? "http:" : "https:";
    return `${proto}//${host}/`;
  }
  return `#${surface}`;
}

export { SURFACE_HOST, BRAND_HOSTS };
