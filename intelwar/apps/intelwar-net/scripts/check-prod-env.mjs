/**
 * Fail closed for production web builds (PM-007).
 * Dev builds may omit VITE_LOG_API_URL (Vite proxy).
 */

// Railway (and explicit opt-in) must never ship a shell without an API origin.
// Local `vite build` may omit the URL (dev proxy / offline artifact).
const requireApi =
  process.env.RAILWAY_ENVIRONMENT != null ||
  process.env.INTELWAR_REQUIRE_LOG_API === "1";

const api = String(process.env.VITE_LOG_API_URL || "").trim();

if (requireApi && !api) {
  console.error(
    [
      "INTELWAR fail-closed: VITE_LOG_API_URL is required for Railway/public builds.",
      "Set it to the public HTTPS origin of the log-api service (no trailing slash).",
    ].join("\n"),
  );
  process.exit(1);
}

if (api && !/^https?:\/\//i.test(api)) {
  console.error(
    `INTELWAR fail-closed: VITE_LOG_API_URL must be an absolute http(s) URL, got: ${api}`,
  );
  process.exit(1);
}

console.log(
  api
    ? `intelwar-net prod env ok (VITE_LOG_API_URL=${api})`
    : "intelwar-net local build (VITE_LOG_API_URL unset)",
);
