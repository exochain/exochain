/**
 * Production static server for Railway (PM-007).
 * Binds 0.0.0.0:$PORT and serves ./dist with SPA fallback to index.html.
 */

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const port = Number(process.env.PORT || 4173);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

async function readDist(rel) {
  const file = path.normalize(path.join(dist, rel));
  if (!file.startsWith(dist)) {
    throw Object.assign(new Error("path"), { code: "ENOENT" });
  }
  return readFile(file);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    let rel = decodeURIComponent(url.pathname);
    if (rel.endsWith("/")) rel += "index.html";
    if (rel === "/") rel = "/index.html";

    let body;
    try {
      body = await readDist(rel);
    } catch {
      body = await readDist("/index.html");
      rel = "/index.html";
    }

    const ext = path.extname(rel).toLowerCase();
    res.writeHead(200, {
      "content-type": TYPES[ext] || "application/octet-stream",
      "cache-control":
        ext === ".html" ? "no-cache" : "public, max-age=31536000, immutable",
    });
    res.end(body);
  } catch (err) {
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end(err instanceof Error ? err.message : "error");
  }
});

server.listen(port, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      event: "intelwar_net_listen",
      port,
      trust_claim: "none",
      dist,
    }),
  );
});
