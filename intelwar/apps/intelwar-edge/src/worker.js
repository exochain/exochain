/**
 * IntelWar edge proxy — serves the Railway SPA under .org / .press
 * without requiring additional Railway custom-domain slots.
 *
 * Browser keeps Host = intelwar.org | intelwar.press (surface lock).
 * Origin fetch uses the Railway service domain (registered + healthy).
 */

const DEFAULT_ORIGIN = "https://intelwar-net-production.up.railway.app";

const TITLE_BY_HOST = {
  "intelwar.org": "IntelWar.org — Home",
  "www.intelwar.org": "IntelWar.org — Home",
  "intelwar.press": "IntelWar.press — Spine",
  "www.intelwar.press": "IntelWar.press — Spine",
};

function titleForHost(host) {
  return TITLE_BY_HOST[String(host || "").toLowerCase()] || null;
}

export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    const originBase = String(env.ORIGIN || DEFAULT_ORIGIN).replace(/\/$/, "");
    const target = new URL(
      `${incoming.pathname}${incoming.search}`,
      `${originBase}/`,
    );

    const headers = new Headers(request.headers);
    headers.delete("host");
    headers.set("x-intelwar-edge", "1");
    headers.set("x-forwarded-host", incoming.host);
    headers.set("x-forwarded-proto", incoming.protocol.replace(":", ""));

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    const upstream = await fetch(target, init);
    const outHeaders = new Headers(upstream.headers);
    outHeaders.set("x-intelwar-edge", "proxied");

    const ctype = String(upstream.headers.get("content-type") || "");
    const wantTitle = titleForHost(incoming.hostname);
    const canRewrite =
      Boolean(wantTitle) &&
      request.method === "GET" &&
      ctype.includes("text/html") &&
      upstream.status >= 200 &&
      upstream.status < 300;

    if (canRewrite) {
      const html = await upstream.text();
      const next = html.replace(
        /<title>[\s\S]*?<\/title>/i,
        `<title>${wantTitle}</title>`,
      );
      outHeaders.delete("content-length");
      return new Response(next, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
      });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  },
};
