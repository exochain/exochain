import test from "node:test";
import assert from "node:assert/strict";
import {
  hostSurface,
  isProductionHost,
  resolveSurface,
  surfaceHref,
  surfaceTitle,
} from "./surface.js";

test("surfaceTitle maps surfaces", () => {
  assert.match(surfaceTitle("org"), /Home/);
  assert.match(surfaceTitle("press"), /Spine/);
  assert.match(surfaceTitle("net"), /Living Log/);
  assert.match(surfaceTitle("ai"), /CrossCheck/);
  assert.match(surfaceTitle("tv"), /Provenance/);
});

test("hostSurface locks brand TLDs", () => {
  assert.equal(hostSurface("intelwar.org"), "org");
  assert.equal(hostSurface("www.intelwar.org"), "org");
  assert.equal(hostSurface("intelwar.press"), "press");
  assert.equal(hostSurface("www.intelwar.press"), "press");
  assert.equal(hostSurface("intelwar.ai"), "ai");
  assert.equal(hostSurface("www.intelwar.ai"), "ai");
  assert.equal(hostSurface("intelwar.tv"), "tv");
  assert.equal(hostSurface("intelwar.net"), "net");
  assert.equal(hostSurface("intelwar-net-production.up.railway.app"), null);
});

test("resolveSurface prefers host over hash on brand domains", () => {
  assert.equal(
    resolveSurface({ hostname: "intelwar.org", hash: "#net" }),
    "org",
  );
  assert.equal(
    resolveSurface({ hostname: "intelwar.press", hash: "#ai" }),
    "press",
  );
  assert.equal(
    resolveSurface({ hostname: "intelwar.ai", hash: "#net" }),
    "ai",
  );
  assert.equal(
    resolveSurface({ hostname: "localhost", hash: "#tv" }),
    "tv",
  );
  assert.equal(
    resolveSurface({ hostname: "localhost", hash: "" }),
    "org",
  );
});

test("surfaceHref uses sibling domains on production hosts", () => {
  assert.equal(
    surfaceHref("org", { hostname: "intelwar.net", protocol: "https:" }),
    "https://intelwar.org/",
  );
  assert.equal(
    surfaceHref("press", { hostname: "intelwar.org", protocol: "https:" }),
    "https://intelwar.press/",
  );
  assert.equal(
    surfaceHref("ai", { hostname: "intelwar.net", protocol: "https:" }),
    "https://intelwar.ai/",
  );
  assert.equal(
    surfaceHref("tv", { hostname: "localhost", protocol: "http:" }),
    "#tv",
  );
  assert.equal(isProductionHost("intelwar.org"), true);
  assert.equal(isProductionHost("intelwar.press"), true);
  assert.equal(isProductionHost("intelwar.net"), true);
  assert.equal(isProductionHost("up.railway.app"), false);
});
