import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

/**
 * End-to-end check of the ASSETS wiring in wrangler.jsonc against the real
 * Astro build in ./dist. `run_worker_first: true` sends every path through
 * src/index.ts, which must hand anything outside /health and /api/* to the
 * assets router untouched — the failure mode this pins is a broad
 * isAppRoute() allowlist answering the dashboard with the API's JSON 404.
 *
 * vitest.global-setup.mts builds ./dist when it is absent, so this runs on a
 * fresh clone as well as in CI.
 */
describe("Astro static output via ASSETS", () => {
  it("serves the dashboard at /", async () => {
    const res = await SELF.fetch("https://aegis.test/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    // Astro scopes elements with data-astro-cid-* when the page carries an
    // inline <style>, so match the h1 tolerantly rather than a literal tag.
    expect(await res.text()).toMatch(/<h1[^>]*>Aegis<\/h1>/);
  });

  it("emits no inline style or script blocks (CSP allows 'self' only)", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    expect(html).not.toMatch(/<style[\s>]/);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/);
  });

  it("serves every hashed /_astro/ asset the page references", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    const paths = [...html.matchAll(/(?:href|src)="(\/_astro\/[^"]+)"/g)].map((m) => m[1]!);
    expect(paths.length).toBeGreaterThanOrEqual(2);
    for (const path of paths) {
      const res = await SELF.fetch(`https://aegis.test${path}`);
      expect(res.status, path).toBe(200);
    }
  });

  it("ships the dashboard script without an innerHTML path", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    const src = html.match(/<script type="module" src="([^"]+)"/)?.[1];
    expect(src).toBeTruthy();
    const js = await (await SELF.fetch(`https://aegis.test${src}`)).text();
    // Every value rendered came from /api/*; the client builds nodes with
    // textContent only, so this stays true after minification.
    expect(js).not.toContain("innerHTML");
    expect(js).toContain("textContent");
  });

  it("serves the built 404 page with a 404 status", async () => {
    const res = await SELF.fetch("https://aegis.test/does-not-exist");
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("Back to Aegis");
  });

  it("stamps security headers on static responses too", async () => {
    const res = await SELF.fetch("https://aegis.test/");
    expect(res.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });
});