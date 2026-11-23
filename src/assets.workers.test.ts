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

  it("ships a search input for the history table and for the assets table", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    for (const id of ["scan-search", "asset-search"]) {
      // A toolbar search box has no visible label, so the accessible name has
      // to come from aria-label; type="search" gives the native clear button.
      expect(html).toMatch(
        new RegExp(`<input(?=[^>]*id="${id}")(?=[^>]*type="search")(?=[^>]*aria-label=)[^>]*>`),
      );
    }
  });

  it("wires both search inputs into the dashboard script", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    const src = html.match(/<script type="module" src="([^"]+)"/)?.[1];
    const js = await (await SELF.fetch(`https://aegis.test${src}`)).text();
    for (const id of ["scan-search", "asset-search"]) expect(js).toContain(id);
  });

  it("wires the findings table and the invasion confirm panel", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    // Every id the client script looks up while rendering findings or building
    // the confirm payload has to exist in the shell, signed in or not.
    for (const id of [
      "findings-section", "finding-severity", "finding-tool", "finding-search",
      "findings-table", "invasion-confirm", "invasion-targets", "invasion-tools",
      "invasion-severity", "invasion-active-note", "invasion-confirm-btn", "invasion-cancel-btn",
    ]) {
      expect(html).toContain(`id="${id}"`);
    }
    // Load-bearing copy: the operator has to know zap-full is an active attack
    // and roughly what it costs in runtime.
    expect(html).toContain(
      "Active attack scanning: zap-full sends attack payloads at every selected URL. Expect up to 60 minutes.",
    );

    const src = html.match(/<script type="module" src="([^"]+)"/)?.[1];
    expect(src).toBeTruthy();
    const js = await (await SELF.fetch(`https://aegis.test${src}`)).text();
    // Ids are referenced as selector strings, so minification cannot rename
    // them; both panels dropping out of the script would be silent at runtime.
    for (const id of ["findings-section", "invasion-confirm"]) expect(js).toContain(id);
    // The findings count comes from the findings endpoint, and the confirm
    // panel is populated from the preview endpoint.
    expect(js).toContain("/findings");
    expect(js).toContain("/invasion-preview");
  });

  it("ships the decorative recon graph on the signed-out page", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    expect(html).toMatch(
      /<svg[^>]*class="recon-graph"[^>]*aria-hidden="true"|<svg[^>]*aria-hidden="true"[^>]*class="recon-graph"/,
    );
  });

  it("renders the graph statically under reduced motion", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    const href = html.match(/<link rel="stylesheet" href="([^"]+)"/)?.[1];
    expect(href).toBeTruthy();
    const css = await (await SELF.fetch(`https://aegis.test${href}`)).text();
    // The minifier drops the space after the colon, so match it tolerantly.
    expect(css).toMatch(/@media \(prefers-reduced-motion:\s*reduce\)[\s\S]*recon-graph/);
  });

  it("ships the public pipeline, tooling and privacy strips", async () => {
    const html = await (await SELF.fetch("https://aegis.test/")).text();
    for (const id of ["landing-pipeline", "landing-tooling", "landing-privacy"]) {
      expect(html).toContain(`id="${id}"`);
    }
    // The honesty line is load-bearing: Explore and Invasion are shipped, Reporting is not.
    expect(html).toContain("Explore and Invasion are live; Reporting lands in Phase 3.");
    expect(html).toContain('href="https://github.com/projectdiscovery/nuclei"');
    expect(html).toContain('href="https://www.zaproxy.org/"');
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

  it("serves the favicon and links it from both pages", async () => {
    for (const path of ["/", "/does-not-exist"]) {
      const html = await (await SELF.fetch(`https://aegis.test${path}`)).text();
      expect(html).toContain('href="/favicon.svg"');
    }
    const res = await SELF.fetch("https://aegis.test/favicon.svg");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("image/svg+xml");
  });
});