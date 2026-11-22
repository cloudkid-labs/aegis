// Astro 7, static output behind the hand-written Hono Worker (src/index.ts).
// Pages build to ./dist, which wrangler.jsonc binds as ASSETS with
// run_worker_first true: /health and /api/* are answered by Hono, every other
// path falls through to the files built here.
// NOTE: intentionally NO Cloudflare adapter. The adapter emits its own Worker
// entry, dist/client/ and dist/wrangler.json, and takes over the deploy;
// src/index.ts is the only Worker.
import { defineConfig } from "astro/config";

export default defineConfig({
  output: "static",
  // dist/404.html (not dist/404/index.html): the ASSETS router's
  // not_found_handling "404-page" serves that filename for misses.
  build: {
    format: "file",
    // The Worker's CSP is style-src 'self' (src/security-headers.ts). Astro's
    // "auto" default inlines stylesheets under 4 kB as a <style> element,
    // which that policy refuses; aegis.css is under the limit. "never" emits
    // a hashed /_astro/*.css link on every page instead.
    inlineStylesheets: "never",
  },
  vite: {
    build: {
      // Same CSP reason for scripts: Astro inlines a page's <script> chunk
      // when it is under Vite's assetsInlineLimit (4 kB default), emitting an
      // inline <script type="module"> that `script-src 'self'` blocks. 0
      // forces every client script out to a hashed /_astro/*.js file.
      assetsInlineLimit: 0,
    },
  },
});