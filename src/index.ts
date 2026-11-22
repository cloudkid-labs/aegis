// Worker entry. Routing: /health and /api/* go to Hono (the API lives in
// src/server/api.ts); every other path falls through to the Astro static
// build in ./dist, bound as ASSETS. See astro.config.mjs for why there is no
// Cloudflare adapter and src/security-headers.ts for the headers stamped on
// every response, static ones included.
import { Hono } from "hono";
import type { Env } from "./env";
import { json, jsonError } from "./http";
import { d1ScanStore } from "./scan-store";
import { withSecurityHeaders } from "./security-headers";
import { createApiApp } from "./server/api";

export { ScanCoordinator } from "./scan-coordinator";

const app = new Hono<{ Bindings: Env }>({ strict: false });
app.get("/health", () => json({ ok: true }, 202));
app.route("/api", createApiApp((c) => d1ScanStore(c.env.AEGIS_DB)));
app.notFound(() => jsonError("Not found", 404));

/**
 * Paths the Worker interprets. Everything else (/, /_astro/*, 404.html, ...)
 * is Astro output and must reach ASSETS untouched. Keep this list narrow:
 * widening it would route hashed CSS/JS through Hono, which answers JSON.
 */
export function isAppRoute(pathname: string): boolean {
  return pathname === "/health" || pathname === "/api" || pathname.startsWith("/api/");
}

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    const response = isAppRoute(pathname)
      ? await app.fetch(request, env, ctx)
      : await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;