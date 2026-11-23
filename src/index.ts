// Worker entry. Routing: /health and /api/* go to Hono (the API lives in
// src/server/api.ts); every other path falls through to the Astro static
// build in ./dist, bound as ASSETS. See astro.config.mjs for why there is no
// Cloudflare adapter and src/security-headers.ts for the headers stamped on
// every response, static ones included.
import { Hono } from "hono";
import type { Env } from "./env";
import { handleGoogleCallback, handleGoogleStart, handleLogout, handleMe } from "./google-oidc";
import { json, jsonError } from "./http";
import { d1ScanStore } from "./scan-store";
import { withSecurityHeaders } from "./security-headers";
import { createApiApp } from "./server/api";
import { d1SessionStore } from "./session-store";

export { ScanCoordinator } from "./scan-coordinator";

const app = new Hono<{ Bindings: Env }>({ strict: false });
app.get("/health", () => json({ ok: true }, 202));
app.route("/api", createApiApp((c) => d1ScanStore(c.env.AEGIS_DB)));

// Google sign-in. Outside the operator gate: these establish or report the
// session itself. /auth/me is public so the shell can render sign-in state.
app.get("/auth/google/start", (c) => handleGoogleStart(c.req.raw, c.env));
app.get("/auth/google/callback", (c) => handleGoogleCallback(c.req.raw, c.env, d1SessionStore(c.env.AEGIS_DB)));
app.get("/auth/logout", (c) => handleLogout(c.req.raw, d1SessionStore(c.env.AEGIS_DB)));
app.get("/auth/me", (c) => handleMe(c.req.raw, d1SessionStore(c.env.AEGIS_DB)));

app.notFound(() => jsonError("Not found", 404));

/**
 * Paths the Worker interprets. Everything else (/, /_astro/*, 404.html, ...)
 * is Astro output and must reach ASSETS untouched. Keep this list narrow:
 * widening it would route hashed CSS/JS through Hono, which answers JSON.
 */
export function isAppRoute(pathname: string): boolean {
  return (
    pathname === "/health" ||
    pathname === "/api" ||
    pathname.startsWith("/api/") ||
    pathname.startsWith("/auth/")
  );
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