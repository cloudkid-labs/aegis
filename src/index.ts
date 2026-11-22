import { isAuthorized } from "./auth";
import type { Env } from "./env";
import { handleCallback } from "./handlers/callback";
import { handleAssets, handleCancelScan, handleCreateScan, handleGetScan, handleListScans } from "./handlers/scans";
import { json, jsonError } from "./http";
import { d1ScanStore } from "./scan-store";
import { withSecurityHeaders } from "./security-headers";

export { ScanCoordinator } from "./scan-coordinator";

async function route(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  const method = request.method;

  if (pathname === "/health") return json({ ok: true }, 202);

  if (pathname.startsWith("/api/")) {
    const store = d1ScanStore(env.AEGIS_DB);

    const cbMatch = pathname.match(/^\/api\/executors\/callback\/([0-9a-f]{32})$/);
    if (cbMatch && method === "POST") return handleCallback(request, env, store, cbMatch[1]!);

    if (!(await isAuthorized(request, env.AEGIS_API_KEY))) return jsonError("Unauthorized", 401);

    if (method === "POST" && pathname === "/api/scans") return handleCreateScan(request, env, store);
    if (method === "GET" && pathname === "/api/scans") return handleListScans(env, store);

    const scanMatch = pathname.match(/^\/api\/scans\/([0-9a-f]{32})(\/assets|\/cancel)?$/);
    if (scanMatch) {
      const [, id, sub] = scanMatch;
      if (method === "GET" && !sub) return handleGetScan(env, store, id!);
      if (method === "GET" && sub === "/assets") return handleAssets(env, store, id!);
      if (method === "POST" && sub === "/cancel") return handleCancelScan(request, env, store, id!);
    }
    return jsonError("Not found", 404);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return withSecurityHeaders(await route(request, env));
  },
} satisfies ExportedHandler<Env>;