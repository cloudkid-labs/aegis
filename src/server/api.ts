// The JSON API, mounted at /api by the Worker entry (src/index.ts) and by
// tests with an in-memory store. Business logic stays in src/handlers/*; this
// file only owns paths, method routing and where the bearer gate applies.
import { Hono } from "hono";
import type { Context } from "hono";
import { isAuthorized } from "../auth";
import type { Env } from "../env";
import { handleCallback } from "../handlers/callback";
import {
  handleAssets, handleCancelScan, handleCreateScan, handleFindings, handleGetScan,
  handleInvasionPreview, handleListScans, handleRetryScan, handleSarif,
} from "../handlers/scans";
import { jsonError } from "../http";
import type { ScanStore } from "../scan-store";
import { currentSession } from "../session";
import { d1SessionStore, type SessionStore } from "../session-store";

// `operatorEmail` is resolved once by the gate and read by the invasion
// create handler, which has to attribute the authorization it stores.
export type ApiEnv = { Bindings: Env; Variables: { operatorEmail: string } };
export type ApiContext = Context<ApiEnv>;

/** Bearer automation has no email. Recording the shared key by name is
 *  truthful about who confirmed, unlike inventing or leaving the column empty. */
const API_KEY_IDENTITY = "api-key";

/** Resolved per request: production reads D1 from c.env, tests pass a memory store. */
export type StoreFactory = (c: ApiContext) => ScanStore;
export type SessionFactory = (c: ApiContext) => SessionStore;

// Same 32-hex scan id the old hand-rolled regex enforced. A path that does
// not match falls to notFound, so unknown ids still answer "Not found".
const SCAN_ID = ":scanId{[0-9a-f]{32}}";

export function createApiApp(
  makeStore: StoreFactory,
  makeSession: SessionFactory = (c) => d1SessionStore(c.env.AEGIS_DB),
): Hono<ApiEnv> {
  const app = new Hono<ApiEnv>({ strict: false });

  // Executor callback. Authenticated by its own short-lived HMAC token,
  // validated inside the scan's Durable Object, so it must stay outside the
  // operator gate: GitHub Actions never holds AEGIS_API_KEY or a session.
  app.post(`/executors/callback/${SCAN_ID}`, (c) =>
    handleCallback(c.req.raw, c.env, makeStore(c), c.req.param("scanId")),
  );

  // Operator API. Admits a dashboard login session OR the Bearer API key, so
  // browser sign-in and headless automation both work. A missing/junk cookie
  // resolves to null without a database round trip (./session), so the
  // bearer-only path never touches D1.
  const requireOperator = async (c: ApiContext, next: () => Promise<void>) => {
    const session = await currentSession(c.req.raw, makeSession(c));
    if (session) {
      c.set("operatorEmail", session.email);
      return next();
    }
    if (await isAuthorized(c.req.raw, c.env.AEGIS_API_KEY)) {
      c.set("operatorEmail", API_KEY_IDENTITY);
      return next();
    }
    return jsonError("Unauthorized", 401);
  };
  app.use("/scans", requireOperator);
  app.use("/scans/*", requireOperator);

  app.post("/scans", (c) => handleCreateScan(c.req.raw, c.env, makeStore(c), c.get("operatorEmail")));
  app.get("/scans", (c) => handleListScans(c.env, makeStore(c)));
  app.get(`/scans/${SCAN_ID}`, (c) => handleGetScan(c.env, makeStore(c), c.req.param("scanId")));
  app.get(`/scans/${SCAN_ID}/assets`, (c) => handleAssets(c.env, makeStore(c), c.req.param("scanId")));
  app.get(`/scans/${SCAN_ID}/invasion-preview`, (c) =>
    handleInvasionPreview(c.env, makeStore(c), c.req.param("scanId")),
  );
  app.get(`/scans/${SCAN_ID}/findings`, (c) => handleFindings(c.env, makeStore(c), c.req.param("scanId")));
  app.get(`/scans/${SCAN_ID}/sarif`, (c) => handleSarif(c.env, makeStore(c), c.req.param("scanId")));
  app.post(`/scans/${SCAN_ID}/cancel`, (c) =>
    handleCancelScan(c.req.raw, c.env, makeStore(c), c.req.param("scanId")),
  );
  app.post(`/scans/${SCAN_ID}/retry`, (c) =>
    handleRetryScan(c.req.raw, c.env, makeStore(c), c.req.param("scanId")),
  );

  // The API never answers with an HTML or plain-text body: the dashboard
  // reads any non-JSON response as a failure between it and the Worker.
  app.notFound(() => jsonError("Not found", 404));

  return app;
}