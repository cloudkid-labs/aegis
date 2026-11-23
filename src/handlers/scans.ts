import { signCallbackToken } from "../callback-token";
import type { Env } from "../env";
import { dispatchGitHubWorkflow } from "../executors/github";
import { json, jsonError, readJsonBody } from "../http";
import { toolsForPhase } from "../registry";
import type { ScanStore } from "../scan-store";
import type { ScanRecord } from "../types";

const PRIVATE_HOST = /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/i;

export function validateTarget(raw: string): string | null {
  let url: URL;
  try { url = new URL(raw); } catch { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const host = url.hostname.toLowerCase();
  if (PRIVATE_HOST.test(host) || host.endsWith(".internal") || host.endsWith(".local") || host === "[::1]") return null;
  return url.toString();
}

function newScanId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const TIMEOUT_SECONDS = 900;

/** Start the timeout alarm, mint a callback token and dispatch the executor.
 *  Shared by create and retry so both track status identically. */
async function launch(
  env: Env, store: ScanStore, id: string, targetUrl: string,
  phase: ScanRecord["phase"], tools: ReturnType<typeof toolsForPhase>, depth: number,
): Promise<void> {
  const stub = env.SCAN_COORDINATOR.get(env.SCAN_COORDINATOR.idFromName(id));
  await stub.fetch("https://do/start", { method: "POST", body: JSON.stringify({ scanId: id, timeoutSeconds: TIMEOUT_SECONDS }) });

  const callbackUrl = `${env.AEGIS_ORIGIN}/api/executors/callback/${id}`;
  const callbackToken = await signCallbackToken(env.CALLBACK_SECRET, id, Date.now() + TIMEOUT_SECONDS * 1000 + 300_000);
  try {
    const result = await dispatchGitHubWorkflow(env, {
      scanId: id, target: targetUrl, phase, tools, callbackUrl, callbackToken, timeoutSeconds: TIMEOUT_SECONDS,
      options: { depth },
    });
    // Conditional: a cancel may land while the dispatch request is pending.
    // Only a still-queued scan becomes running; a cancelled one stays cancelled
    // (its alarm is already deleted, so resurrecting it would lose timeout cover).
    const running = await store.transition(id, ["queued"], "running", { externalUrl: result.externalUrl });
    if (running) await store.addEvent(id, "dispatched", result.externalUrl ?? undefined);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const failed = await store.transition(id, ["queued", "running"], "failed", { error: msg });
    if (failed) await store.addEvent(id, "failed", msg);
  }
}

function selectTools(phase: ScanRecord["phase"], options: Record<string, unknown> | null) {
  const allTools = toolsForPhase(phase);
  const requested = Array.isArray(options?.tools) ? (options!.tools as string[]) : null;
  return requested ? allTools.filter((t) => requested.includes(t.name)) : allTools.filter((t) => t.default !== false);
}

export async function handleCreateScan(req: Request, env: Env, store: ScanStore): Promise<Response> {
  const limit = await env.SCAN_LIMITER.limit({ key: "scans" });
  if (!limit.success) return jsonError("Rate limit exceeded", 429);

  const body = await readJsonBody(req);
  if (!body.ok) return body.response;
  const { target, phase, options } = body.value as { target?: string; phase?: string; options?: Record<string, unknown> };

  const targetUrl = typeof target === "string" ? validateTarget(target) : null;
  if (!targetUrl) return jsonError("Invalid or disallowed target URL", 400);
  const scanPhase = phase === "invasion" ? "invasion" : "explore";
  if (scanPhase === "invasion") return jsonError("Invasion phase not yet available (Phase 2)", 501);

  const tools = selectTools(scanPhase, options ?? null);
  if (tools.length === 0) return jsonError("No tools selected", 400);

  const id = newScanId();
  const now = new Date().toISOString();
  const rec: ScanRecord = {
    id, target: targetUrl, phase: scanPhase, status: "queued", parentScanId: null,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: options ? JSON.stringify(options) : null,
  };
  await store.create(rec);
  await store.addEvent(id, "created", `${scanPhase}:${tools.map((t) => t.name).join(",")}`);
  await launch(env, store, id, targetUrl, scanPhase, tools, Number(options?.depth) || 2);

  const final = await store.get(id);
  return json({ id, status: final!.status }, 201);
}

/** Re-run a failed or cancelled scan as a NEW scan with the same target and
 *  options, linked to the original via parentScanId and a retry event. */
export async function handleRetryScan(_req: Request, env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  if (rec.status !== "failed" && rec.status !== "cancelled") {
    return jsonError("Only failed or cancelled scans can be re-run", 409);
  }
  const limit = await env.SCAN_LIMITER.limit({ key: "scans" });
  if (!limit.success) return jsonError("Rate limit exceeded", 429);
  if (rec.phase === "invasion") return jsonError("Invasion phase not yet available (Phase 2)", 501);

  const options = rec.options ? (JSON.parse(rec.options) as Record<string, unknown>) : null;
  const tools = selectTools(rec.phase, options);
  if (tools.length === 0) return jsonError("No tools selected", 400);

  const newId = newScanId();
  const now = new Date().toISOString();
  const copy: ScanRecord = {
    id: newId, target: rec.target, phase: rec.phase, status: "queued", parentScanId: rec.id,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: rec.options,
  };
  await store.create(copy);
  await store.addEvent(newId, "created", `retry:${id} ${rec.phase}:${tools.map((t) => t.name).join(",")}`);
  await store.addEvent(id, "retried", newId);
  await launch(env, store, newId, rec.target, rec.phase, tools, Number(options?.depth) || 2);

  const final = await store.get(newId);
  return json({ id: newId, status: final!.status }, 201);
}

export async function handleListScans(_env: Env, store: ScanStore): Promise<Response> {
  return json({ scans: await store.list(50) });
}

export async function handleGetScan(_env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  return json({ scan: rec, events: await store.events(id) });
}

export async function handleAssets(_env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  return json({ assets: await store.listAssets(id) });
}

export async function handleCancelScan(_req: Request, env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  if (rec.status === "completed" || rec.status === "failed" || rec.status === "cancelled") return jsonError("Scan already terminal", 409);
  const stub = env.SCAN_COORDINATOR.get(env.SCAN_COORDINATOR.idFromName(id));
  await stub.fetch("https://do/cancel", { method: "POST" });
  const cancelled = await store.transition(id, ["queued", "running"], "cancelled");
  if (cancelled) await store.addEvent(id, "cancelled");
  return json({ id, status: cancelled ? "cancelled" : (await store.get(id))!.status });
}