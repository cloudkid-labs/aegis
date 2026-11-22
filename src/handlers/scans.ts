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

  const allTools = toolsForPhase(scanPhase);
  const requestedTools = Array.isArray(options?.tools) ? (options!.tools as string[]) : null;
  const tools = requestedTools ? allTools.filter((t) => requestedTools.includes(t.name)) : allTools.filter((t) => t.default !== false);
  if (tools.length === 0) return jsonError("No tools selected", 400);

  const timeoutSeconds = 900;
  const id = newScanId();
  const now = new Date().toISOString();
  const rec: ScanRecord = {
    id, target: targetUrl, phase: scanPhase, status: "queued", parentScanId: null,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: options ? JSON.stringify(options) : null,
  };
  await store.create(rec);
  await store.addEvent(id, "created", `${scanPhase}:${tools.map((t) => t.name).join(",")}`);

  const stub = env.SCAN_COORDINATOR.get(env.SCAN_COORDINATOR.idFromName(id));
  await stub.fetch("https://do/start", { method: "POST", body: JSON.stringify({ scanId: id, timeoutSeconds }) });

  const callbackUrl = `${env.AEGIS_ORIGIN}/api/executors/callback/${id}`;
  const callbackToken = await signCallbackToken(env.CALLBACK_SECRET, id, Date.now() + timeoutSeconds * 1000 + 300_000);
  try {
    const result = await dispatchGitHubWorkflow(env, {
      scanId: id, target: targetUrl, phase: scanPhase, tools, callbackUrl, callbackToken, timeoutSeconds,
      options: { depth: Number(options?.depth) || 2 },
    });
    await store.setStatus(id, "running", { externalUrl: result.externalUrl });
    await store.addEvent(id, "dispatched", result.externalUrl ?? undefined);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await store.setStatus(id, "failed", { error: msg });
    await store.addEvent(id, "failed", msg);
  }

  const final = await store.get(id);
  return json({ id, status: final!.status }, 201);
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
  await store.setStatus(id, "cancelled");
  await store.addEvent(id, "cancelled");
  return json({ id, status: "cancelled" });
}