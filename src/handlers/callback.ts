import type { Env } from "../env";
import { json, jsonError, readJsonBody } from "../http";
import { normalize } from "../normalizers/index";
import { getTool } from "../registry";
import type { ScanStore } from "../scan-store";
import type { Asset } from "../types";

const CALLBACK_BODY_LIMIT = 5 * 1024 * 1024;

interface Artifact { tool: string; format: string; data: unknown }

export async function handleCallback(req: Request, env: Env, store: ScanStore, scanId: string): Promise<Response> {
  const rec = await store.get(scanId);
  if (!rec) return jsonError("Scan not found", 404);
  if (rec.status === "completed" || rec.status === "failed" || rec.status === "cancelled") return jsonError("Scan already terminal", 409);

  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const stub = env.SCAN_COORDINATOR.get(env.SCAN_COORDINATOR.idFromName(scanId));
  const consume = await stub.fetch("https://do/consume", { method: "POST", body: JSON.stringify({ scanId, token }) });
  if (consume.status === 401) return jsonError("Invalid callback token", 401);
  if (consume.status === 409) return jsonError("Callback already consumed", 409);

  const body = await readJsonBody(req, CALLBACK_BODY_LIMIT);
  if (!body.ok) return body.response;
  const { artifacts, error, failures } = body.value as { artifacts?: Artifact[]; error?: string; failures?: string[] };

  if (typeof error === "string" && error.length > 0) {
    await store.setStatus(scanId, "failed", { error });
    await store.addEvent(scanId, "failed", error);
    await stub.fetch("https://do/cancel", { method: "POST" });
    return json({ ok: true, status: "failed" });
  }

  const now = new Date().toISOString();
  const allAssets: Asset[] = [];

  for (const artifact of artifacts ?? []) {
    const rawRef = `scans/${scanId}/raw/${artifact.tool}-${Date.now()}.json`;
    await env.ARTIFACTS.put(rawRef, typeof artifact.data === "string" ? artifact.data : JSON.stringify(artifact.data), { httpMetadata: { contentType: "application/json" } });

    const tool = getTool(artifact.tool);
    const normalizerKey = tool?.normalizer ?? `${artifact.tool}-${artifact.format}`;
    const assets = await normalize(normalizerKey, artifact.data, scanId, now);
    allAssets.push(...assets);
  }

  await store.insertAssets(allAssets);
  await store.setStatus(scanId, "completed", { completedAt: now });
  const failNote = Array.isArray(failures) && failures.length > 0 ? `; ${failures.length} tool failure(s): ${failures.join(", ")}` : "";
  await store.addEvent(scanId, "completed", `${allAssets.length} assets${failNote}`);
  await stub.fetch("https://do/cancel", { method: "POST" });

  return json({ ok: true, assets: allAssets.length });
}