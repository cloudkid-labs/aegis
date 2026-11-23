import type { Env } from "../env";
import { json, jsonError, readJsonBody } from "../http";
import { normalize, normalizeFindings } from "../normalizers/index";
import { getTool } from "../registry";
import type { ScanStore } from "../scan-store";
import type { Asset, Finding } from "../types";

const CALLBACK_BODY_LIMIT = 5 * 1024 * 1024;

interface Artifact { tool: string; format: string; data: unknown; raw?: string }

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
  const { artifacts, error, failures, truncated } = body.value as { artifacts?: Artifact[]; error?: string; failures?: string[]; truncated?: string[] };

  if (typeof error === "string" && error.length > 0) {
    const failed = await store.transition(scanId, ["queued", "running"], "failed", { error });
    if (failed) await store.addEvent(scanId, "failed", error);
    await stub.fetch("https://do/cancel", { method: "POST" });
    return json({ ok: true, status: failed ? "failed" : (await store.get(scanId))!.status });
  }

  const now = new Date().toISOString();
  const allAssets: Asset[] = [];
  const allFindings: Finding[] = [];

  for (const artifact of artifacts ?? []) {
    // A resolved tool (alterx) sends the verification records as data and its
    // original wordlist as raw: the wordlist is the evidence, kept verbatim.
    const isRawText = typeof artifact.raw === "string";
    const rawRef = `scans/${scanId}/raw/${artifact.tool}-${Date.now()}.${isRawText ? "txt" : "json"}`;
    await env.ARTIFACTS.put(
      rawRef,
      isRawText ? artifact.raw! : typeof artifact.data === "string" ? artifact.data : JSON.stringify(artifact.data),
      { httpMetadata: { contentType: isRawText ? "text/plain" : "application/json" } },
    );

    const tool = getTool(artifact.tool);
    // Route on the registry's outputType, never on the executor's labels. An
    // unknown tool (an older executor still shipping a retired name) keeps the
    // asset path it always had, so mixed-version callbacks keep ingesting.
    if (tool?.outputType === "findings") {
      // The label hashed into finding ids is the registry name; getTool only
      // matches exact names, so it equals artifact.tool for a resolved entry.
      const findings = await normalizeFindings(tool.normalizer, tool.name, artifact.data, scanId, now);
      // rawRef is attribution, not identity: set it on the normalized findings
      // before the insert and leave the ids the normalizer computed alone.
      for (const finding of findings) finding.rawRef = rawRef;
      allFindings.push(...findings);
      continue;
    }
    const normalizerKey = tool?.normalizer ?? `${artifact.tool}-${artifact.format}`;
    const assets = await normalize(normalizerKey, artifact.data, scanId, now);
    allAssets.push(...assets);
  }

  await store.insertAssets(allAssets);
  // Idempotent on id: a finding reported twice in one callback (or by a
  // re-delivered artifact) updates its row instead of duplicating it.
  await store.insertFindings(allFindings);
  // Conditional: a cancel or timeout may have landed while artifacts were
  // uploading. Keep that terminal verdict rather than resurrecting the scan.
  const completed = await store.transition(scanId, ["queued", "running"], "completed", { completedAt: now });
  await stub.fetch("https://do/cancel", { method: "POST" });
  if (!completed) {
    return json({ ok: true, status: (await store.get(scanId))!.status });
  }
  const failNote = Array.isArray(failures) && failures.length > 0 ? `; ${failures.length} tool failure(s): ${failures.join(", ")}` : "";
  const truncNote = Array.isArray(truncated) && truncated.length > 0 ? `; output truncated to fit callback limit: ${truncated.join(", ")}` : "";
  await store.addEvent(scanId, "completed", `${allAssets.length} assets; ${allFindings.length} findings${failNote}${truncNote}`);

  return json({ ok: true, assets: allAssets.length, findings: allFindings.length });
}