import { signCallbackToken } from "../callback-token";
import type { Env } from "../env";
import { dispatchGitHubWorkflow } from "../executors/github";
import { json, jsonError, readJsonBody } from "../http";
import { selectInvasionTargets } from "../invasion-targets";
import {
  INVASION_MAX_URLS, INVASION_TIMEOUT_ACTIVE, INVASION_TIMEOUT_BASELINE,
} from "../limits";
import { toolsForPhase } from "../registry";
import { buildSarif } from "../sarif";
import type { ScanStore } from "../scan-store";
import type { Finding, ScanAuthorization, ScanRecord, Severity } from "../types";

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

/** Explore's timeout. Invasion derives its own from the selection (../limits). */
const TIMEOUT_SECONDS = 900;

/** Invasion-only dispatch extras. Explore keeps its 900 seconds and no target list. */
interface LaunchExtras {
  targets?: string[];
  severity?: string;
  timeoutSeconds?: number;
}

/** Start the timeout alarm, mint a callback token and dispatch the executor.
 *  Shared by create and retry so both track status identically. Everything
 *  that can throw sits inside the try: a Durable Object or token failure must
 *  leave the scan failed with an event, never queued with no alarm. Returns
 *  false when launch failed, so callers answer a JSON 500 instead of a 201
 *  claiming a scan that never started. */
async function launch(
  env: Env, store: ScanStore, id: string, targetUrl: string,
  phase: ScanRecord["phase"], tools: ReturnType<typeof toolsForPhase>, depth: number,
  extra: LaunchExtras = {},
): Promise<boolean> {
  const timeoutSeconds = extra.timeoutSeconds ?? TIMEOUT_SECONDS;
  try {
    const stub = env.SCAN_COORDINATOR.get(env.SCAN_COORDINATOR.idFromName(id));
    await stub.fetch("https://do/start", { method: "POST", body: JSON.stringify({ scanId: id, timeoutSeconds }) });

    const callbackUrl = `${env.AEGIS_ORIGIN}/api/executors/callback/${id}`;
    const callbackToken = await signCallbackToken(env.CALLBACK_SECRET, id, Date.now() + timeoutSeconds * 1000 + 300_000);
    // Explore's depth drives katana. Invasion has no depth tier; its severity
    // filter takes the same options bag, and the executor defaults it when absent.
    const options: Record<string, string | number | boolean> = phase === "explore" ? { depth } : {};
    if (extra.severity !== undefined) options.severity = extra.severity;
    const result = await dispatchGitHubWorkflow(env, {
      scanId: id, target: targetUrl, phase, tools, callbackUrl, callbackToken, timeoutSeconds,
      options,
      ...(extra.targets ? { targets: extra.targets } : {}),
    });
    // Conditional: a cancel may land while the dispatch request is pending.
    // Only a still-queued scan becomes running; a cancelled one stays cancelled
    // (its alarm is already deleted, so resurrecting it would lose timeout cover).
    const running = await store.transition(id, ["queued"], "running", { externalUrl: result.externalUrl });
    if (running) await store.addEvent(id, "dispatched", result.externalUrl ?? undefined);
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const failed = await store.transition(id, ["queued", "running"], "failed", { error: msg });
    if (failed) await store.addEvent(id, "failed", msg);
    return false;
  }
}

function selectTools(phase: ScanRecord["phase"], options: Record<string, unknown> | null) {
  const allTools = toolsForPhase(phase);
  const requested = Array.isArray(options?.tools) ? (options!.tools as string[]) : null;
  return requested ? allTools.filter((t) => requested.includes(t.name)) : allTools.filter((t) => t.default !== false);
}

/** Request options are untrusted JSON; only a plain object is a usable bag. */
function asOptions(raw: unknown): Record<string, unknown> | null {
  return typeof raw === "object" && raw !== null && !Array.isArray(raw) ? raw as Record<string, unknown> : null;
}

/** `options` is stored verbatim, so a corrupted row must not crash a retry. */
function storedOptions(raw: string | null): Record<string, unknown> | null {
  if (!raw) return null;
  try { return asOptions(JSON.parse(raw)); } catch { return null; }
}

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** The executor hands this straight to nuclei's `-severity` flag, so a space
 *  or an unknown word would be a silent scan-wide misconfiguration, not a
 *  narrower filter. Only exact tokens pass. */
function isSeverityList(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  return value.split(",").every((part) => (SEVERITIES as readonly string[]).includes(part));
}

export async function handleCreateScan(
  req: Request, env: Env, store: ScanStore, operatorEmail: string,
): Promise<Response> {
  const limit = await env.SCAN_LIMITER.limit({ key: "scans" });
  if (!limit.success) return jsonError("Rate limit exceeded", 429);

  const body = await readJsonBody(req);
  if (!body.ok) return body.response;
  const value = body.value as Record<string, unknown>;
  const options = asOptions(value.options);
  const scanPhase: ScanRecord["phase"] = value.phase === "invasion" ? "invasion" : "explore";

  if (scanPhase === "invasion") return createInvasion(env, store, value, options, operatorEmail);

  const targetUrl = typeof value.target === "string" ? validateTarget(value.target) : null;
  if (!targetUrl) return jsonError("Invalid or disallowed target URL", 400);

  const tools = selectTools(scanPhase, options);
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
  const launched = await launch(env, store, id, targetUrl, scanPhase, tools, Number(options?.depth) || 2);
  // launch() has already moved the scan to failed; report the failure rather
  // than a 201 for a scan no executor will ever run.
  if (!launched) return jsonError("Scan could not be launched", 500);

  const final = await store.get(id);
  return json({ id, status: final!.status }, 201);
}

/**
 * Invasion create. Validation order is normative (design spec Section 1):
 * parent (or standalone target) → allowed set → targets → tools →
 * authorization → severity, then rows, events and dispatch. Authorization is
 * a separate row so the exact payload survives on the audit trail even after
 * the scan record's options change shape.
 */
async function createInvasion(
  env: Env, store: ScanStore, value: Record<string, unknown>,
  options: Record<string, unknown> | null, operatorEmail: string,
): Promise<Response> {
  const rawParent = value.parentScanId;
  let parent: ScanRecord | null = null;
  let targetUrl: string;

  if (rawParent !== undefined && rawParent !== null) {
    if (typeof rawParent !== "string" || rawParent.length === 0) {
      return jsonError("Invalid parent scan id", 400);
    }
    parent = await store.get(rawParent);
    if (!parent) return jsonError("Parent scan not found", 400);
    if (parent.phase !== "explore") return jsonError("Parent scan must be an explore scan", 400);
    if (parent.status !== "completed") return jsonError("Parent scan must have completed", 400);
    // A chained scan attacks the same site its parent explored; ZAP takes one
    // entry point even though nuclei gets every selected URL.
    targetUrl = parent.target;
  } else {
    const validated = typeof value.target === "string" ? validateTarget(value.target) : null;
    if (!validated) return jsonError("Invalid or disallowed target URL", 400);
    targetUrl = validated;
  }

  const allowed = new Set(
    parent
      ? selectInvasionTargets(await store.listAssets(parent.id)).targets.map((t) => t.url)
      : [targetUrl],
  );

  const requestedTargets = value.targets;
  if (
    !Array.isArray(requestedTargets) || requestedTargets.length === 0 ||
    !requestedTargets.every((t): t is string => typeof t === "string" && allowed.has(t))
  ) {
    return jsonError("Targets must be a non-empty subset of the allowed URLs", 400);
  }
  if (requestedTargets.length > INVASION_MAX_URLS) {
    return jsonError(`At most ${INVASION_MAX_URLS} targets per invasion scan`, 400);
  }

  const invasionTools = toolsForPhase("invasion");
  const requestedTools = value.tools;
  if (
    !Array.isArray(requestedTools) || requestedTools.length === 0 ||
    !requestedTools.every((t): t is string => typeof t === "string" && invasionTools.some((entry) => entry.name === t))
  ) {
    return jsonError("Tools must be a non-empty subset of the invasion registry", 400);
  }
  const selectedTools = invasionTools.filter((entry) => requestedTools.includes(entry.name));
  const selectedToolNames = selectedTools.map((entry) => entry.name);

  const authorization = value.authorization;
  if (
    typeof authorization !== "object" || authorization === null ||
    (authorization as { confirmed?: unknown }).confirmed !== true
  ) {
    return jsonError("Invasion scans require authorization.confirmed === true", 400);
  }

  const severity = options?.severity;
  if (severity !== undefined && !isSeverityList(severity)) {
    return jsonError("Invalid severity option: expected a comma list of critical, high, medium, low, info", 400);
  }

  const active = selectedToolNames.includes("zap-full");
  const timeoutSeconds = active ? INVASION_TIMEOUT_ACTIVE : INVASION_TIMEOUT_BASELINE;
  const id = newScanId();
  const now = new Date().toISOString();
  const rec: ScanRecord = {
    id, target: targetUrl, phase: "invasion", status: "queued",
    parentScanId: parent ? parent.id : null,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: options ? JSON.stringify(options) : null,
  };
  await store.create(rec);
  const authorizationRec: ScanAuthorization = {
    scanId: id,
    email: operatorEmail,
    targets: [...requestedTargets],
    tools: selectedToolNames,
    active,
    confirmedAt: now,
  };
  const authorized = await persistAuthorization(store, authorizationRec);
  if (authorized) return authorized;
  await store.addEvent(id, "created", `invasion:${selectedToolNames.join(",")}`);
  await store.addEvent(id, "authorized", authorizeDetail(authorizationRec));
  const launched = await launch(env, store, id, targetUrl, "invasion", selectedTools, 2, {
    targets: authorizationRec.targets,
    severity: severity === undefined ? undefined : severity,
    timeoutSeconds,
  });
  if (!launched) return jsonError("Scan could not be launched", 500);

  const final = await store.get(id);
  return json({ id, status: final!.status }, 201);
}

/** Audit line for both create and retry: who confirmed, how many, which profile. */
function authorizeDetail(authorization: ScanAuthorization): string {
  return `${authorization.email}; targets=${authorization.targets.length}; active=${authorization.active}`;
}

/** The retried event names the copy and who triggered the retry. The stored
 *  authorization keeps its original email and confirmedAt: re-running a scan
 *  is not a new confirmation. */
function retriedDetail(newScanId: string, operatorEmail: string): string {
  return `${newScanId}; retried by ${operatorEmail}`;
}

/** The retry claim's CAS token must differ from the value it compares against.
 *  ISO timestamps only resolve to the millisecond, so a scan that failed in
 *  the same millisecond as the retry would otherwise rewrite updated_at
 *  unchanged and let a second retry claim the same row. */
function claimToken(expectedUpdatedAt: string): string {
  const now = Date.now();
  const expected = Date.parse(expectedUpdatedAt);
  return new Date(Number.isFinite(expected) && now <= expected ? expected + 1 : now).toISOString();
}

/**
 * Persist the authorization row and turn a failure into the right response.
 *
 * Only a primary-key conflict means "this scan id was already confirmed".
 * Re-reading the row is the honest probe for that: the row is either there or
 * it is not, with no dependence on D1's driver wording. Every other failure
 * (an outage, a broken statement) must not masquerade as a conflict and leave
 * a queued scan that no alarm will ever move, so it fails the scan and answers
 * 500. Returns null on success.
 */
async function persistAuthorization(
  store: ScanStore, authorization: ScanAuthorization,
): Promise<Response | null> {
  try {
    await store.createAuthorization(authorization);
    return null;
  } catch (err) {
    let existing: ScanAuthorization | null = null;
    try { existing = await store.getAuthorization(authorization.scanId); } catch { /* unreadable: treat as unwritten */ }
    const detail = existing ? "Scan already authorized" : (err instanceof Error ? err.message : String(err));
    // No path below launches, so the queued row must not keep advertising
    // itself as pending work. Retried copies land here the same way.
    try {
      const failed = await store.transition(authorization.scanId, ["queued"], "failed", { error: detail });
      if (failed) await store.addEvent(authorization.scanId, "failed", detail);
    } catch { /* the authorization failure is already being reported */ }
    return existing
      ? jsonError("Scan already authorized", 409)
      : jsonError("Authorization could not be stored", 500);
  }
}

/** Re-run a failed or cancelled scan as a NEW scan with the same target and
 *  options, linked to the original via parentScanId and a retry event.
 *  `operatorEmail` is who triggered the retry, recorded on that event; the
 *  stored authorization itself stays immutable. */
export async function handleRetryScan(
  _req: Request, env: Env, store: ScanStore, id: string, operatorEmail: string,
): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  if (rec.status !== "failed" && rec.status !== "cancelled") {
    return jsonError("Only failed or cancelled scans can be re-run", 409);
  }
  const limit = await env.SCAN_LIMITER.limit({ key: "scans" });
  if (!limit.success) return jsonError("Rate limit exceeded", 429);

  // Single-flight: two requests of a concurrent retry read the same row, but
  // only the first claim moves its updatedAt. Without this each request would
  // create and dispatch its own active copy of one failed scan.
  const now = new Date().toISOString();
  if (!(await store.claimRetry(rec.id, rec.updatedAt, claimToken(rec.updatedAt)))) {
    return jsonError("Retry already in progress", 409);
  }
  if (rec.phase === "invasion") return retryInvasion(env, store, rec, operatorEmail, now);

  const options = rec.options ? (JSON.parse(rec.options) as Record<string, unknown>) : null;
  const tools = selectTools(rec.phase, options);
  if (tools.length === 0) return jsonError("No tools selected", 400);

  const newId = newScanId();
  const copy: ScanRecord = {
    id: newId, target: rec.target, phase: rec.phase, status: "queued", parentScanId: rec.id,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: rec.options,
  };
  await store.create(copy);
  await store.addEvent(newId, "created", `retry:${id} ${rec.phase}:${tools.map((t) => t.name).join(",")}`);
  await store.addEvent(id, "retried", retriedDetail(newId, operatorEmail));
  const launched = await launch(env, store, newId, rec.target, rec.phase, tools, Number(options?.depth) || 2);
  if (!launched) return jsonError("Scan could not be launched", 500);

  const final = await store.get(newId);
  return json({ id: newId, status: final!.status }, 201);
}

/**
 * Invasion retry replays the stored authorization, not the scan row: the
 * targets and tools the operator confirmed are the whole point of the row.
 * A chained retry re-reads the parent's live selection, because an asset that
 * is no longer allowed there must not be attacked under the old confirmation.
 */
async function retryInvasion(
  env: Env, store: ScanStore, rec: ScanRecord, operatorEmail: string, now: string,
): Promise<Response> {
  const authorization = await store.getAuthorization(rec.id);
  if (!authorization) return jsonError("Scan has no stored authorization", 409);

  const invasionTools = toolsForPhase("invasion");
  const names = invasionTools.map((entry) => entry.name);
  if (authorization.targets.length === 0 || authorization.targets.length > INVASION_MAX_URLS) {
    return jsonError("Stored authorization exceeds the target cap", 409);
  }
  if (authorization.tools.length === 0 || !authorization.tools.every((tool) => (names as string[]).includes(tool))) {
    return jsonError("Stored authorization names unknown tools", 409);
  }

  if (rec.parentScanId) {
    const parent = await store.get(rec.parentScanId);
    if (!parent) return jsonError("Parent scan is no longer available", 409);
    // Only an explore parent defines the allowed URL set. A standalone scan's
    // retry records the previous invasion row as lineage, so a retry-of-retry
    // must not be re-validated against it: those targets were checked when the
    // authorization was first written. A chained scan keeps its explore parent
    // across retries, so its live subset check still runs.
    if (parent.phase === "explore") {
      if (parent.status !== "completed") {
        return jsonError("Parent scan is no longer available", 409);
      }
      const allowed = new Set(
        selectInvasionTargets(await store.listAssets(parent.id)).targets.map((t) => t.url),
      );
      if (!authorization.targets.every((target) => allowed.has(target))) {
        return jsonError("Stored targets are no longer allowed by the parent scan", 409);
      }
    }
  }

  const tools = invasionTools.filter((entry) => authorization.tools.includes(entry.name));
  const active = authorization.tools.includes("zap-full");
  const storedSeverity = storedOptions(rec.options)?.severity;
  const severity = isSeverityList(storedSeverity) ? storedSeverity : undefined;
  const timeoutSeconds = active ? INVASION_TIMEOUT_ACTIVE : INVASION_TIMEOUT_BASELINE;

  const newId = newScanId();
  const copy: ScanRecord = {
    id: newId, target: rec.target, phase: "invasion", status: "queued",
    // Keep a chained scan pointing at the explore scan whose assets allowed
    // it; only a standalone scan uses the retry link for lineage.
    parentScanId: rec.parentScanId ?? rec.id,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: rec.options,
  };
  await store.create(copy);
  const authorizationRec: ScanAuthorization = {
    scanId: newId,
    email: authorization.email,
    targets: [...authorization.targets],
    tools: [...authorization.tools],
    active: authorization.active,
    confirmedAt: authorization.confirmedAt,
  };
  const authorized = await persistAuthorization(store, authorizationRec);
  if (authorized) return authorized;
  await store.addEvent(newId, "created", `retry:${rec.id} invasion:${tools.map((t) => t.name).join(",")}`);
  await store.addEvent(newId, "authorized", authorizeDetail(authorizationRec));
  await store.addEvent(rec.id, "retried", retriedDetail(newId, operatorEmail));
  const launched = await launch(env, store, newId, rec.target, "invasion", tools, 2, {
    targets: authorizationRec.targets,
    severity,
    timeoutSeconds,
  });
  if (!launched) return jsonError("Scan could not be launched", 500);

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

/** An explore scan's live URLs, pre-filtered for the invasion confirm panel. */
export async function handleInvasionPreview(_env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec || rec.phase !== "explore") return jsonError("Scan not found", 404);
  const selection = selectInvasionTargets(await store.listAssets(id));
  return json({ targets: selection.targets, excluded: selection.excluded, maxUrls: INVASION_MAX_URLS });
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

/** Severity rank, then discovery order within a rank. `id` breaks the
 *  same-millisecond tie so two runs of the same stored data agree. */
function bySeverityThenCreated(a: Finding, b: Finding): number {
  return (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5)
    || a.createdAt.localeCompare(b.createdAt)
    || a.id.localeCompare(b.id);
}

export async function handleFindings(_env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  const findings = (await store.listFindings(id)).sort(bySeverityThenCreated);
  return json({ findings });
}

/** SARIF is a JSON document, not the API's JSON envelope: content type and
 *  attachment disposition are what an editor's SARIF importer keys on. */
export async function handleSarif(_env: Env, store: ScanStore, id: string): Promise<Response> {
  const rec = await store.get(id);
  if (!rec) return jsonError("Scan not found", 404);
  const findings = (await store.listFindings(id)).sort(bySeverityThenCreated);
  return new Response(JSON.stringify(buildSarif(rec, findings)), {
    headers: {
      "content-type": "application/sarif+json",
      "content-disposition": `attachment; filename="aegis-${id.slice(0, 8)}.sarif"`,
    },
  });
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