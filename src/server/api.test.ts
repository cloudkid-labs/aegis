import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex } from "../auth";
import type { Env } from "../env";
import type { ScanStore } from "../scan-store";
import { SESSION_COOKIE } from "../session";
import { memorySessionStore } from "../session-store";
import { nucleiRecord } from "../test-support/fixtures";
import { memoryScanStore } from "../test-support/memory-store";
import type { Asset, Finding, ScanRecord, Severity } from "../types";
import { createApiApp } from "./api";

const KEY = "test-key";
const auth = { authorization: `Bearer ${KEY}` };

interface Harness {
  env: Env;
  store: ScanStore;
  /** Durable Object routes hit, e.g. "/start" or "/consume". */
  doCalls: string[];
  /** Bodies posted to the DO's /start, so timeout derivation is observable. */
  doStarts: { path: string; body: Record<string, unknown> }[];
  /** GitHub workflow dispatch bodies, captured from the stubbed global fetch. */
  dispatches: { url: string; body: { inputs: Record<string, string> } }[];
}

/**
 * Fake bindings for the node project. The Durable Object answers /start with
 * 200 and rejects every /consume token, which is all the API layer needs to
 * prove it delegated (the real DO logic is pinned in
 * src/scan-coordinator.workers.test.ts) and that the callback route is not
 * behind the bearer gate.
 */
function harness(overrides: Partial<Env> = {}): Harness {
  const doCalls: string[] = [];
  const doStarts: Harness["doStarts"] = [];
  const dispatches: Harness["dispatches"] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    dispatches.push({ url: String(input), body: JSON.parse(String(init?.body)) });
    return new Response(null, { status: 204 });
  });
  const env = {
    AEGIS_API_KEY: KEY,
    AEGIS_ORIGIN: "https://aegis.test",
    CALLBACK_SECRET: "test-callback-secret",
    GITHUB_TOKEN: "test-github-token",
    GITHUB_OWNER: "cloudkid-labs",
    GITHUB_REPO: "aegis",
    GITHUB_WORKFLOW: "aegis-explore.yml",
    GITHUB_WORKFLOW_INVASION: "aegis-invasion.yml",
    SCAN_LIMITER: { limit: async () => ({ success: true }) },
    SCAN_COORDINATOR: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          const path = new URL(String(input)).pathname;
          doCalls.push(path);
          if (path === "/start") doStarts.push({ path, body: JSON.parse(String(init?.body ?? "{}")) });
          return new Response(null, { status: path === "/consume" ? 401 : 200 });
        },
      }),
    },
    ...overrides,
  } as unknown as Env;
  return { env, store: memoryScanStore(), doCalls, doStarts, dispatches };
}

function seed(
  store: ScanStore,
  id: string,
  status: ScanRecord["status"] = "queued",
  phase: ScanRecord["phase"] = "explore",
): Promise<void> {
  const now = new Date().toISOString();
  return store.create({
    id, target: "https://example.com/", phase, status, parentScanId: null,
    executor: "github", externalUrl: null, createdAt: now, updatedAt: now,
    completedAt: null, error: null, options: null,
  });
}

// The real DO is pinned in src/scan-coordinator.workers.test.ts; callback
// tests only need it to accept the token and the cancel that follows.
const acceptingDo = {
  idFromName: (n: string) => n,
  get: () => ({ fetch: async () => new Response(null, { status: 200 }) }),
} as unknown as DurableObjectNamespace;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("createApiApp", () => {
  it("rejects the scan routes without a bearer key", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);

    for (const [method, path] of [
      ["GET", "/scans"],
      ["POST", "/scans"],
      ["GET", "/scans/0123456789abcdef0123456789abcdef"],
      ["POST", "/scans/0123456789abcdef0123456789abcdef/cancel"],
      ["GET", "/scans/0123456789abcdef0123456789abcdef/invasion-preview"],
      ["GET", "/scans/0123456789abcdef0123456789abcdef/findings"],
      ["GET", "/scans/0123456789abcdef0123456789abcdef/sarif"],
    ] as const) {
      const res = await app.request(path, { method, headers: { "content-type": "application/json" } }, env);
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "Unauthorized" });
    }
  });

  it("lists scans for an authorized caller", async () => {
    const { env, store } = harness();
    await seed(store, "0123456789abcdef0123456789abcdef");
    const app = createApiApp(() => store);

    const res = await app.request("/scans", { headers: auth }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { scans: ScanRecord[] };
    expect(body.scans.map((s) => s.id)).toEqual(["0123456789abcdef0123456789abcdef"]);
  });

  it("list response carries each scan's asset count", async () => {
    const { env, store } = harness();
    const id = "0123456789abcdef0123456789abcdef";
    await seed(store, id);
    await store.insertAssets([{
      id: "count-asset", scanId: id, type: "subdomain", value: "x.example.com",
      metadata: null, createdAt: new Date().toISOString(),
    }]);
    const app = createApiApp(() => store);

    const res = await app.request("/scans", { headers: auth }, env);
    const body = (await res.json()) as { scans: (ScanRecord & { assetCount: number })[] };
    expect(body.scans[0]!.assetCount).toBe(1);
  });

  it("creates a scan, starts the Durable Object and dispatches the workflow", async () => {
    const { env, store, doCalls, doStarts, dispatches } = harness();
    const app = createApiApp(() => store);

    const res = await app.request("/scans", {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ target: "https://example.com", phase: "explore", options: { depth: 3, tools: ["subfinder"] } }),
    }, env);

    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; status: string };
    expect(body.id).toMatch(/^[0-9a-f]{32}$/);
    expect(body.status).toBe("running");

    const rec = await store.get(body.id);
    expect(rec?.target).toBe("https://example.com/");
    expect(rec?.status).toBe("running");
    expect(rec?.externalUrl).toContain("github.com");

    expect(doCalls).toEqual(["/start"]);
    // Explore keeps its own 900-second timeout.
    expect(doStarts[0]!.body.timeoutSeconds).toBe(900);
    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]!.url).toContain("aegis-explore.yml");
    expect(dispatches[0]!.body.inputs.callback_url).toBe(`https://aegis.test/api/executors/callback/${body.id}`);
    expect(dispatches[0]!.body.inputs.tools).toBe('["subfinder"]');

    const events = await store.events(body.id);
    expect(events.map((e) => e.event)).toEqual(["created", "dispatched"]);
  });

  it("rejects a disallowed target before touching the executor", async () => {
    const { env, store, doCalls } = harness();
    const app = createApiApp(() => store);

    const res = await app.request("/scans", {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ target: "http://127.0.0.1:8080", phase: "explore" }),
    }, env);

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Invalid or disallowed target URL" });
    expect(doCalls).toEqual([]);
    expect(await store.list(10)).toEqual([]);
  });

  it("returns 429 when the rate limiter refuses", async () => {
    const { env, store } = harness({ SCAN_LIMITER: { limit: async () => ({ success: false }) } as unknown as RateLimit });
    const app = createApiApp(() => store);

    const res = await app.request("/scans", {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ target: "https://example.com" }),
    }, env);
    expect(res.status).toBe(429);
  });

  it("returns a scan with its events", async () => {
    const { env, store } = harness();
    const id = "0123456789abcdef0123456789abcdef";
    await seed(store, id, "running");
    await store.addEvent(id, "created", "explore:subfinder");
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${id}`, { headers: auth }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { scan: ScanRecord; events: { event: string }[] };
    expect(body.scan.id).toBe(id);
    expect(body.events.map((e) => e.event)).toEqual(["created"]);

    const missing = await app.request(`/scans/${"0".repeat(32)}`, { headers: auth }, env);
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "Scan not found" });
  });

  it("serves the callback route without the bearer key and delegates the token to the DO", async () => {
    const { env, store, doCalls } = harness();
    const id = "0123456789abcdef0123456789abcdef";
    await seed(store, id);
    const app = createApiApp(() => store);

    const res = await app.request(`/executors/callback/${id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ artifacts: [] }),
    }, env);

    // "Invalid callback token" proves the bearer gate was skipped: an
    // unauthorized scan route answers {error:"Unauthorized"} instead.
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Invalid callback token" });
    expect(doCalls).toEqual(["/consume"]);
  });

  it("does not route a malformed scan id", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);

    for (const path of ["/scans/not-a-scan", "/scans/0123", `/scans/${"A".repeat(32)}`]) {
      const res = await app.request(path, { headers: auth }, env);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "Not found" });
    }
  });

  it("answers unknown API paths with JSON", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);
    const res = await app.request("/nope", { headers: auth }, env);
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
  });
});

describe("operator gate: session or bearer", () => {
  async function sessionCookie(email = "operator@example.com", ttl = 100_000): Promise<{ store: ReturnType<typeof memorySessionStore>; cookie: string }> {
    const store = memorySessionStore();
    const token = "C".repeat(43);
    const now = Date.now();
    await store.create(await sha256Hex(token), email, now, now + ttl);
    return { store, cookie: `${SESSION_COOKIE}=${token}` };
  }

  it("admits a valid login session without a bearer key", async () => {
    const { env, store } = harness();
    const { store: sessions, cookie } = await sessionCookie();
    const app = createApiApp(() => store, () => sessions);
    const res = await app.request("/scans", { headers: { cookie } }, env);
    expect(res.status).toBe(200);
  });

  it("rejects an expired session when no bearer key is present", async () => {
    const { env, store } = harness();
    const { store: sessions, cookie } = await sessionCookie("operator@example.com", -1);
    const app = createApiApp(() => store, () => sessions);
    const res = await app.request("/scans", { headers: { cookie } }, env);
    expect(res.status).toBe(401);
  });

  it("still admits the bearer key for automation (no session)", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store, () => memorySessionStore());
    const res = await app.request("/scans", { headers: auth }, env);
    expect(res.status).toBe(200);
  });
});

describe("callback terminal-state guard", () => {
  const ID = "0123456789abcdef0123456789abcdef";
  const callbackBody = JSON.stringify({ artifacts: [{ tool: "subfinder", format: "json", data: [{ host: "x.example.com" }] }] });

  it("completes a running scan", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running");
    env.SCAN_COORDINATOR = acceptingDo;
    env.ARTIFACTS = { put: async () => {} } as unknown as R2Bucket;
    const app = createApiApp(() => store);
    const res = await app.request(`/executors/callback/${ID}`, { method: "POST", headers: { "content-type": "application/json" }, body: callbackBody }, env);
    expect(res.status).toBe(200);
    expect((await res.json()) as { assets: number }).toMatchObject({ assets: 1 });
    expect((await store.get(ID))!.status).toBe("completed");
  });

  it("does not resurrect a scan cancelled while artifacts upload", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running");
    env.SCAN_COORDINATOR = acceptingDo;
    // A cancel lands mid-callback (during the R2 upload), after the handler's
    // opening terminal check but before its completion transition.
    env.ARTIFACTS = { put: async () => { await store.transition(ID, ["queued", "running"], "cancelled"); } } as unknown as R2Bucket;
    const app = createApiApp(() => store);
    const res = await app.request(`/executors/callback/${ID}`, { method: "POST", headers: { "content-type": "application/json" }, body: callbackBody }, env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { status: string }).status).toBe("cancelled");
    expect((await store.get(ID))!.status).toBe("cancelled");
    expect((await store.events(ID)).some((e) => e.event === "completed")).toBe(false);
  });

  it("records output truncation in the completion event", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running");
    env.SCAN_COORDINATOR = acceptingDo;
    env.ARTIFACTS = { put: async () => {} } as unknown as R2Bucket;
    const app = createApiApp(() => store);
    const res = await app.request(`/executors/callback/${ID}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ artifacts: [{ tool: "subfinder", format: "json", data: [{ host: "x.example.com" }] }], truncated: ["katana"] }),
    }, env);
    expect(res.status).toBe(200);
    const completed = (await store.events(ID)).find((e) => e.event === "completed");
    expect(completed?.detail).toContain("truncated");
    expect(completed?.detail).toContain("katana");
  });

  it("stores an artifact's raw wordlist in R2 and ingests only the resolved records", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running");
    env.SCAN_COORDINATOR = acceptingDo;
    const puts: { key: string; body: string; type?: string }[] = [];
    env.ARTIFACTS = {
      put: async (key: string, body: string, opts?: { httpMetadata?: { contentType?: string } }) => {
        puts.push({ key, body, type: opts?.httpMetadata?.contentType });
      },
    } as unknown as R2Bucket;
    const app = createApiApp(() => store);
    const res = await app.request(`/executors/callback/${ID}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        artifacts: [{
          tool: "alterx", format: "json",
          data: [{ host: "x.example.com", a: ["1.2.3.4"] }],
          raw: "x.example.com\ny.example.com\n",
        }],
      }),
    }, env);
    expect(res.status).toBe(200);
    expect(puts.length).toBe(1);
    expect(puts[0]!.body).toBe("x.example.com\ny.example.com\n");
    expect(puts[0]!.key.endsWith(".txt")).toBe(true);
    expect(puts[0]!.type).toContain("text/plain");
    expect((await store.listAssets(ID)).map((a) => a.value)).toEqual(["x.example.com"]);
  });
});

describe("callback findings routing", () => {
  const ID = "0123456789abcdef0123456789abcdef";

  it("ingests findings for a registry findings artifact and counts them in the event", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running", "invasion");
    env.SCAN_COORDINATOR = acceptingDo;
    const puts: { key: string; body: string }[] = [];
    env.ARTIFACTS = {
      put: async (key: string, body: string) => { puts.push({ key, body }); },
    } as unknown as R2Bucket;
    const app = createApiApp(() => store);

    const res = await app.request(`/executors/callback/${ID}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ artifacts: [{ tool: "nuclei", format: "jsonl", data: [nucleiRecord()] }] }),
    }, env);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, assets: 0, findings: 1 });
    expect((await store.get(ID))!.status).toBe("completed");

    const findings = await store.listFindings(ID);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ scanId: ID, tool: "nuclei", severity: "high", url: "https://x.example/a" });
    // The raw artifact is stored before ingestion and the finding points at it.
    expect(puts).toHaveLength(1);
    expect(findings[0]!.rawRef).toBe(puts[0]!.key);
    expect(puts[0]!.key.startsWith(`scans/${ID}/raw/nuclei-`)).toBe(true);
    expect(JSON.parse(puts[0]!.body)).toEqual([nucleiRecord()]);

    const completed = (await store.events(ID)).find((e) => e.event === "completed");
    expect(completed?.detail).toContain("1 findings");
    expect(completed?.detail).toContain("0 assets");
  });

  it("keeps the asset path for assets tools and for a tool the registry does not know", async () => {
    const { env, store } = harness();
    await seed(store, ID, "running");
    env.SCAN_COORDINATOR = acceptingDo;
    env.ARTIFACTS = { put: async () => {} } as unknown as R2Bucket;
    const app = createApiApp(() => store);

    const res = await app.request(`/executors/callback/${ID}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        artifacts: [
          { tool: "subfinder", format: "json", data: [{ host: "x.example.com" }] },
          { tool: "legacy-scanner", format: "json", data: [{ anything: true }] },
        ],
      }),
    }, env);

    // The unknown tool resolves no asset normalizer but must not be routed
    // into the findings path (nor fail the callback): old executors keep working.
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, assets: 1, findings: 0 });
    expect((await store.listAssets(ID)).map((a) => a.value)).toEqual(["x.example.com"]);
    expect(await store.listFindings(ID)).toEqual([]);
  });
});

describe("retry", () => {
  const ID = "0123456789abcdef0123456789abcdef";

  it("re-runs a failed scan as a new linked scan", async () => {
    const { env, store, dispatches } = harness();
    await seed(store, ID, "failed");
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${ID}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; status: string };
    expect(body.id).not.toBe(ID);
    expect(body.status).toBe("running");
    const copy = (await store.get(body.id))!;
    expect(copy.parentScanId).toBe(ID);
    expect(copy.target).toBe("https://example.com/");
    expect((await store.events(ID)).some((e) => e.event === "retried" && e.detail === body.id)).toBe(true);
    expect((await store.events(body.id))[0]!.detail).toContain(`retry:${ID}`);
    expect(dispatches).toHaveLength(1);
  });

  it("re-runs a cancelled scan", async () => {
    const { env, store } = harness();
    await seed(store, ID, "cancelled");
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${ID}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(201);
  });

  it("refuses to re-run a completed scan", async () => {
    const { env, store } = harness();
    await seed(store, ID, "completed");
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${ID}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(409);
  });

  it("404s an unknown scan", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${"0".repeat(32)}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(404);
  });
});

describe("dispatch terminal-state guard", () => {
  it("a cancel landing during dispatch is not overwritten by running", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);
    // The GitHub dispatch request is pending; a cancel lands before it resolves.
    vi.stubGlobal("fetch", async () => {
      const [rec] = await store.list(10);
      await store.transition(rec!.id, ["queued", "running"], "cancelled");
      return new Response(null, { status: 204 });
    });
    const res = await app.request("/scans", {
      method: "POST", headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ target: "https://example.com" }),
    }, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; status: string };
    expect(body.status).toBe("cancelled");
    expect((await store.get(body.id))!.status).toBe("cancelled");
  });
});

// ---------------------------------------------------------------------------
// Invasion: authorization, target selection, findings, SARIF (spec Sections 1
// and 4). Shared fixtures keep every rejection test on the same valid base
// payload, so a failing status is attributable to the one field under test.
// ---------------------------------------------------------------------------

const PARENT = "e".repeat(32);
const KEPT = ["https://example.com/login", "https://example.com/admin"] as const;

function asset(scanId: string, type: Asset["type"], value: string, statusCode: number | null = null): Asset {
  return {
    id: `asset-${value}`, scanId, type, value,
    metadata: statusCode === null ? null : JSON.stringify({ status_code: statusCode }),
    createdAt: "2026-11-23T00:00:00.000Z",
  };
}

/** A completed explore scan plus the assets the invasion selection hygiene reads. */
async function seedParent(
  store: ScanStore,
  overrides: { id?: string; status?: ScanRecord["status"]; assets?: Asset[] } = {},
): Promise<string> {
  const id = overrides.id ?? PARENT;
  await seed(store, id, overrides.status ?? "completed", "explore");
  await store.insertAssets(overrides.assets ?? [
    asset(id, "url", KEPT[0], 200),
    asset(id, "url", KEPT[1], 204),
  ]);
  return id;
}

function invasionPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    phase: "invasion",
    parentScanId: PARENT,
    targets: [...KEPT],
    tools: ["nuclei", "zap-baseline"],
    options: { severity: "critical,high" },
    authorization: { confirmed: true },
    ...overrides,
  };
}

async function postJson(
  app: ReturnType<typeof createApiApp>,
  env: Env,
  path: string,
  body: unknown,
  headers: Record<string, string> = auth,
): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(body),
  }, env);
}

function finding(scanId: string, id: string, severity: Severity, createdAt: string, tool = "nuclei"): Finding {
  return {
    id, scanId, tool, severity, confidence: "high", title: `title-${id}`, description: "",
    url: "https://example.com/", parameter: null, evidence: null, cwe: null,
    remediation: null, rawRef: null, createdAt,
  };
}

describe("invasion create validation", () => {
  it("rejects a create without a confirmed authorization", async () => {
    for (const authorization of [undefined, { confirmed: false }, { confirmed: "true" }]) {
      const { env, store, doCalls } = harness();
      await seedParent(store);
      const app = createApiApp(() => store);

      const res = await postJson(app, env, "/scans", invasionPayload({
        parentScanId: undefined, target: "https://example.com", targets: ["https://example.com/"],
        tools: ["nuclei"], authorization,
      }));

      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toContain("authorization.confirmed");
      expect(doCalls).toEqual([]);
      // Only the seeded parent exists; no invasion row was written.
      expect(await store.list(10)).toHaveLength(1);
    }
  });

  it("rejects targets that are not a subset of the allowed URLs", async () => {
    const { env, store, doCalls } = harness();
    await seedParent(store);
    const app = createApiApp(() => store);

    for (const targets of [["https://evil.example/"], [], [KEPT[0], "https://example.com/app.js"], "https://example.com/login"]) {
      const res = await postJson(app, env, "/scans", invasionPayload({ targets }));
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toContain("subset");
    }
    expect(doCalls).toEqual([]);
  });

  it("rejects more targets than the invasion cap", async () => {
    const { env, store, doCalls } = harness();
    const nine = Array.from({ length: 9 }, (_, i) => asset(PARENT, "url", `https://example.com/page-${i}`, 200));
    await seedParent(store, { assets: nine });
    const app = createApiApp(() => store);

    const res = await postJson(app, env, "/scans", invasionPayload({ targets: nine.map((a) => a.value) }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain("8");
    expect(doCalls).toEqual([]);
  });

  it("rejects a tool outside the invasion registry", async () => {
    const { env, store } = harness();
    await seedParent(store);
    const app = createApiApp(() => store);

    for (const tools of [[], ["subfinder"], ["sqlmap"], ["nuclei", "nuclei-extra"], "nuclei"]) {
      const res = await postJson(app, env, "/scans", invasionPayload({ tools }));
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toContain("Tools");
    }
  });

  it("rejects a malformed severity option", async () => {
    const { env, store } = harness();
    await seedParent(store);
    const app = createApiApp(() => store);

    for (const severity of ["critical,catastrophic", "", "critical,", "Critical", 5]) {
      const res = await postJson(app, env, "/scans", invasionPayload({ options: { severity } }));
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toContain("severity");
    }
  });

  it("rejects a parent that is missing, not explore, or not completed", async () => {
    const missing = harness();
    const missingApp = createApiApp(() => missing.store);
    const notFound = await postJson(missingApp, missing.env, "/scans", invasionPayload({ parentScanId: "f".repeat(32) }));
    expect(notFound.status).toBe(400);
    expect(((await notFound.json()) as { error: string }).error).toContain("Parent scan not found");

    const invasionParent = harness();
    await seed(invasionParent.store, PARENT, "completed", "invasion");
    const invasionRes = await postJson(createApiApp(() => invasionParent.store), invasionParent.env, "/scans", invasionPayload());
    expect(invasionRes.status).toBe(400);
    expect(((await invasionRes.json()) as { error: string }).error).toContain("explore");

    const running = harness();
    await seedParent(running.store, { status: "running" });
    const runningRes = await postJson(createApiApp(() => running.store), running.env, "/scans", invasionPayload());
    expect(runningRes.status).toBe(400);
    expect(((await runningRes.json()) as { error: string }).error).toContain("completed");
  });

  it("maps an authorization conflict to 409 without dispatching", async () => {
    const { env, store, doCalls } = harness();
    await seedParent(store);
    const conflicting = {
      ...store,
      createAuthorization: async () => { throw new Error("UNIQUE constraint failed"); },
    } as ScanStore;
    const app = createApiApp(() => conflicting);

    const res = await postJson(app, env, "/scans", invasionPayload());
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toContain("authorized");
    expect(doCalls).toEqual([]);
  });
});

describe("invasion create success", () => {
  it("creates a chained invasion, authorizes it and dispatches the selection", async () => {
    const { env, store, doCalls, doStarts, dispatches } = harness();
    await seedParent(store);
    const app = createApiApp(() => store);

    const before = Date.now();
    const res = await postJson(app, env, "/scans", invasionPayload());
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; status: string };
    expect(body.id).toMatch(/^[0-9a-f]{32}$/);
    expect(body.status).toBe("running");

    const rec = (await store.get(body.id))!;
    expect(rec.phase).toBe("invasion");
    // A chained scan attacks the same site its parent explored.
    expect(rec.target).toBe("https://example.com/");
    expect(rec.parentScanId).toBe(PARENT);

    const authorization = (await store.getAuthorization(body.id))!;
    expect(authorization).toMatchObject({
      scanId: body.id,
      // Bearer automation has no email; the row records that it was the shared key.
      email: "api-key",
      targets: [...KEPT],
      tools: ["nuclei", "zap-baseline"],
      active: false,
    });
    expect(authorization.confirmedAt).not.toBe("");

    expect(doCalls).toEqual(["/start"]);
    expect(doStarts).toEqual([{ path: "/start", body: { scanId: body.id, timeoutSeconds: 1800 } }]);

    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]!.url).toContain("aegis-invasion.yml");
    const inputs = dispatches[0]!.body.inputs;
    expect(inputs.phase).toBe("invasion");
    expect(JSON.parse(inputs.targets!)).toEqual([...KEPT]);
    expect(JSON.parse(inputs.tools!)).toEqual(["nuclei", "zap-baseline"]);
    expect(JSON.parse(inputs.options!)).toEqual({ severity: "critical,high" });
    expect(inputs.timeout_seconds).toBe("1800");
    // The callback token outlives the scan by the same 5-minute grace as explore.
    const expiresAt = Number(inputs.callback_token!.split(".")[1]);
    expect(expiresAt - before).toBeGreaterThanOrEqual(1800_000 + 300_000);
    expect(expiresAt - before).toBeLessThan(1800_000 + 300_000 + 10_000);

    const events = await store.events(body.id);
    expect(events.map((e) => e.event)).toEqual(["created", "authorized", "dispatched"]);
    expect(events[1]!.detail).toContain("api-key");
    expect(events[1]!.detail).toContain("targets=2");
    expect(events[1]!.detail).toContain("active=false");
  });

  it("creates a standalone invasion against the validated target", async () => {
    const { env, store, dispatches } = harness();
    const app = createApiApp(() => store);

    const res = await postJson(app, env, "/scans", {
      phase: "invasion", target: "https://example.com",
      targets: ["https://example.com/"], tools: ["nuclei"], authorization: { confirmed: true },
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string };

    const rec = (await store.get(body.id))!;
    expect(rec.target).toBe("https://example.com/");
    expect(rec.parentScanId).toBeNull();
    const authorization = (await store.getAuthorization(body.id))!;
    expect(authorization.targets).toEqual(["https://example.com/"]);
    expect(JSON.parse(dispatches[0]!.body.inputs.targets!)).toEqual(["https://example.com/"]);
    // No severity option: the executor applies its own default.
    expect(JSON.parse(dispatches[0]!.body.inputs.options!)).toEqual({});
  });

  it("derives the active timeout and active flag when zap-full is selected", async () => {
    const { env, store, doStarts, dispatches } = harness();
    await seedParent(store);
    const app = createApiApp(() => store);

    const res = await postJson(app, env, "/scans", invasionPayload({
      tools: ["nuclei", "zap-full"], options: {},
    }));
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string };

    expect((await store.getAuthorization(body.id))!.active).toBe(true);
    expect(doStarts[0]!.body.timeoutSeconds).toBe(3600);
    expect(dispatches[0]!.body.inputs.timeout_seconds).toBe("3600");
    const authorized = (await store.events(body.id)).find((e) => e.event === "authorized");
    expect(authorized?.detail).toContain("active=true");
  });

  it("records the signed-in operator's email on the authorization", async () => {
    const { env, store } = harness();
    await seedParent(store);
    const sessions = memorySessionStore();
    const token = "D".repeat(43);
    const now = Date.now();
    await sessions.create(await sha256Hex(token), "operator@example.com", now, now + 60_000);
    const app = createApiApp(() => store, () => sessions);

    const res = await postJson(app, env, "/scans", invasionPayload(), { cookie: `${SESSION_COOKIE}=${token}` });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string };
    expect((await store.getAuthorization(body.id))!.email).toBe("operator@example.com");
    expect((await store.events(body.id)).find((e) => e.event === "authorized")?.detail).toContain("operator@example.com");
  });
});

describe("invasion preview", () => {
  it("returns the kept and excluded assets of an explore scan", async () => {
    const { env, store } = harness();
    const assets = [
      asset(PARENT, "url", KEPT[0], 200),
      asset(PARENT, "url", "https://example.com/app.js", 200),
      asset(PARENT, "subdomain", "api.example.com"),
      asset(PARENT, "url", "https://example.com/stale", 500),
    ];
    await seedParent(store, { assets });
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${PARENT}/invasion-preview`, { headers: auth }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      targets: { url: string; type: string; statusCode: number | null }[];
      excluded: { url: string; reason: string }[];
      maxUrls: number;
    };
    expect(body.targets).toEqual([{ url: KEPT[0], type: "url", statusCode: 200 }]);
    expect(body.excluded).toHaveLength(3);
    expect(body.excluded).toEqual(expect.arrayContaining([
      { url: "https://example.com/app.js", reason: "static-asset" },
      { url: "api.example.com", reason: "not-url" },
      { url: "https://example.com/stale", reason: "not-live" },
    ]));
    expect(body.maxUrls).toBe(8);
  });

  it("404s a scan that is not an explore scan", async () => {
    const { env, store } = harness();
    const invasionId = "a".repeat(32);
    await seed(store, invasionId, "completed", "invasion");
    const app = createApiApp(() => store);

    for (const id of [invasionId, "0".repeat(32)]) {
      const res = await app.request(`/scans/${id}/invasion-preview`, { headers: auth }, env);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "Scan not found" });
    }
  });
});

describe("findings route", () => {
  it("returns findings severity-ranked then oldest first", async () => {
    const { env, store } = harness();
    const id = "b".repeat(32);
    await seed(store, id, "completed", "invasion");
    await store.insertFindings([
      finding(id, "f-info", "info", "2026-11-23T00:00:05.000Z", "zap-baseline"),
      finding(id, "f-critical", "critical", "2026-11-23T00:00:04.000Z"),
      finding(id, "f-medium", "medium", "2026-11-23T00:00:01.000Z", "zap-full"),
      finding(id, "f-high-late", "high", "2026-11-23T00:00:03.000Z"),
      finding(id, "f-low", "low", "2026-11-23T00:00:02.000Z", "zap-baseline"),
      finding(id, "f-high-early", "high", "2026-11-23T00:00:01.000Z"),
    ]);
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${id}/findings`, { headers: auth }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { findings: { id: string }[] };
    expect(body.findings.map((f) => f.id)).toEqual([
      "f-critical", "f-high-early", "f-high-late", "f-medium", "f-low", "f-info",
    ]);
  });

  it("404s an unknown scan", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${"0".repeat(32)}/findings`, { headers: auth }, env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Scan not found" });
  });
});

describe("sarif route", () => {
  it("exports stored findings as a SARIF attachment", async () => {
    const { env, store } = harness();
    const id = "c".repeat(32);
    await seed(store, id, "completed", "invasion");
    await store.insertFindings([
      finding(id, "s-low", "low", "2026-11-23T00:00:01.000Z", "zap-baseline"),
      finding(id, "s-critical", "critical", "2026-11-23T00:00:02.000Z"),
      finding(id, "s-medium", "medium", "2026-11-23T00:00:03.000Z", "zap-baseline"),
    ]);
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${id}/sarif`, { headers: auth }, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/sarif+json");
    const disposition = res.headers.get("content-disposition") ?? "";
    expect(disposition).toContain("attachment");
    expect(disposition).toContain(`aegis-${id.slice(0, 8)}.sarif`);

    const doc = (await res.json()) as {
      version: string;
      runs: { tool: { driver: { name: string } }; results: { level: string }[] }[];
    };
    expect(doc.version).toBe("2.1.0");
    expect(doc.runs.map((run) => run.tool.driver.name)).toEqual(["nuclei", "zap-baseline"]);
    expect(doc.runs[0]!.results[0]!.level).toBe("error");
    expect(doc.runs[1]!.results.map((r) => r.level)).toEqual(["warning", "note"]);
  });

  it("404s an unknown scan", async () => {
    const { env, store } = harness();
    const app = createApiApp(() => store);
    const res = await app.request(`/scans/${"0".repeat(32)}/sarif`, { headers: auth }, env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Scan not found" });
  });
});

describe("invasion retry", () => {
  const ORIG = "d".repeat(32);

  async function seedFailedInvasion(
    store: ScanStore,
    authorization: { targets: string[]; tools: string[]; active: boolean },
  ): Promise<void> {
    const now = new Date().toISOString();
    await store.create({
      id: ORIG, target: "https://example.com/", phase: "invasion", status: "failed", parentScanId: PARENT,
      executor: "github", externalUrl: null, createdAt: now, updatedAt: now, completedAt: null,
      error: "boom", options: JSON.stringify({ severity: "high,medium" }),
    });
    await store.createAuthorization({
      scanId: ORIG, email: "operator@example.com", confirmedAt: now, ...authorization,
    });
  }

  it("relaunches an invasion scan from its stored authorization", async () => {
    const { env, store, doStarts, dispatches } = harness();
    await seedParent(store);
    await seedFailedInvasion(store, { targets: [...KEPT], tools: ["nuclei", "zap-full"], active: true });
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${ORIG}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; status: string };
    expect(body.status).toBe("running");

    const copy = (await store.get(body.id))!;
    expect(copy.phase).toBe("invasion");
    expect(copy.target).toBe("https://example.com/");
    // The chained scan keeps pointing at the explore scan that allowed its URLs.
    expect(copy.parentScanId).toBe(PARENT);

    const authorization = (await store.getAuthorization(body.id))!;
    expect(authorization).toMatchObject({
      scanId: body.id,
      email: "operator@example.com",
      targets: [...KEPT],
      tools: ["nuclei", "zap-full"],
      active: true,
    });

    expect(doStarts[0]!.body.timeoutSeconds).toBe(3600);
    const inputs = dispatches[0]!.body.inputs;
    expect(JSON.parse(inputs.targets!)).toEqual([...KEPT]);
    expect(JSON.parse(inputs.tools!)).toEqual(["nuclei", "zap-full"]);
    expect(JSON.parse(inputs.options!)).toEqual({ severity: "high,medium" });
    expect(inputs.timeout_seconds).toBe("3600");

    const events = await store.events(body.id);
    expect(events.map((e) => e.event)).toEqual(["created", "authorized", "dispatched"]);
    expect(events[0]!.detail).toContain(`retry:${ORIG}`);
    expect((await store.events(ORIG)).some((e) => e.event === "retried" && e.detail === body.id)).toBe(true);
  });

  it("refuses to relaunch when a stored target is no longer allowed by the parent", async () => {
    const { env, store, dispatches } = harness();
    await seedParent(store);
    await seedFailedInvasion(store, {
      targets: ["https://example.com/removed"], tools: ["nuclei"], active: false,
    });
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${ORIG}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toContain("targets");
    expect(dispatches).toEqual([]);
  });

  it("refuses to relaunch an invasion scan with no stored authorization", async () => {
    const { env, store } = harness();
    const now = new Date().toISOString();
    await store.create({
      id: ORIG, target: "https://example.com/", phase: "invasion", status: "failed", parentScanId: null,
      executor: "github", externalUrl: null, createdAt: now, updatedAt: now, completedAt: null,
      error: "boom", options: null,
    });
    const app = createApiApp(() => store);

    const res = await app.request(`/scans/${ORIG}/retry`, { method: "POST", headers: auth }, env);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toContain("authorization");
  });
});