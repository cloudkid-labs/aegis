import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex } from "../auth";
import type { Env } from "../env";
import type { ScanStore } from "../scan-store";
import { SESSION_COOKIE } from "../session";
import { memorySessionStore } from "../session-store";
import { nucleiRecord } from "../test-support/fixtures";
import { memoryScanStore } from "../test-support/memory-store";
import type { ScanRecord } from "../types";
import { createApiApp } from "./api";

const KEY = "test-key";
const auth = { authorization: `Bearer ${KEY}` };

interface Harness {
  env: Env;
  store: ScanStore;
  /** Durable Object routes hit, e.g. "/start" or "/consume". */
  doCalls: string[];
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
    SCAN_LIMITER: { limit: async () => ({ success: true }) },
    SCAN_COORDINATOR: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: async (input: RequestInfo | URL) => {
          const path = new URL(String(input)).pathname;
          doCalls.push(path);
          return new Response(null, { status: path === "/consume" ? 401 : 200 });
        },
      }),
    },
    ...overrides,
  } as unknown as Env;
  return { env, store: memoryScanStore(), doCalls, dispatches };
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
    const { env, store, doCalls, dispatches } = harness();
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
    expect(dispatches).toHaveLength(1);
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