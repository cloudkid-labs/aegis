import { applyD1Migrations, env, SELF, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { signCallbackToken } from "../callback-token";
import type { Env } from "../env";
import { d1ScanStore } from "../scan-store";
import { nucleiRecord, zapReport } from "../test-support/fixtures";

/**
 * End-to-end ingestion: the callback route over the real Worker entry, the
 * real Durable Object consuming the token, and real D1/R2 bindings. The node
 * project covers routing with fakes; this proves the findings actually land
 * in the store the dashboard reads.
 */
type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

const ID = "0123456789abcdef0123456789abcdef";

async function seedScan(id: string, status: "running" | "completed"): Promise<void> {
  const now = new Date().toISOString();
  await d1ScanStore(testEnv.AEGIS_DB).create({
    id, target: "https://example.com/", phase: "invasion", status,
    parentScanId: null, executor: "github", externalUrl: null, createdAt: now,
    updatedAt: now, completedAt: null, error: null, options: null,
  });
}

function callback(id: string, token: string, body: unknown): Promise<Response> {
  return SELF.fetch(`https://aegis.test/api/executors/callback/${id}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("executor callback findings ingestion", () => {
  it("persists nuclei and ZAP findings in D1 and R2, deduping repeated ids", async () => {
    await seedScan(ID, "running");

    // Same pattern as src/scan-coordinator.workers.test.ts: start the DO so it
    // holds the scan's deadline, then sign the token the executor would hold.
    const stub = testEnv.SCAN_COORDINATOR.get(testEnv.SCAN_COORDINATOR.idFromName(ID));
    const started = await stub.fetch("https://do/start", {
      method: "POST",
      body: JSON.stringify({ scanId: ID, timeoutSeconds: 600 }),
    });
    expect(started.status).toBe(200);
    const token = await signCallbackToken(testEnv.CALLBACK_SECRET, ID, Date.now() + 60_000);

    const res = await callback(ID, token, {
      artifacts: [
        { tool: "nuclei", format: "jsonl", data: [nucleiRecord()] },
        { tool: "zap-baseline", format: "json", data: zapReport() },
        // Same structured record again: identical finding id, so the second
        // insert must update the row rather than add one.
        { tool: "nuclei", format: "jsonl", data: [nucleiRecord()] },
      ],
    });

    expect(res.status).toBe(200);
    // Counts are of normalized findings; dedupe is the store's job on insert.
    expect(await res.json()).toEqual({ ok: true, assets: 0, findings: 3 });

    const store = d1ScanStore(testEnv.AEGIS_DB);
    const findings = await store.listFindings(ID);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.tool).sort()).toEqual(["nuclei", "zap-baseline"]);
    expect(findings.find((f) => f.tool === "nuclei")).toMatchObject({
      scanId: ID, severity: "high", url: "https://x.example/a", evidence: "proof", cwe: 79,
    });
    expect(findings.find((f) => f.tool === "zap-baseline")).toMatchObject({
      scanId: ID, severity: "medium", url: "https://x.example/", cwe: 693,
    });

    // rawRef points at the artifact that was really written to R2.
    for (const finding of findings) {
      expect(finding.rawRef).toMatch(new RegExp(`^scans/${ID}/raw/${finding.tool}-\\d+\\.json$`));
      expect(await testEnv.ARTIFACTS.head(finding.rawRef!)).not.toBeNull();
    }

    expect((await store.get(ID))!.status).toBe("completed");
    const completed = (await store.events(ID)).find((e) => e.event === "completed");
    expect(completed?.detail).toBe("0 assets; 3 findings");
  });

  it("rejects a replayed callback token with 409 while the scan is still running", async () => {
    const replayId = "00112233445566778899aabbccddeeff";
    await seedScan(replayId, "running");
    const stub = testEnv.SCAN_COORDINATOR.get(testEnv.SCAN_COORDINATOR.idFromName(replayId));
    expect((await stub.fetch("https://do/start", {
      method: "POST",
      body: JSON.stringify({ scanId: replayId, timeoutSeconds: 600 }),
    })).status).toBe(200);
    const token = await signCallbackToken(testEnv.CALLBACK_SECRET, replayId, Date.now() + 60_000);

    // The route consumes the token before it parses the body, so a truncated
    // upload burns the token and leaves the scan running. Replaying right after
    // a completed scan would hit the terminal guard first and never exercise
    // the single-use check; this is the reachable non-terminal replay.
    const truncated = await SELF.fetch(`https://aegis.test/api/executors/callback/${replayId}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: "{",
    });
    expect(truncated.status).toBe(400);
    expect(await truncated.json()).toEqual({ error: "Invalid JSON" });

    const replay = await callback(replayId, token, {
      artifacts: [{ tool: "nuclei", format: "jsonl", data: [nucleiRecord()] }],
    });
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual({ error: "Callback already consumed" });

    const store = d1ScanStore(testEnv.AEGIS_DB);
    expect((await store.get(replayId))!.status).toBe("running");
    expect(await store.listFindings(replayId)).toEqual([]);
  });

  it("answers a late callback for a completed scan with 409 and stores nothing", async () => {
    const completedId = "fedcba9876543210fedcba9876543210";
    await seedScan(completedId, "completed");
    const token = await signCallbackToken(testEnv.CALLBACK_SECRET, completedId, Date.now() + 60_000);

    const res = await callback(completedId, token, {
      artifacts: [{ tool: "nuclei", format: "jsonl", data: [nucleiRecord()] }],
    });

    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "Scan already terminal" });
    expect(await d1ScanStore(testEnv.AEGIS_DB).listFindings(completedId)).toEqual([]);
  });
});