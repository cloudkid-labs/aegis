import { applyD1Migrations, env, runDurableObjectAlarm, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { signCallbackToken } from "./callback-token";
import type { Env } from "./env";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

function stub(scanId: string) {
  return testEnv.SCAN_COORDINATOR.get(testEnv.SCAN_COORDINATOR.idFromName(scanId));
}

async function seedScan(id: string, status: string): Promise<void> {
  const now = new Date().toISOString();
  await testEnv.AEGIS_DB.prepare(
    "INSERT INTO scans (id,target,phase,status,executor,created_at,updated_at) VALUES (?1,?2,'explore',?3,'github',?4,?4)",
  ).bind(id, "https://example.com", status, now).run();
}

function start(scanId: string, timeoutSeconds = 3600): Promise<Response> {
  return stub(scanId).fetch("https://do/start", {
    method: "POST",
    body: JSON.stringify({ scanId, timeoutSeconds }),
  });
}

function consume(scanId: string, token: string): Promise<Response> {
  return stub(scanId).fetch("https://do/consume", {
    method: "POST",
    body: JSON.stringify({ scanId, token }),
  });
}

describe("ScanCoordinator", () => {
  it("/start schedules an alarm and /consume accepts a valid token exactly once", async () => {
    await seedScan("s1", "running");
    expect((await start("s1")).status).toBe(200);

    const token = await signCallbackToken(testEnv.CALLBACK_SECRET, "s1", Date.now() + 60_000);
    expect((await consume("s1", token)).status).toBe(200);
    expect((await consume("s1", token)).status).toBe(409);
  });

  it("/consume rejects a bad or foreign token", async () => {
    expect((await consume("s2", "v1.999.bad")).status).toBe(401);

    const foreign = await signCallbackToken(testEnv.CALLBACK_SECRET, "someone-else", Date.now() + 60_000);
    expect((await consume("s2", foreign)).status).toBe(401);

    const expired = await signCallbackToken(testEnv.CALLBACK_SECRET, "s2", Date.now() - 1);
    expect((await consume("s2", expired)).status).toBe(401);
  });

  it("/consume rejects malformed bodies and non-POST methods", async () => {
    const invalidJson = await stub("s2b").fetch("https://do/consume", { method: "POST", body: "{" });
    expect(invalidJson.status).toBe(400);

    const noToken = await stub("s2b").fetch("https://do/consume", {
      method: "POST",
      body: JSON.stringify({ scanId: "s2b" }),
    });
    expect(noToken.status).toBe(400);

    const wrongMethod = await stub("s2b").fetch("https://do/consume");
    expect(wrongMethod.status).toBe(405);

    const unknownRoute = await stub("s2b").fetch("https://do/nope", { method: "POST" });
    expect(unknownRoute.status).toBe(404);
  });

  it("/start validates its body", async () => {
    const missing = await stub("s2c").fetch("https://do/start", {
      method: "POST",
      body: JSON.stringify({ timeoutSeconds: 60 }),
    });
    expect(missing.status).toBe(400);

    const negative = await stub("s2c").fetch("https://do/start", {
      method: "POST",
      body: JSON.stringify({ scanId: "s2c", timeoutSeconds: -1 }),
    });
    expect(negative.status).toBe(400);

    const tooLong = await stub("s2c").fetch("https://do/start", {
      method: "POST",
      body: JSON.stringify({ scanId: "s2c", timeoutSeconds: 86_401 }),
    });
    expect(tooLong.status).toBe(400);
  });

  it("the alarm marks a still-running scan failed with timeout", async () => {
    await seedScan("s3", "running");
    await start("s3");

    expect(await runDurableObjectAlarm(stub("s3"))).toBe(true);

    const row = await testEnv.AEGIS_DB.prepare("SELECT status, error FROM scans WHERE id='s3'")
      .first<{ status: string; error: string }>();
    expect(row!.status).toBe("failed");
    expect(row!.error).toBe("timeout");

    const event = await testEnv.AEGIS_DB.prepare(
      "SELECT event, detail FROM scan_events WHERE scan_id='s3'",
    ).first<{ event: string; detail: string }>();
    expect(event!.event).toBe("failed");
    expect(event!.detail).toBe("timeout");
  });

  it("the alarm also fails a scan still queued", async () => {
    await seedScan("s3b", "queued");
    await start("s3b");
    await runDurableObjectAlarm(stub("s3b"));

    const row = await testEnv.AEGIS_DB.prepare("SELECT status FROM scans WHERE id='s3b'")
      .first<{ status: string }>();
    expect(row!.status).toBe("failed");
  });

  it("the alarm leaves a completed scan alone", async () => {
    await seedScan("s4", "completed");
    await start("s4");

    expect(await runDurableObjectAlarm(stub("s4"))).toBe(true);

    const row = await testEnv.AEGIS_DB.prepare("SELECT status, error FROM scans WHERE id='s4'")
      .first<{ status: string; error: string | null }>();
    expect(row!.status).toBe("completed");
    expect(row!.error).toBeNull();
    expect(await testEnv.AEGIS_DB.prepare("SELECT COUNT(*) AS n FROM scan_events WHERE scan_id='s4'")
      .first<{ n: number }>()).toEqual({ n: 0 });
  });

  it("/cancel removes the pending alarm", async () => {
    await start("s5");
    const cancelled = await stub("s5").fetch("https://do/cancel", { method: "POST" });
    expect(cancelled.status).toBe(200);

    expect(await runDurableObjectAlarm(stub("s5"))).toBe(false);
  });
});