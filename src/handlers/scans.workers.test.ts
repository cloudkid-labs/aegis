import { applyD1Migrations, env, SELF, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { Env } from "../env";
import { d1ScanStore } from "../scan-store";

/**
 * Invasion rejection paths over the real Worker entry, the real wrangler.jsonc
 * and a local D1 with the real migrations. The node project pins each rule
 * against a fake store; this proves the same validation runs when the request
 * crosses SELF.fetch and that a rejected create leaves no scan row behind.
 */
type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

// The workers project's AEGIS_API_KEY comes from vitest.config.mts bindings.
const AUTH = { authorization: "Bearer test-api-key", "content-type": "application/json" };

/**
 * A completed explore scan with live URL assets. Only a parent can widen the
 * allowed set beyond one URL, which the cap and subset rules need.
 */
async function seedParent(id: string, urls: string[]): Promise<void> {
  const store = d1ScanStore(testEnv.AEGIS_DB);
  const at = new Date().toISOString();
  await store.create({
    id, target: "https://example.com/", phase: "explore", status: "completed",
    parentScanId: null, executor: "github", externalUrl: null, createdAt: at,
    updatedAt: at, completedAt: at, error: null, options: null,
  });
  await store.insertAssets(urls.map((url, i) => ({
    id: `${id}-${i}`, scanId: id, type: "url" as const, value: url,
    metadata: JSON.stringify({ status_code: 200 }), createdAt: at,
  })));
}

function create(body: unknown): Promise<Response> {
  return SELF.fetch("https://aegis.test/api/scans", {
    method: "POST", headers: AUTH, body: JSON.stringify(body),
  });
}

async function invasionRowCount(): Promise<number> {
  const scans = await d1ScanStore(testEnv.AEGIS_DB).list(50);
  return scans.filter((scan) => scan.phase === "invasion").length;
}

describe("invasion create rejection through the Worker", () => {
  it("rejects an unconfirmed create with 400 and writes no scan", async () => {
    const parent = "a1".repeat(16);
    const urls = ["https://example.com/one", "https://example.com/two"];
    await seedParent(parent, urls);

    const res = await create({
      phase: "invasion", parentScanId: parent, targets: urls, tools: ["nuclei"],
      authorization: { confirmed: false },
    });

    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain("authorization.confirmed");
    expect(await invasionRowCount()).toBe(0);
  });

  it("rejects more targets than the cap with 400 and writes no scan", async () => {
    const parent = "b2".repeat(16);
    const urls = Array.from({ length: 9 }, (_, i) => `https://example.com/page-${i}`);
    await seedParent(parent, urls);

    const res = await create({
      phase: "invasion", parentScanId: parent, targets: urls, tools: ["nuclei"],
      authorization: { confirmed: true },
    });

    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain("8");
    expect(await invasionRowCount()).toBe(0);
  });

  it("rejects targets outside the parent's live URL set with 400", async () => {
    const parent = "c3".repeat(16);
    const urls = ["https://example.com/one", "https://example.com/two"];
    await seedParent(parent, urls);

    const res = await create({
      phase: "invasion", parentScanId: parent,
      targets: ["https://example.com/one", "https://example.com/elsewhere"],
      tools: ["nuclei"], authorization: { confirmed: true },
    });

    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain("subset");
    expect(await invasionRowCount()).toBe(0);
  });
});