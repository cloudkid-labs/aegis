import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { Env } from "./env";
import { d1ScanStore } from "./scan-store";
import { describeScanStoreContract } from "./test-support/scan-store-contract";

/**
 * The D1 half of the contract: miniflare's local D1 with the real migrations
 * applied, read from migrations/ by vitest.config.mts into TEST_MIGRATIONS.
 * If memoryScanStore and this disagree, the fake is wrong.
 */
type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

describeScanStoreContract("D1 AEGIS_DB", () => d1ScanStore(testEnv.AEGIS_DB));

/**
 * A corrupt row can only be produced by writing around the store: the memory
 * fake stores arrays, so this belongs here rather than in the shared
 * contract. A row that cannot be read back as two lists is no authorization.
 */
describe("D1 corrupt authorization rows", () => {
  async function insertRow(id: string, targets: string, tools: string): Promise<void> {
    await testEnv.AEGIS_DB
      .prepare(
        "INSERT INTO scan_authorizations (scan_id, email, targets, tools, active, confirmed_at) VALUES (?1,?2,?3,?4,?5,?6)",
      )
      .bind(id, "op@example.com", targets, tools, 0, "2026-11-23T00:00:00.000Z")
      .run();
  }

  it("treats an unparseable targets list as no authorization", async () => {
    await insertRow("corrupt-targets", '{"not": "an array"', '["nuclei"]');
    expect(await d1ScanStore(testEnv.AEGIS_DB).getAuthorization("corrupt-targets")).toBeNull();
  });

  it("treats an unparseable tools list as no authorization", async () => {
    await insertRow("corrupt-tools", '["https://example.com/"]', "nuclei, zap-baseline");
    expect(await d1ScanStore(testEnv.AEGIS_DB).getAuthorization("corrupt-tools")).toBeNull();
  });

  it("treats parsed non-array JSON as no authorization", async () => {
    await insertRow("corrupt-scalar", '"https://example.com/"', '["nuclei"]');
    expect(await d1ScanStore(testEnv.AEGIS_DB).getAuthorization("corrupt-scalar")).toBeNull();
  });
});