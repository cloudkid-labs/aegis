import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll } from "vitest";
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