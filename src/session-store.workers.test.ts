import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll } from "vitest";
import type { Env } from "./env";
import { d1SessionStore } from "./session-store";
import { describeSessionStoreContract } from "./test-support/session-store-contract";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

describeSessionStoreContract("D1 AEGIS_DB", () => d1SessionStore(testEnv.AEGIS_DB));