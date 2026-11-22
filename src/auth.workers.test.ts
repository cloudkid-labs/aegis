import { applyD1Migrations, env, SELF, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { sha256Hex } from "./auth";
import type { Env } from "./env";
import { SESSION_COOKIE } from "./session";
import { d1SessionStore } from "./session-store";

/**
 * The auth routes against the real wrangler.jsonc and a local D1 with the real
 * migrations. The Google token exchange itself is covered by the node unit
 * tests (mocked jose); here we pin routing, the public sign-in state, and that
 * a session row in D1 actually admits the operator API and is deletable.
 */
type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as unknown as TestEnv;

beforeAll(async () => {
  await applyD1Migrations(testEnv.AEGIS_DB, testEnv.TEST_MIGRATIONS);
});

describe("auth routes", () => {
  it("/auth/me is public and reports signed-out", async () => {
    const res = await SELF.fetch("https://aegis.test/auth/me");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ authenticated: false });
  });

  it("/auth/google/start redirects to Google (client id configured)", async () => {
    const res = await SELF.fetch("https://aegis.test/auth/google/start", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).origin).toBe("https://accounts.google.com");
  });

  it("a D1 session admits the operator API and logout deletes it", async () => {
    const store = d1SessionStore(testEnv.AEGIS_DB);
    const token = "D".repeat(43);
    const now = Date.now();
    await store.create(await sha256Hex(token), "operator@example.com", now, now + 100_000);
    const cookie = `${SESSION_COOKIE}=${token}`;

    const me = await SELF.fetch("https://aegis.test/auth/me", { headers: { cookie } });
    expect(await me.json()).toEqual({ authenticated: true, email: "operator@example.com" });

    const scans = await SELF.fetch("https://aegis.test/api/scans", { headers: { cookie } });
    expect(scans.status).toBe(200);

    const out = await SELF.fetch("https://aegis.test/auth/logout", {
      headers: { cookie, "sec-fetch-site": "same-origin" },
      redirect: "manual",
    });
    expect(out.status).toBe(302);
    expect(await store.get(await sha256Hex(token), Date.now())).toBeNull();

    const after = await SELF.fetch("https://aegis.test/api/scans", { headers: { cookie } });
    expect(after.status).toBe(401);
  });
});