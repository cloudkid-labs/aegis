import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex } from "./auth";
import type { Env } from "./env";
import {
  OAUTH_COOKIE, handleGoogleCallback, handleGoogleStart, handleLogout, handleMe,
  isAllowedEmail, parseAllowlist, safeNext,
} from "./google-oidc";
import { SESSION_COOKIE, base64url, currentSession } from "./session";
import { memorySessionStore } from "./session-store";

vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(() => ({})),
  jwtVerify: vi.fn(),
}));
import { jwtVerify } from "jose";
const verifyMock = vi.mocked(jwtVerify);

const env = {
  GOOGLE_CLIENT_ID: "test-client-id",
  GOOGLE_CLIENT_SECRET: "test-client-secret",
  AEGIS_ORIGIN: "https://aegis.test",
  AEGIS_ALLOWED_EMAILS: "operator@example.com",
} as unknown as Env;

const FLOW = { state: "state-123", nonce: "nonce-456", verifier: "verifier-789", next: "/" };
function flowCookie(flow = FLOW): string {
  return `${OAUTH_COOKIE}=${base64url(new TextEncoder().encode(JSON.stringify(flow)))}`;
}
function callbackUrl(query: string): Request {
  return new Request(`https://aegis.test/auth/google/callback?${query}`, { headers: { cookie: flowCookie() } });
}
function stubTokenExchange() {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ id_token: "fake-id-token" }), { status: 200 }));
}
function verifiedPayload(overrides: Record<string, unknown> = {}) {
  verifyMock.mockResolvedValue({
    payload: { nonce: FLOW.nonce, sub: "google-sub", email: "operator@example.com", email_verified: true, ...overrides },
  } as never);
}
function sessionTokenFrom(res: Response): string | null {
  const joined = res.headers.get("set-cookie") ?? "";
  const m = joined.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  return m && m[1] ? m[1] : null;
}

afterEach(() => {
  vi.unstubAllGlobals();
  verifyMock.mockReset();
});

describe("safeNext", () => {
  it("only admits the dashboard root", () => {
    expect(safeNext("/")).toBe("/");
    for (const bad of ["/app", "//evil.com", "https://evil.com", "/\\evil.com", null, undefined, "/\u0000"]) {
      expect(safeNext(bad as string)).toBe("/");
    }
  });
});

describe("allowlist", () => {
  it("parses comma-separated emails, lowercased and trimmed", () => {
    expect(parseAllowlist(" A@x.com , b@y.com ,")).toEqual(new Set(["a@x.com", "b@y.com"]));
  });
  it("empty input is an empty set (deny-by-default)", () => {
    expect(parseAllowlist("").size).toBe(0);
    expect(parseAllowlist(undefined).size).toBe(0);
    expect(isAllowedEmail("anyone@example.com", parseAllowlist(""))).toBe(false);
  });
  it("matches case-insensitively", () => {
    expect(isAllowedEmail("Operator@Example.com", parseAllowlist("operator@example.com"))).toBe(true);
    expect(isAllowedEmail("other@example.com", parseAllowlist("operator@example.com"))).toBe(false);
  });
});

describe("handleGoogleStart", () => {
  it("503 when sign-in is not configured", async () => {
    const res = await handleGoogleStart(new Request("https://aegis.test/auth/google/start"), { ...env, GOOGLE_CLIENT_ID: "" } as Env);
    expect(res.status).toBe(503);
  });
  it("redirects to Google with PKCE and sets the flow cookie", async () => {
    const res = await handleGoogleStart(new Request("https://aegis.test/auth/google/start"), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin).toBe("https://accounts.google.com");
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    expect(loc.searchParams.get("redirect_uri")).toBe("https://aegis.test/auth/google/callback");
    expect(res.headers.get("set-cookie")).toContain(OAUTH_COOKIE);
  });
});

describe("handleGoogleCallback", () => {
  it("fails without a flow cookie", async () => {
    const res = await handleGoogleCallback(new Request("https://aegis.test/auth/google/callback?state=x&code=y"), env, memorySessionStore());
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/?signin=failed");
  });
  it("treats access_denied as cancelled, not an error", async () => {
    const res = await handleGoogleCallback(callbackUrl("error=access_denied"), env, memorySessionStore());
    expect(res.headers.get("location")).toBe("/?signin=cancelled");
  });
  it("fails on state mismatch", async () => {
    const res = await handleGoogleCallback(callbackUrl("state=wrong&code=y"), env, memorySessionStore());
    expect(res.headers.get("location")).toBe("/?signin=failed");
  });
  it("signs in an allowlisted, verified email and sets a session", async () => {
    stubTokenExchange();
    verifiedPayload();
    const store = memorySessionStore();
    const res = await handleGoogleCallback(callbackUrl(`state=${FLOW.state}&code=abc`), env, store, 1000);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
    const token = sessionTokenFrom(res);
    expect(token).toBeTruthy();
    // The stored hash resolves to the allowlisted email.
    const session = await store.get(await sha256Hex(token!), 1000);
    expect(session?.email).toBe("operator@example.com");
  });
  it("refuses a verified email that is not on the allowlist", async () => {
    stubTokenExchange();
    verifiedPayload({ email: "stranger@example.com" });
    const res = await handleGoogleCallback(callbackUrl(`state=${FLOW.state}&code=abc`), env, memorySessionStore());
    expect(res.headers.get("location")).toBe("/?signin=failed");
  });
  it("refuses an unverified email", async () => {
    stubTokenExchange();
    verifiedPayload({ email_verified: false });
    const res = await handleGoogleCallback(callbackUrl(`state=${FLOW.state}&code=abc`), env, memorySessionStore());
    expect(res.headers.get("location")).toBe("/?signin=failed");
  });
  it("refuses a nonce that does not match the flow", async () => {
    stubTokenExchange();
    verifiedPayload({ nonce: "different" });
    const res = await handleGoogleCallback(callbackUrl(`state=${FLOW.state}&code=abc`), env, memorySessionStore());
    expect(res.headers.get("location")).toBe("/?signin=failed");
  });
});

describe("handleLogout", () => {
  it("refuses a cross-site trigger", async () => {
    const res = await handleLogout(new Request("https://aegis.test/auth/logout", { headers: { "sec-fetch-site": "cross-site" } }), memorySessionStore());
    expect(res.status).toBe(403);
  });
  it("deletes the session and clears the cookie on a same-site navigation", async () => {
    const store = memorySessionStore();
    const token = "A".repeat(43);
    await store.create(await sha256Hex(token), "operator@example.com", 1000, 9_999_999);
    const req = new Request("https://aegis.test/auth/logout", {
      headers: { "sec-fetch-site": "same-origin", cookie: `${SESSION_COOKIE}=${token}` },
    });
    const res = await handleLogout(req, store);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
    expect(res.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await store.get(await sha256Hex(token), 1000)).toBeNull();
  });
});

describe("handleMe", () => {
  it("reports signed-out without a cookie", async () => {
    const res = await handleMe(new Request("https://aegis.test/auth/me"), memorySessionStore());
    expect(await res.json()).toEqual({ authenticated: false });
  });
  it("reports the signed-in email", async () => {
    const store = memorySessionStore();
    const token = "B".repeat(43);
    const now = Date.now();
    await store.create(await sha256Hex(token), "operator@example.com", now, now + 100_000);
    const req = new Request("https://aegis.test/auth/me", { headers: { cookie: `${SESSION_COOKIE}=${token}` } });
    expect(await handleMe(req, store).then((r) => r.json())).toEqual({ authenticated: true, email: "operator@example.com" });
    expect(await currentSession(req, store)).not.toBeNull();
  });
});