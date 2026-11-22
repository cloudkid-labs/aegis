import { describe, expect, it } from "vitest";
import worker from "./index";

const fakeAssets = { fetch: async () => new Response("404", { status: 404 }) };
const baseEnv = { ASSETS: fakeAssets, AEGIS_API_KEY: "test-key" } as unknown as Record<string, unknown>;

describe("routing", () => {
  it("GET /health returns 202 with JSON", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/health"), baseEnv as never);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("unknown paths fall through to assets", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/nope"), baseEnv as never);
    expect(res.status).toBe(404);
  });

  it("API requires auth", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/api/scans"), baseEnv as never);
    expect(res.status).toBe(401);
  });

  it("API with wrong key returns 401", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/api/scans", { headers: { authorization: "Bearer wrong" } }), baseEnv as never);
    expect(res.status).toBe(401);
  });

  it("sets security headers on all responses", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/health"), baseEnv as never);
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });
});