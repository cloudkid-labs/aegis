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

  it("unknown API paths answer JSON, never the static shell", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/api/nope"), baseEnv as never);
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ error: "Not found" });
  });

  it("bare /api is an app route", async () => {
    const res = await worker.fetch(new Request("https://aegis.test/api"), baseEnv as never);
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
  });

  it("static paths reach ASSETS untouched", async () => {
    const asked: string[] = [];
    const env = {
      AEGIS_API_KEY: "test-key",
      ASSETS: {
        fetch: async (req: Request) => {
          asked.push(new URL(req.url).pathname);
          return new Response("<html>Aegis</html>", { status: 200, headers: { "content-type": "text/html" } });
        },
      },
    };
    const res = await worker.fetch(new Request("https://aegis.test/_astro/app.css"), env as never);
    expect(asked).toEqual(["/_astro/app.css"]);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("<html>Aegis</html>");
    // Security headers are stamped on static responses too.
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("the allowlist is narrow: /health/ready is not an app route", async () => {
    const asked: string[] = [];
    const env = {
      AEGIS_API_KEY: "test-key",
      ASSETS: {
        fetch: async (req: Request) => {
          asked.push(new URL(req.url).pathname);
          return new Response("asset", { status: 200 });
        },
      },
    };
    const res = await worker.fetch(new Request("https://aegis.test/health/ready"), env as never);
    expect(asked).toEqual(["/health/ready"]);
    expect(await res.text()).toBe("asset");
  });
});