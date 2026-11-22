import { describe, expect, it } from "vitest";
import { withSecurityHeaders } from "./security-headers";

describe("withSecurityHeaders", () => {
  it("sets strict CSP and frame protection", () => {
    const res = withSecurityHeaders(new Response("ok"));
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("preserves body and status", async () => {
    const res = withSecurityHeaders(new Response("body", { status: 201 }));
    expect(res.status).toBe(201);
    expect(await res.text()).toBe("body");
  });
});