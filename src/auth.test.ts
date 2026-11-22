import { describe, expect, it } from "vitest";
import { constantTimeEqual, isAuthorized, sha256Hex } from "./auth";

function request(headers: Record<string, string> = {}): Request {
  return new Request("https://aegis.test/api/scans", { headers });
}

const KEY = "secret-key-123";

describe("isAuthorized", () => {
  it("accepts the correct bearer key", async () => {
    expect(await isAuthorized(request({ authorization: `Bearer ${KEY}` }), KEY)).toBe(true);
  });

  it("rejects a wrong key", async () => {
    expect(await isAuthorized(request({ authorization: "Bearer wrong" }), KEY)).toBe(false);
  });

  it("rejects a key that only shares a prefix", async () => {
    expect(await isAuthorized(request({ authorization: `Bearer ${KEY.slice(0, -1)}` }), KEY)).toBe(false);
  });

  it("rejects a missing header", async () => {
    expect(await isAuthorized(request(), KEY)).toBe(false);
  });

  it("rejects a non-bearer scheme", async () => {
    expect(await isAuthorized(request({ authorization: `Basic ${KEY}` }), KEY)).toBe(false);
    expect(await isAuthorized(request({ authorization: `bearer ${KEY}` }), KEY)).toBe(false);
  });

  it("rejects when no expected key is configured", async () => {
    expect(await isAuthorized(request({ authorization: "Bearer anything" }), "")).toBe(false);
  });
});

describe("constantTimeEqual", () => {
  it("compares equal strings", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
  });

  it("rejects different strings of the same length", () => {
    expect(constantTimeEqual("abc", "abd")).toBe(false);
  });

  it("rejects different lengths", () => {
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
    expect(constantTimeEqual("", "a")).toBe(false);
  });

  it("treats two empty strings as equal", () => {
    expect(constantTimeEqual("", "")).toBe(true);
  });
});

describe("sha256Hex", () => {
  it("produces lowercase hex of the known digest", async () => {
    // SHA-256("test") — pins the encoding, not just the length.
    expect(await sha256Hex("test")).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );
  });

  it("matches the 64-char hex shape", async () => {
    expect(await sha256Hex("anything")).toMatch(/^[0-9a-f]{64}$/);
  });
});