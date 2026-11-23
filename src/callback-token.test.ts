import { describe, expect, it } from "vitest";
import { signCallbackToken, verifyCallbackToken } from "./callback-token";

const SECRET = "callback-secret";
const SCAN = "scan-123";
const NOW = 1_700_000_000_000;

describe("callback tokens", () => {
  it("signs and verifies", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    expect(token).toMatch(/^v1\.\d+\.[0-9a-f]{64}$/);
    expect(await verifyCallbackToken(SECRET, SCAN, token, NOW)).toBe(true);
  });

  it("is deterministic for the same inputs", async () => {
    const a = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    const b = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    expect(a).toBe(b);
  });

  it("accepts a token that expires exactly now and rejects one millisecond later", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW);
    expect(await verifyCallbackToken(SECRET, SCAN, token, NOW)).toBe(true);
    expect(await verifyCallbackToken(SECRET, SCAN, token, NOW + 1)).toBe(false);
  });

  it("rejects an expired token", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW - 1);
    expect(await verifyCallbackToken(SECRET, SCAN, token, NOW)).toBe(false);
  });

  it("rejects a tampered signature", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    const tampered = token.slice(0, -1) + (token.endsWith("0") ? "1" : "0");
    expect(await verifyCallbackToken(SECRET, SCAN, tampered, NOW)).toBe(false);
  });

  it("rejects a tampered expiry, because it is part of the signed message", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW + 1_000);
    const parts = token.split(".");
    parts[1] = String(NOW + 999_000);
    expect(await verifyCallbackToken(SECRET, SCAN, parts.join("."), NOW)).toBe(false);
  });

  it("rejects a token for a different scan", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    expect(await verifyCallbackToken(SECRET, "other-scan", token, NOW)).toBe(false);
  });

  it("rejects a wrong secret", async () => {
    const token = await signCallbackToken(SECRET, SCAN, NOW + 60_000);
    expect(await verifyCallbackToken("wrong-secret", SCAN, token, NOW)).toBe(false);
  });

  it("rejects malformed tokens", async () => {
    expect(await verifyCallbackToken(SECRET, SCAN, "", NOW)).toBe(false);
    expect(await verifyCallbackToken(SECRET, SCAN, "garbage", NOW)).toBe(false);
    expect(await verifyCallbackToken(SECRET, SCAN, "v2.123.abc", NOW)).toBe(false);
    expect(await verifyCallbackToken(SECRET, SCAN, `v1.abc.${"0".repeat(64)}`, NOW)).toBe(false);
    expect(await verifyCallbackToken(SECRET, SCAN, `v1.123.${"0".repeat(63)}`, NOW)).toBe(false);
    expect(await verifyCallbackToken(SECRET, SCAN, `v1.123.${"0".repeat(64)}.extra`, NOW)).toBe(false);
  });

  it("rejects an expiry that overflows a safe integer", async () => {
    expect(await verifyCallbackToken(SECRET, SCAN, `v1.99999999999999999999.${"0".repeat(64)}`, NOW)).toBe(false);
  });
});