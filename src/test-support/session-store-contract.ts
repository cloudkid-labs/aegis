import { describe, expect, it } from "vitest";
import type { SessionStore } from "../session-store";

/**
 * One spec run against both the memory fake (node) and real D1 (workers), so
 * a fake that drifts from the SQL is a red test rather than a new de-facto
 * spec. Asserts only what holds in BOTH.
 */
export function describeSessionStoreContract(name: string, makeStore: () => SessionStore): void {
  describe(`SessionStore contract: ${name}`, () => {
    const NOW = 1_000_000;

    it("resolves a live session by its token hash", async () => {
      const store = makeStore();
      await store.create("hash-a", "operator@example.com", NOW, NOW + 5000);
      expect(await store.get("hash-a", NOW)).toEqual({ email: "operator@example.com", expiresAt: NOW + 5000 });
    });

    it("returns null for an unknown hash", async () => {
      const store = makeStore();
      expect(await store.get("missing", NOW)).toBeNull();
    });

    it("does not resolve an expired session", async () => {
      const store = makeStore();
      await store.create("hash-b", "operator@example.com", NOW, NOW + 1000);
      expect(await store.get("hash-b", NOW + 1000)).toBeNull();
      expect(await store.get("hash-b", NOW + 5000)).toBeNull();
    });

    it("delete removes the session (sign-out is effective next request)", async () => {
      const store = makeStore();
      await store.create("hash-c", "operator@example.com", NOW, NOW + 5000);
      await store.delete("hash-c");
      expect(await store.get("hash-c", NOW)).toBeNull();
    });

    it("create overwrites the same hash without duplicating", async () => {
      const store = makeStore();
      await store.create("hash-d", "old@example.com", NOW, NOW + 5000);
      await store.create("hash-d", "new@example.com", NOW, NOW + 9000);
      expect(await store.get("hash-d", NOW)).toEqual({ email: "new@example.com", expiresAt: NOW + 9000 });
    });
  });
}