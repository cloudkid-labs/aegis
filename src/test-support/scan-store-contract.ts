import { describe, expect, it } from "vitest";
import type { ScanStore } from "../scan-store";
import type { Asset, Finding, ScanRecord } from "../types";

/**
 * One spec, run against the memory fake (node project) and against real D1
 * (workers project). Assert only what holds in both: the fake is held to D1,
 * not the other way round.
 *
 * Every test uses its own ids and either a scan-scoped read or a filtered view
 * of `list`, because the D1 project shares one database across the file.
 */

function rec(id: string, overrides: Partial<ScanRecord> = {}): ScanRecord {
  const now = "2026-11-22T00:00:00.000Z";
  return {
    id,
    target: "https://example.com",
    phase: "explore",
    status: "queued",
    parentScanId: null,
    executor: "github",
    externalUrl: null,
    createdAt: now,
    updatedAt: now,
    completedAt: null,
    error: null,
    options: null,
    ...overrides,
  };
}

function asset(id: string, scanId: string, overrides: Partial<Asset> = {}): Asset {
  return {
    id,
    scanId,
    type: "subdomain",
    value: `${id}.example.com`,
    metadata: null,
    createdAt: "2026-11-22T00:00:00.000Z",
    ...overrides,
  };
}

function finding(id: string, scanId: string): Finding {
  return {
    id,
    scanId,
    tool: "nuclei",
    severity: "high",
    confidence: "high",
    title: "Test finding",
    description: "d",
    url: "https://example.com/x",
    parameter: null,
    evidence: null,
    cwe: 79,
    remediation: null,
    rawRef: "raw/nuclei.sarif",
    createdAt: "2026-11-22T00:00:00.000Z",
  };
}

export function describeScanStoreContract(label: string, make: () => ScanStore): void {
  describe(`ScanStore contract (${label})`, () => {
    it("create + get roundtrip preserves every field", async () => {
      const store = make();
      const record = rec("roundtrip", {
        phase: "invasion",
        parentScanId: "parent-scan",
        status: "running",
        executor: "selfhosted",
        externalUrl: "https://github.com/o/r/actions/runs/1",
        completedAt: null,
        error: null,
        options: '{"depth":2,"severity":"high"}',
      });
      await store.create(record);
      expect(await store.get("roundtrip")).toEqual(record);
      expect(await store.get("does-not-exist")).toBeNull();
    });

    it("list returns newest first", async () => {
      const store = make();
      await store.create(rec("list-old", { createdAt: "2026-11-20T00:00:00.000Z" }));
      await store.create(rec("list-new", { createdAt: "2026-11-21T00:00:00.000Z" }));
      const rows = await store.list(1000);
      expect(rows.filter((r) => r.id === "list-old" || r.id === "list-new").map((r) => r.id))
        .toEqual(["list-new", "list-old"]);
    });

    it("list honours a zero limit", async () => {
      const store = make();
      expect(await store.list(0)).toEqual([]);
    });

    it("list carries the number of assets per scan", async () => {
      const store = make();
      await store.create(rec("count-full"));
      await store.insertAssets([asset("count-a1", "count-full"), asset("count-a2", "count-full")]);
      const rows = await store.list(1000);
      expect(rows.find((r) => r.id === "count-full")!.assetCount).toBe(2);
    });

    it("list reports zero assets for a scan with none", async () => {
      const store = make();
      await store.create(rec("count-empty"));
      const rows = await store.list(1000);
      expect(rows.find((r) => r.id === "count-empty")!.assetCount).toBe(0);
    });

    it("listAssets hides stored alterx candidates", async () => {
      const store = make();
      await store.create(rec("cand-scan"));
      await store.insertAssets([
        asset("cand-guess", "cand-scan", { metadata: '{"source":"alterx","candidate":true}' }),
        asset("cand-real", "cand-scan", { metadata: '{"resolved":true}' }),
      ]);
      const rows = await store.listAssets("cand-scan");
      expect(rows.map((r) => r.id)).toEqual(["cand-real"]);
    });

    it("asset counts exclude stored alterx candidates", async () => {
      const store = make();
      await store.create(rec("cand-count"));
      await store.insertAssets([
        asset("cand-c1", "cand-count", { metadata: '{"source":"alterx","candidate":true}' }),
        asset("cand-c2", "cand-count", { metadata: null }),
      ]);
      const rows = await store.list(1000);
      expect(rows.find((r) => r.id === "cand-count")!.assetCount).toBe(1);
    });

    it("setStatus applies patch fields", async () => {
      const store = make();
      await store.create(rec("status"));
      await store.setStatus("status", "completed", {
        completedAt: "2026-11-22T01:00:00.000Z",
        externalUrl: "https://github.com/o/r/actions/runs/2",
      });
      const got = (await store.get("status"))!;
      expect(got.status).toBe("completed");
      expect(got.completedAt).toBe("2026-11-22T01:00:00.000Z");
      expect(got.externalUrl).toBe("https://github.com/o/r/actions/runs/2");
    });

    it("setStatus on a missing scan is a no-op", async () => {
      const store = make();
      await store.setStatus("missing", "failed", { error: "boom" });
      expect(await store.get("missing")).toBeNull();
    });

    it("claimOldest claims the oldest queued scan for one executor only", async () => {
      const store = make();
      const now = "2026-11-22T02:00:00.000Z";
      await store.create(rec("claim-gh", { executor: "github", createdAt: "2026-11-20T00:00:00.000Z" }));
      await store.create(rec("claim-sh1", { executor: "selfhosted", createdAt: "2026-11-21T00:00:00.000Z" }));
      await store.create(rec("claim-sh2", { executor: "selfhosted", createdAt: "2026-11-22T00:00:00.000Z" }));

      const first = await store.claimOldest("selfhosted", now);
      expect(first).not.toBeNull();
      expect(first!.id).toBe("claim-sh1");
      expect(first!.status).toBe("running");
      expect(first!.updatedAt).toBe(now);

      const second = await store.claimOldest("selfhosted", now);
      expect(second!.id).toBe("claim-sh2");

      expect(await store.claimOldest("selfhosted", now)).toBeNull();
      expect((await store.get("claim-gh"))!.status).toBe("queued");
    });

    it("claimRetry succeeds once and refuses a stale claim on the same row", async () => {
      const store = make();
      await store.create(rec("retry-claim", { status: "failed", updatedAt: "2026-11-22T00:00:00.000Z" }));
      const winner = "2026-11-22T04:00:00.000Z";

      expect(await store.claimRetry("retry-claim", "2026-11-22T00:00:00.000Z", winner)).toBe(true);
      expect((await store.get("retry-claim"))!.updatedAt).toBe(winner);

      // The losing retry read the row before the winner wrote it.
      expect(await store.claimRetry("retry-claim", "2026-11-22T00:00:00.000Z", "2026-11-22T04:00:01.000Z")).toBe(false);
      expect((await store.get("retry-claim"))!.updatedAt).toBe(winner);
      expect((await store.get("retry-claim"))!.status).toBe("failed");
    });

    it("claimRetry accepts a cancelled scan", async () => {
      const store = make();
      await store.create(rec("retry-claim-cancelled", { status: "cancelled" }));
      expect(await store.claimRetry("retry-claim-cancelled", "2026-11-22T00:00:00.000Z", "2026-11-22T05:00:00.000Z")).toBe(true);
      expect((await store.get("retry-claim-cancelled"))!.updatedAt).toBe("2026-11-22T05:00:00.000Z");
    });

    it("claimRetry refuses a scan that is not failed or cancelled", async () => {
      for (const id of ["retry-claim-running", "retry-claim-done"]) {
        const store = make();
        await store.create(rec(id, { status: id.endsWith("running") ? "running" : "completed" }));
        expect(await store.claimRetry(id, "2026-11-22T00:00:00.000Z", "2026-11-22T06:00:00.000Z")).toBe(false);
        expect((await store.get(id))!.updatedAt).toBe("2026-11-22T00:00:00.000Z");
      }
    });

    it("claimRetry on a missing scan returns false", async () => {
      expect(await make().claimRetry("retry-claim-missing", "2026-11-22T00:00:00.000Z", "2026-11-22T06:00:00.000Z")).toBe(false);
    });

    it("insertAssets stores assets scoped to a scan and is idempotent on id", async () => {
      const store = make();
      await store.create(rec("assets-a"));
      await store.create(rec("assets-b"));

      await store.insertAssets([
        asset("a2", "assets-a", { createdAt: "2026-11-22T00:00:02.000Z", type: "url", value: "https://example.com/x", metadata: '{"status_code":200}' }),
        asset("a1", "assets-a", { createdAt: "2026-11-22T00:00:01.000Z" }),
        asset("b1", "assets-b"),
      ]);

      const assetsA = await store.listAssets("assets-a");
      expect(assetsA.map((a) => a.id)).toEqual(["a1", "a2"]);
      expect(assetsA[1]!.type).toBe("url");
      expect(assetsA[1]!.metadata).toBe('{"status_code":200}');
      expect((await store.listAssets("assets-b")).map((a) => a.id)).toEqual(["b1"]);

      await store.insertAssets([asset("a1", "assets-a", { createdAt: "2026-11-22T00:00:01.000Z" })]);
      expect((await store.listAssets("assets-a")).length).toBe(2);
      expect(await store.listAssets("assets-missing")).toEqual([]);
    });

    it("insertFindings is scoped to a scan and idempotent on id", async () => {
      const store = make();
      await store.create(rec("findings-a"));
      await store.create(rec("findings-b"));

      await store.insertFindings([
        finding("f1", "findings-a"),
        finding("f2", "findings-a"),
        finding("f3", "findings-b"),
      ]);
      expect((await store.listFindings("findings-a")).map((f) => f.id).sort()).toEqual(["f1", "f2"]);
      expect((await store.listFindings("findings-b")).map((f) => f.id)).toEqual(["f3"]);

      await store.insertFindings([finding("f1", "findings-a")]);
      expect((await store.listFindings("findings-a")).length).toBe(2);
      expect(await store.listFindings("findings-missing")).toEqual([]);
    });

    it("events append in insertion order", async () => {
      const store = make();
      await store.create(rec("events"));
      await store.addEvent("events", "created");
      await store.addEvent("events", "dispatched", "run-1");

      const events = await store.events("events");
      expect(events.map((e) => e.event)).toEqual(["created", "dispatched"]);
      expect(events[0]!.detail).toBeNull();
      expect(events[1]!.detail).toBe("run-1");
      expect(await store.events("events-missing")).toEqual([]);
    });

    it("transition writes only from an allowed status", async () => {
      const store = make();
      await store.create(rec("trans"));
      expect(await store.transition("trans", ["queued", "running"], "completed", { completedAt: "2026-11-22T03:00:00.000Z" })).toBe(true);
      const got = (await store.get("trans"))!;
      expect(got.status).toBe("completed");
      expect(got.completedAt).toBe("2026-11-22T03:00:00.000Z");
    });

    it("transition refuses to resurrect a terminal scan", async () => {
      const store = make();
      await store.create(rec("trans-term", { status: "cancelled" }));
      expect(await store.transition("trans-term", ["queued", "running"], "completed")).toBe(false);
      expect((await store.get("trans-term"))!.status).toBe("cancelled");
    });

    it("transition is first-writer-wins between cancel and completion", async () => {
      const store = make();
      await store.create(rec("trans-race"));
      expect(await store.transition("trans-race", ["queued", "running"], "cancelled")).toBe(true);
      expect(await store.transition("trans-race", ["queued", "running"], "completed")).toBe(false);
      expect((await store.get("trans-race"))!.status).toBe("cancelled");
    });

    it("transition on a missing scan returns false", async () => {
      const store = make();
      expect(await store.transition("trans-missing", ["queued"], "running")).toBe(false);
    });

    it("authorization roundtrips and is unique per scan", async () => {
      const store = make();
      await store.create(rec("auth-scan"));
      const a = {
        scanId: "auth-scan",
        email: "op@example.com",
        targets: ["https://x.example/"],
        tools: ["nuclei"],
        active: false,
        confirmedAt: "2026-11-23T00:00:00.000Z",
      };
      await store.createAuthorization(a);
      expect(await store.getAuthorization("auth-scan")).toEqual(a);
      await expect(store.createAuthorization(a)).rejects.toThrow();
      expect(await store.getAuthorization("missing")).toBeNull();
    });

    it("authorization preserves active and multi-entry lists", async () => {
      // active: true is the zap-full opt-in: a write side stuck at 0 would
      // silently downgrade the authorization, so it is asserted separately
      // from the active: false case above. Two entries per list catch a
      // serialiser that only carries the first.
      const store = make();
      await store.create(rec("auth-full"));
      const a = {
        scanId: "auth-full",
        email: "zap@example.com",
        targets: ["https://a.example/", "https://b.example:8443/"],
        tools: ["nuclei", "zap-full"],
        active: true,
        confirmedAt: "2026-11-23T01:00:00.000Z",
      };
      await store.createAuthorization(a);
      expect(await store.getAuthorization("auth-full")).toEqual(a);
    });
  });
}