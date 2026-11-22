import { describe, expect, it } from "vitest";
import { sha256Hex } from "./auth";
import { normalize, hasNormalizer } from "./normalizers/index";
import { normalizeSubfinder, normalizeHttpx, normalizeKatana, normalizeDnsx, normalizeNaabu, normalizeAlterx } from "./normalizers/explore";

const SCAN = "scan-test-1";
const NOW = "2026-11-22T00:00:00.000Z";

describe("explore normalizers", () => {
  it("subfinder: JSON lines → subdomain assets", async () => {
    const data = [{ host: "api.example.com", source: "crtsh" }, { host: "dev.example.com", source: "dns" }];
    const assets = await normalizeSubfinder(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    expect(assets[0]!.type).toBe("subdomain");
    expect(assets[0]!.value).toBe("api.example.com");
  });

  it("httpx: JSON → url assets with metadata", async () => {
    const data = [{ url: "https://example.com", status_code: 200, title: "Home", tech: ["Cloudflare"] }];
    const assets = await normalizeHttpx(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    expect(assets[0]!.type).toBe("url");
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.status_code).toBe(200);
    expect(meta.tech).toContain("Cloudflare");
  });

  it("katana: JSONL → endpoint assets", async () => {
    const data = [{ request: { endpoint: "https://example.com/api/users" } }, { endpoint: "https://example.com/login" }];
    const assets = await normalizeKatana(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    expect(assets[0]!.type).toBe("endpoint");
  });

  it("dnsx: JSON → resolved subdomain assets", async () => {
    const data = [{ host: "api.example.com", a: ["1.2.3.4"], cname: [] }];
    const assets = await normalizeDnsx(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.resolved).toBe(true);
    expect(meta.a).toContain("1.2.3.4");
  });

  it("naabu: JSON → port assets", async () => {
    const data = [{ host: "example.com", port: 8443, protocol: "tcp" }];
    const assets = await normalizeNaabu(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    expect(assets[0]!.value).toBe("example.com:8443");
  });

  it("alterx: text lines → candidate subdomains", async () => {
    const data = "dev-api.example.com\nstaging.example.com\n";
    const assets = await normalizeAlterx(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.candidate).toBe(true);
  });

  it("handles string JSONL input", async () => {
    const data = '{"host":"a.example.com"}\n{"host":"b.example.com"}';
    const assets = await normalizeSubfinder(data, SCAN, NOW);
    expect(assets.length).toBe(2);
  });

  it("returns [] for garbage input", async () => {
    expect(await normalizeSubfinder(null, SCAN, NOW)).toEqual([]);
    expect(await normalizeHttpx({}, SCAN, NOW)).toEqual([]);
  });

  it("distinct endpoints get distinct ids (collision regression)", async () => {
    // The old rolling hash collided on /Aa vs /BB; SHA-256 must not.
    const data = [{ endpoint: "https://example.com/Aa" }, { endpoint: "https://example.com/BB" }];
    const assets = await normalizeKatana(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    expect(assets[0]!.id).not.toBe(assets[1]!.id);
  });

  it("id namespace is independent of displayed type (dnsx=dns, naabu=port)", async () => {
    // The record factory keeps idKind separate from type on purpose: folding
    // them would re-key every dnsx/naabu asset and break dedup against history.
    const dnsx = await normalizeDnsx([{ host: "api.example.com" }], SCAN, NOW);
    expect(dnsx[0]!.type).toBe("subdomain");
    expect(dnsx[0]!.id).toBe((await sha256Hex(`${SCAN}|dns|api.example.com`)).slice(0, 32));

    const naabu = await normalizeNaabu([{ host: "example.com", port: 8443 }], SCAN, NOW);
    expect(naabu[0]!.type).toBe("endpoint");
    expect(naabu[0]!.id).toBe((await sha256Hex(`${SCAN}|port|example.com:8443`)).slice(0, 32));
  });
});

describe("registry dispatch", () => {
  it("routes by normalizer key", async () => {
    const assets = await normalize("subfinder-json", [{ host: "x.com" }], SCAN, NOW);
    expect(assets.length).toBe(1);
  });
  it("returns [] for unknown key", async () => {
    expect(await normalize("unknown-tool", [], SCAN, NOW)).toEqual([]);
  });
  it("hasNormalizer checks existence", () => {
    expect(hasNormalizer("nuclei-sarif")).toBe(false); // Phase 2
    expect(hasNormalizer("httpx-json")).toBe(true);
  });
});