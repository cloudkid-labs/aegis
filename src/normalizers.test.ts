import { describe, expect, it } from "vitest";
import { normalize, hasNormalizer } from "./normalizers/index";
import { normalizeSubfinder, normalizeHttpx, normalizeKatana, normalizeDnsx, normalizeNaabu, normalizeAlterx } from "./normalizers/explore";

const SCAN = "scan-test-1";
const NOW = "2026-11-22T00:00:00.000Z";

describe("explore normalizers", () => {
  it("subfinder: JSON lines → subdomain assets", () => {
    const data = [{ host: "api.example.com", source: "crtsh" }, { host: "dev.example.com", source: "dns" }];
    const assets = normalizeSubfinder(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    expect(assets[0]!.type).toBe("subdomain");
    expect(assets[0]!.value).toBe("api.example.com");
  });

  it("httpx: JSON → url assets with metadata", () => {
    const data = [{ url: "https://example.com", status_code: 200, title: "Home", tech: ["Cloudflare"] }];
    const assets = normalizeHttpx(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    expect(assets[0]!.type).toBe("url");
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.status_code).toBe(200);
    expect(meta.tech).toContain("Cloudflare");
  });

  it("katana: JSONL → endpoint assets", () => {
    const data = [{ request: { endpoint: "https://example.com/api/users" } }, { endpoint: "https://example.com/login" }];
    const assets = normalizeKatana(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    expect(assets[0]!.type).toBe("endpoint");
  });

  it("dnsx: JSON → resolved subdomain assets", () => {
    const data = [{ host: "api.example.com", a: ["1.2.3.4"], cname: [] }];
    const assets = normalizeDnsx(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.resolved).toBe(true);
    expect(meta.a).toContain("1.2.3.4");
  });

  it("naabu: JSON → port assets", () => {
    const data = [{ host: "example.com", port: 8443, protocol: "tcp" }];
    const assets = normalizeNaabu(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    expect(assets[0]!.value).toBe("example.com:8443");
  });

  it("alterx: text lines → candidate subdomains", () => {
    const data = "dev-api.example.com\nstaging.example.com\n";
    const assets = normalizeAlterx(data, SCAN, NOW);
    expect(assets.length).toBe(2);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.candidate).toBe(true);
  });

  it("handles string JSONL input", () => {
    const data = '{"host":"a.example.com"}\n{"host":"b.example.com"}';
    const assets = normalizeSubfinder(data, SCAN, NOW);
    expect(assets.length).toBe(2);
  });

  it("returns [] for garbage input", () => {
    expect(normalizeSubfinder(null, SCAN, NOW)).toEqual([]);
    expect(normalizeHttpx({}, SCAN, NOW)).toEqual([]);
  });
});

describe("registry dispatch", () => {
  it("routes by normalizer key", () => {
    const assets = normalize("subfinder-json", [{ host: "x.com" }], SCAN, NOW);
    expect(assets.length).toBe(1);
  });
  it("returns [] for unknown key", () => {
    expect(normalize("unknown-tool", [], SCAN, NOW)).toEqual([]);
  });
  it("hasNormalizer checks existence", () => {
    expect(hasNormalizer("nuclei-sarif")).toBe(false); // Phase 2
    expect(hasNormalizer("httpx-json")).toBe(true);
  });
});