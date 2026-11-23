import { describe, expect, it } from "vitest";
import { sha256Hex } from "./auth";
import { normalize, hasNormalizer, normalizeFindings } from "./normalizers/index";
import { normalizeSubfinder, normalizeHttpx, normalizeKatana, normalizeDnsx, normalizeNaabu, normalizeAlterxResolved } from "./normalizers/explore";
import { normalizeNucleiJsonl, normalizeZapJson } from "./normalizers/invasion";
import { nucleiInfo, nucleiRecord, zapAlert, zapReport } from "./test-support/fixtures";

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

  it("alterx: resolved dnsx records → subdomains tagged alterx, never candidates", async () => {
    const data = [{ host: "dev-api.example.com", a: ["1.2.3.4"] }];
    const assets = await normalizeAlterxResolved(data, SCAN, NOW);
    expect(assets.length).toBe(1);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.resolved).toBe(true);
    expect(meta.source).toBe("alterx");
    expect(meta.candidate).toBeUndefined();
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

describe("nuclei normalizer", () => {
  it("maps a jsonl record to a Finding, every field pinned", async () => {
    const [f] = await normalizeNucleiJsonl([nucleiRecord()], SCAN, NOW);
    expect(f).toEqual({
      id: await sha256Hex(`${SCAN}|nuclei|CVE-2024-1234|https://x.example/a|`),
      scanId: SCAN,
      tool: "nuclei",
      severity: "high",
      // nuclei reports no confidence; medium is the neutral default, the same
      // clamp an unrecognised ZAP confidence gets.
      confidence: "medium",
      title: "X",
      description: "d",
      url: "https://x.example/a",
      parameter: null,
      evidence: "proof",
      cwe: 79,
      remediation: "r",
      rawRef: null,
      createdAt: NOW,
    });
  });

  it("hashes a stable id for the same record and a different one per url", async () => {
    const first = await normalizeNucleiJsonl([nucleiRecord()], SCAN, NOW);
    const again = await normalizeNucleiJsonl([nucleiRecord()], SCAN, NOW);
    expect(first[0]!.id).toBe(again[0]!.id);
    const other = await normalizeNucleiJsonl([nucleiRecord({ "matched-at": "https://x.example/b" })], SCAN, NOW);
    expect(other[0]!.id).not.toBe(first[0]!.id);
  });

  it("clamps an unknown severity to info", async () => {
    for (const severity of ["weird", "unknown"]) {
      const [f] = await normalizeNucleiJsonl([nucleiRecord({ info: nucleiInfo({ severity }) })], SCAN, NOW);
      expect(f!.severity).toBe("info");
    }
  });

  it("falls back to matcher-name and then null for evidence", async () => {
    const viaMatcher = await normalizeNucleiJsonl(
      [nucleiRecord({ "extracted-results": [], "matcher-name": "wordpress-detect" })], SCAN, NOW,
    );
    expect(viaMatcher[0]!.evidence).toBe("wordpress-detect");
    const none = await normalizeNucleiJsonl(
      [nucleiRecord({ "extracted-results": undefined, "matcher-name": undefined })], SCAN, NOW,
    );
    expect(none[0]!.evidence).toBeNull();
  });

  it("joins multiple extracted results with '; '", async () => {
    const [f] = await normalizeNucleiJsonl([nucleiRecord({ "extracted-results": ["a", "b"] })], SCAN, NOW);
    expect(f!.evidence).toBe("a; b");
  });

  it("falls back to template-id for the title and hashes it as the rule id", async () => {
    const [f] = await normalizeNucleiJsonl([nucleiRecord({ info: nucleiInfo({ name: undefined }) })], SCAN, NOW);
    expect(f!.title).toBe("CVE-2024-1234");
    expect(f!.id).toBe(await sha256Hex(`${SCAN}|nuclei|CVE-2024-1234|https://x.example/a|`));
  });

  it("takes the first parseable CWE and nulls it when none parses", async () => {
    const [mixed] = await normalizeNucleiJsonl(
      [nucleiRecord({ info: nucleiInfo({ classification: { "cwe-id": ["not-a-cwe", "CWE-89"] } }) })], SCAN, NOW,
    );
    expect(mixed!.cwe).toBe(89);
    const [absent] = await normalizeNucleiJsonl([nucleiRecord({ info: nucleiInfo({ classification: undefined }) })], SCAN, NOW);
    expect(absent!.cwe).toBeNull();
  });

  it("accepts newline-delimited JSON text", async () => {
    const text = `${JSON.stringify(nucleiRecord())}\n${JSON.stringify(nucleiRecord({ "matched-at": "https://x.example/b" }))}`;
    expect((await normalizeNucleiJsonl(text, SCAN, NOW)).length).toBe(2);
  });

  it("returns [] for garbage input", async () => {
    expect(await normalizeNucleiJsonl(null, SCAN, NOW)).toEqual([]);
    expect(await normalizeNucleiJsonl("{not json}", SCAN, NOW)).toEqual([]);
    expect(await normalizeNucleiJsonl([{ info: {} }], SCAN, NOW)).toEqual([]);
  });
});

describe("zap normalizer", () => {
  it("maps an alert to a Finding, every field pinned", async () => {
    const [f] = await normalizeZapJson(zapReport(), SCAN, NOW);
    expect(f).toEqual({
      id: await sha256Hex(`${SCAN}|zap-baseline|10021|https://x.example/|`),
      scanId: SCAN,
      tool: "zap-baseline",
      severity: "medium",
      confidence: "medium",
      title: "Missing CSP",
      description: "d",
      url: "https://x.example/",
      // Empty strings are absence in the ZAP report, not a parameter or proof.
      parameter: null,
      evidence: null,
      cwe: 693,
      remediation: "s",
      rawRef: null,
      createdAt: NOW,
    });
  });

  it("maps every risk level, Informational to info, and clamps unknown to info", async () => {
    const cases: [string, string][] = [
      ["Informational", "info"], ["Low", "low"], ["Medium", "medium"],
      ["High", "high"], ["Critical", "critical"], ["Bogus", "info"],
    ];
    for (const [riskdesc, expected] of cases) {
      const [f] = await normalizeZapJson(zapReport([zapAlert({ riskdesc })]), SCAN, NOW);
      expect(f!.severity).toBe(expected);
    }
  });

  it("maps confidence and clamps unknown to medium", async () => {
    const cases: [string, string][] = [
      ["Confirmed", "high"], ["High", "high"], ["Medium", "medium"],
      ["Low", "low"], ["False Positive", "low"], ["Odd", "medium"],
    ];
    for (const [confidence, expected] of cases) {
      const [f] = await normalizeZapJson(zapReport([zapAlert({ confidence })]), SCAN, NOW);
      expect(f!.confidence).toBe(expected);
    }
  });

  it("keeps a parameter and evidence when the report has them", async () => {
    const [f] = await normalizeZapJson(zapReport([zapAlert({ param: "q", evidence: "proof" })]), SCAN, NOW);
    expect(f!.parameter).toBe("q");
    expect(f!.evidence).toBe("proof");
  });

  it("falls back to name for the title when alert is absent", async () => {
    const [f] = await normalizeZapJson(zapReport([zapAlert({ alert: "" })]), SCAN, NOW);
    expect(f!.title).toBe("Missing CSP");
  });

  it("nulls the CWE when cweid is absent or unparseable", async () => {
    const [absent] = await normalizeZapJson(zapReport([zapAlert({ cweid: undefined })]), SCAN, NOW);
    expect(absent!.cwe).toBeNull();
    const [bogus] = await normalizeZapJson(zapReport([zapAlert({ cweid: "n/a" })]), SCAN, NOW);
    expect(bogus!.cwe).toBeNull();
  });

  it("keys a finding per parameter, so two parameters never collide on insert", async () => {
    const findings = await normalizeZapJson(zapReport([zapAlert({ param: "q" }), zapAlert({ param: "id" })]), SCAN, NOW);
    expect(findings.length).toBe(2);
    expect(findings[0]!.id).not.toBe(findings[1]!.id);
  });

  it("flattens every site and alert", async () => {
    const report = {
      site: [
        { alerts: [zapAlert(), zapAlert({ pluginid: "10022", uri: "https://x.example/b" })] },
        { alerts: [zapAlert({ pluginid: "10023", uri: "https://x.example/c" })] },
      ],
    };
    const findings = await normalizeZapJson(report, SCAN, NOW);
    expect(findings.map((f) => f.url)).toEqual(["https://x.example/", "https://x.example/b", "https://x.example/c"]);
  });

  it("hashes a stable id for the same report", async () => {
    const first = await normalizeZapJson(zapReport(), SCAN, NOW);
    const again = await normalizeZapJson(zapReport(), SCAN, NOW);
    expect(first[0]!.id).toBe(again[0]!.id);
  });

  it("returns [] for garbage input", async () => {
    expect(await normalizeZapJson(null, SCAN, NOW)).toEqual([]);
    expect(await normalizeZapJson("{not json}", SCAN, NOW)).toEqual([]);
    expect(await normalizeZapJson({ site: "nope" }, SCAN, NOW)).toEqual([]);
  });
});

describe("findings dispatch", () => {
  it("routes by finding normalizer key", async () => {
    expect((await normalizeFindings("nuclei-jsonl", "nuclei", [nucleiRecord()], SCAN, NOW)).length).toBe(1);
    expect((await normalizeFindings("zap-json", "zap-baseline", zapReport(), SCAN, NOW)).length).toBe(1);
  });

  it("returns [] for an unknown key", async () => {
    expect(await normalizeFindings("nuclei-sarif", "nuclei", [nucleiRecord()], SCAN, NOW)).toEqual([]);
  });

  it("returns [] for prototype keys instead of resolving them off Object.prototype", async () => {
    // parseRegistry accepts any non-empty normalizer string, so a tools.json typo
    // can arrive here. A bare map lookup finds Object.prototype.toString (a
    // function, not a normalizer) and Object's own "__proto__" accessor.
    await expect(normalizeFindings("toString", "nuclei", [], "s", "now")).resolves.toEqual([]);
    await expect(normalizeFindings("__proto__", "nuclei", [], "s", "now")).resolves.toEqual([]);
    await expect(normalizeFindings("constructor", "nuclei", [], "s", "now")).resolves.toEqual([]);
  });

  it("hashes the caller's tool name into the id, so zap-full and zap-baseline never collide", async () => {
    const baseline = await normalizeFindings("zap-json", "zap-baseline", zapReport(), SCAN, NOW);
    const full = await normalizeFindings("zap-json", "zap-full", zapReport(), SCAN, NOW);
    expect(full[0]!.tool).toBe("zap-full");
    expect(baseline[0]!.tool).toBe("zap-baseline");
    expect(full[0]!.id).toBe(await sha256Hex(`${SCAN}|zap-full|10021|https://x.example/|`));
    expect(full[0]!.id).not.toBe(baseline[0]!.id);
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
  it("normalize() stays asset-only; findings go through normalizeFindings", () => {
    expect(hasNormalizer("nuclei-jsonl")).toBe(false);
    expect(hasNormalizer("subfinder-json")).toBe(true);
  });
});