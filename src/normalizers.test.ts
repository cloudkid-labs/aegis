import { describe, expect, it } from "vitest";
import { sha256Hex } from "./auth";
import { normalize, hasNormalizer, normalizeFindings } from "./normalizers/index";
import { loadRegistry } from "./registry";
import { selectInvasionTargets } from "./invasion-targets";
import { normalizeSubfinder, normalizeHttpx, normalizeKatana, normalizeDnsx, normalizeNaabu, normalizeAlterxResolved } from "./normalizers/explore";
import { normalizeNucleiJsonl, normalizeZapJson } from "./normalizers/invasion";
import { nucleiInfo, nucleiRecord, zapAlert, zapInstance, zapReport } from "./test-support/fixtures";

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

  it("katana: response.status_code lands in metadata and survives invasion selection", async () => {
    // katana writes the status on `response` (pkg/navigation/response.go:
    // StatusCode int `json:"status_code,omitempty"`), never on the record root.
    const data = [
      { request: { endpoint: "https://example.com/api/users" }, response: { status_code: 200 } },
      { request: { endpoint: "https://example.com/missing" } },
      { request: { endpoint: "https://example.com/odd" }, response: { status_code: "200" } },
    ];
    const assets = await normalizeKatana(data, SCAN, NOW);
    expect(JSON.parse(assets[0]!.metadata!)).toEqual({ status_code: 200 });
    expect(JSON.parse(assets[1]!.metadata!)).toEqual({ status_code: null });
    expect(JSON.parse(assets[2]!.metadata!)).toEqual({ status_code: null });

    const selection = selectInvasionTargets(assets);
    expect(selection.targets.map((t) => t.url)).toEqual(["https://example.com/api/users"]);
    expect(selection.excluded).toEqual([
      { url: "https://example.com/missing", reason: "not-live" },
      { url: "https://example.com/odd", reason: "not-live" },
    ]);
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

  it("dnsx: drops records with no address data (NOERROR/NODATA zones)", async () => {
    // cloudkid.link answers NOERROR + SOA authority (not NXDOMAIN) for labels
    // that do not exist; dnsx emits those lines with no `a` field and we must
    // not store them as subdomains.
    const data = [
      { host: "dev-monitoring.cloudkid.link" },
      { host: "ads.cloudkid.link", a: [], cname: [] },
      { host: "real.example.com", a: ["1.2.3.4"] },
    ];
    const assets = await normalizeDnsx(data, SCAN, NOW);
    expect(assets.map((a) => a.value)).toEqual(["real.example.com"]);
  });

  it("dnsx: keeps IPv6-only hosts and records aaaa", async () => {
    const assets = await normalizeDnsx([{ host: "v6.example.com", aaaa: ["2606:4700::1"] }], SCAN, NOW);
    expect(assets.map((a) => a.value)).toEqual(["v6.example.com"]);
    const meta = JSON.parse(assets[0]!.metadata!);
    expect(meta.aaaa).toEqual(["2606:4700::1"]);
    expect(meta.resolved).toBe(true);
  });

  it("alterx: drops permutations with no address data", async () => {
    const data = [
      { host: "bogus.example.com", a: [], cname: [] },
      { host: "live.example.com", a: ["9.9.9.9"] },
    ];
    const assets = await normalizeAlterxResolved(data, SCAN, NOW);
    expect(assets.map((a) => a.value)).toEqual(["live.example.com"]);
    expect(JSON.parse(assets[0]!.metadata!).source).toBe("alterx");
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
    const dnsx = await normalizeDnsx([{ host: "api.example.com", a: ["1.2.3.4"] }], SCAN, NOW);
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
  it("maps every instance of a ZAP alert to its own Finding, every field pinned", async () => {
    const findings = await normalizeZapJson(zapReport(), SCAN, NOW);
    expect(findings.length).toBe(3);

    // Instance one: empty param/evidence strings are absence, not values.
    expect(findings[0]).toEqual({
      id: await sha256Hex(`${SCAN}|zap-baseline|10021|https://x.example/|`),
      scanId: SCAN,
      tool: "zap-baseline",
      severity: "medium",
      confidence: "medium",
      title: "Missing CSP",
      description: "d",
      url: "https://x.example/",
      parameter: null,
      evidence: null,
      cwe: 693,
      remediation: "s",
      rawRef: null,
      createdAt: NOW,
    });

    // Instance two of the same alert: the occurrence fields come from here.
    expect(findings[1]).toMatchObject({
      id: await sha256Hex(`${SCAN}|zap-baseline|10021|https://x.example/search|q`),
      url: "https://x.example/search",
      parameter: "q",
      evidence: "proof",
      title: "Missing CSP",
      severity: "medium",
      cwe: 693,
    });

    // The single-instance alert in the same report.
    expect(findings[2]).toMatchObject({
      id: await sha256Hex(`${SCAN}|zap-baseline|10022|https://x.example/login|`),
      title: "Missing Anti-clickjacking Header",
      url: "https://x.example/login",
      parameter: null,
      evidence: null,
      severity: "low",
      confidence: "high",
      cwe: 1021,
      remediation: "s2",
    });
  });

  it("maps every risk level, Informational to info, and clamps unknown to info", async () => {
    const cases: [string, string][] = [
      ["Informational", "info"], ["Low", "low"], ["Medium", "medium"],
      ["High", "high"], ["Critical", "critical"], ["Bogus", "info"],
    ];
    for (const [riskdesc, expected] of cases) {
      const report = zapReport([zapAlert({ riskdesc, instances: [zapInstance()] })]);
      const [f] = await normalizeZapJson(report, SCAN, NOW);
      expect(f!.severity).toBe(expected);
    }
  });

  it("maps confidence and clamps unknown to medium", async () => {
    const cases: [string, string][] = [
      ["Confirmed", "high"], ["High", "high"], ["Medium", "medium"],
      ["Low", "low"], ["False Positive", "low"], ["Odd", "medium"],
      // traditional-json writes numeric codes: 0 false positive, 1 low,
      // 2 medium, 3 high, 4 confirmed.
      ["0", "low"], ["1", "low"], ["2", "medium"], ["3", "high"], ["4", "high"],
    ];
    for (const [confidence, expected] of cases) {
      const report = zapReport([zapAlert({ confidence, instances: [zapInstance()] })]);
      const [f] = await normalizeZapJson(report, SCAN, NOW);
      expect(f!.confidence).toBe(expected);
    }
  });

  it("keeps a parameter and evidence when the instance has them", async () => {
    const report = zapReport([zapAlert({ instances: [zapInstance({ param: "q", evidence: "proof" })] })]);
    const [f] = await normalizeZapJson(report, SCAN, NOW);
    expect(f!.parameter).toBe("q");
    expect(f!.evidence).toBe("proof");
  });

  it("falls back to the instance attack for evidence when evidence is absent", async () => {
    const report = zapReport([zapAlert({ instances: [zapInstance({ attack: "<script>alert(1)</script>" })] })]);
    const [f] = await normalizeZapJson(report, SCAN, NOW);
    expect(f!.evidence).toBe("<script>alert(1)</script>");
    expect(f!.parameter).toBeNull();
  });

  it("skips instances with no uri and alerts with no usable instance", async () => {
    const report = {
      site: [{
        alerts: [
          // Empty uri, non-record, and missing instances: nothing to locate.
          zapAlert({ pluginid: "10024", instances: [zapInstance({ uri: "" }), { param: "q" }] }),
          zapAlert({ instances: [] }),
          zapAlert({ instances: undefined }),
          "not-an-alert",
          // One usable instance survives beside a blank one.
          zapAlert({ pluginid: "10025", instances: [zapInstance({ uri: "" }), zapInstance({ uri: "https://x.example/kept" })] }),
        ],
      }],
    };
    const findings = await normalizeZapJson(report, SCAN, NOW);
    expect(findings.map((f) => f.url)).toEqual(["https://x.example/kept"]);
    expect(findings[0]!.id).toBe(await sha256Hex(`${SCAN}|zap-baseline|10025|https://x.example/kept|`));
  });

  it("falls back to name for the title when alert is absent", async () => {
    const report = zapReport([zapAlert({ alert: "", instances: [zapInstance()] })]);
    const [f] = await normalizeZapJson(report, SCAN, NOW);
    expect(f!.title).toBe("Missing CSP");
  });

  it("nulls the CWE when cweid is absent or unparseable", async () => {
    const absent = await normalizeZapJson(zapReport([zapAlert({ cweid: undefined, instances: [zapInstance()] })]), SCAN, NOW);
    expect(absent[0]!.cwe).toBeNull();
    const bogus = await normalizeZapJson(zapReport([zapAlert({ cweid: "n/a", instances: [zapInstance()] })]), SCAN, NOW);
    expect(bogus[0]!.cwe).toBeNull();
  });

  it("keys a finding per instance parameter, so two parameters never collide on insert", async () => {
    const report = zapReport([zapAlert({ instances: [zapInstance({ param: "q" }), zapInstance({ param: "id" })] })]);
    const findings = await normalizeZapJson(report, SCAN, NOW);
    expect(findings.length).toBe(2);
    expect(findings[0]!.id).not.toBe(findings[1]!.id);
  });

  it("flattens every site and alert", async () => {
    const report = {
      site: [
        { alerts: [zapAlert({ instances: [zapInstance({ uri: "https://x.example/" }), zapInstance({ uri: "https://x.example/b" })] })] },
        { alerts: [zapAlert({ pluginid: "10023", instances: [zapInstance({ uri: "https://x.example/c" })] })] },
      ],
    };
    const findings = await normalizeZapJson(report, SCAN, NOW);
    expect(findings.map((f) => f.url)).toEqual(["https://x.example/", "https://x.example/b", "https://x.example/c"]);
  });

  it("hashes a stable id for the same report", async () => {
    const first = await normalizeZapJson(zapReport(), SCAN, NOW);
    const again = await normalizeZapJson(zapReport(), SCAN, NOW);
    expect(first.map((f) => f.id)).toEqual(again.map((f) => f.id));
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
    expect((await normalizeFindings("zap-json", "zap-baseline", zapReport(), SCAN, NOW)).length).toBe(3);
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

describe("findings registry coverage", () => {
  // A findings entry whose normalizer key is absent from FINDING_NORMALIZERS
  // makes normalizeFindings return [] (index.ts:42): the callback then reports
  // "0 findings" and completes green, with no signal that the tool was dropped.
  // A sample per tool proves the registry key actually resolves to a producing
  // normalizer, and forces a new findings tool to add one before shipping.
  const SAMPLES = new Map<string, unknown>([
    ["nuclei", [nucleiRecord()]],
    ["zap-baseline", zapReport()],
    ["zap-full", zapReport()],
  ]);

  it("every findings entry's normalizer resolves to a producing implementation", async () => {
    const entries = loadRegistry().filter((tool) => tool.outputType === "findings");
    expect(entries.length).toBeGreaterThan(0);
    for (const tool of entries) {
      const sample = SAMPLES.get(tool.name);
      expect(sample, `add a sample for findings tool "${tool.name}"`).toBeDefined();
      const findings = await normalizeFindings(tool.normalizer, tool.name, sample, SCAN, NOW);
      expect(findings.length, `normalizer "${tool.normalizer}" (${tool.name}) resolved to nothing`).toBeGreaterThan(0);
    }
  });
});