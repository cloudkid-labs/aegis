import { describe, expect, it } from "vitest";
import { buildSarif } from "./sarif";
import type { Finding, ScanRecord, Severity } from "./types";

const NOW = "2026-11-23T00:00:00.000Z";

const SCAN: ScanRecord = {
  id: "scan-invasion-1",
  target: "https://x.example",
  phase: "invasion",
  status: "completed",
  parentScanId: null,
  executor: "github",
  externalUrl: null,
  createdAt: NOW,
  updatedAt: NOW,
  completedAt: NOW,
  error: null,
  options: null,
};

/** A complete Finding; override only what the case is about. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    scanId: SCAN.id,
    tool: "nuclei",
    severity: "high",
    confidence: "high",
    title: "Reflected XSS",
    description: "d",
    url: "https://x.example/a",
    parameter: "q",
    evidence: "proof",
    cwe: 79,
    remediation: "escape output",
    rawRef: "scans/scan-invasion-1/raw/nuclei-1.json",
    createdAt: NOW,
    ...overrides,
  };
}

describe("buildSarif log envelope", () => {
  it("writes the SARIF 2.1.0 schema and version", () => {
    const log = buildSarif(SCAN, [finding()]);
    expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(log.version).toBe("2.1.0");
  });

  it("emits runs: [] for a scan with no findings", () => {
    expect(buildSarif(SCAN, [])).toEqual({
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [],
    });
  });
});

describe("buildSarif runs", () => {
  it("groups by tool in first-seen order and keeps finding order inside a run", () => {
    const log = buildSarif(SCAN, [
      finding({ id: "n1", tool: "nuclei", title: "First nuclei" }),
      finding({ id: "z1", tool: "zap-baseline", title: "Only zap" }),
      finding({ id: "n2", tool: "nuclei", title: "Second nuclei" }),
    ]);

    expect(log.runs.length).toBe(2);
    expect(log.runs.map((run) => run.tool.driver.name)).toEqual(["nuclei", "zap-baseline"]);
    expect(log.runs[0]!.results.map((result) => result.message.text)).toEqual(["First nuclei", "Second nuclei"]);
    expect(log.runs[1]!.results.map((result) => result.message.text)).toEqual(["Only zap"]);
  });
});

describe("buildSarif level map", () => {
  it("maps all five severities onto SARIF levels", () => {
    const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
    const log = buildSarif(SCAN, severities.map((severity) => finding({ id: `f-${severity}`, severity })));

    expect(log.runs.length).toBe(1);
    expect(log.runs[0]!.results.map((result) => result.level)).toEqual([
      "error",
      "error",
      "warning",
      "note",
      "note",
    ]);
  });
});

describe("buildSarif rule ids", () => {
  it("derives ruleId as the tool-prefixed lowercase hyphenated slug of the title", () => {
    const log = buildSarif(SCAN, [
      finding({ tool: "nuclei", title: "CVE-2024-1234" }),
      finding({ tool: "zap-baseline", title: "Missing Anti-clickjacking Header" }),
      finding({ tool: "zap-full", title: "Absence of Anti-CSRF Tokens" }),
    ]);

    expect(log.runs[0]!.results[0]!.ruleId).toBe("nuclei-cve-2024-1234");
    expect(log.runs[1]!.results[0]!.ruleId).toBe("zap-baseline-missing-anti-clickjacking-header");
    expect(log.runs[2]!.results[0]!.ruleId).toBe("zap-full-absence-of-anti-csrf-tokens");
  });

  it("is stable for the same tool and title, whatever the url or id", () => {
    const log = buildSarif(SCAN, [
      finding({ id: "a", tool: "nuclei", title: "Reflected XSS", url: "https://x.example/a" }),
      finding({ id: "b", tool: "nuclei", title: "Reflected XSS", url: "https://x.example/b?q=2" }),
    ]);

    const ruleIds = log.runs[0]!.results.map((result) => result.ruleId);
    expect(ruleIds).toEqual(["nuclei-reflected-xss", "nuclei-reflected-xss"]);
  });
});

describe("buildSarif result shape", () => {
  it("writes every result field from the finding", () => {
    const log = buildSarif(SCAN, [finding()]);
    expect(log.runs[0]!.results[0]).toEqual({
      ruleId: "nuclei-reflected-xss",
      level: "error",
      message: { text: "Reflected XSS" },
      locations: [{ physicalLocation: { artifactLocation: { uri: "https://x.example/a" } } }],
      properties: {
        severity: "high",
        confidence: "high",
        cwe: 79,
        evidence: "proof",
        remediation: "escape output",
        parameter: "q",
        rawRef: "scans/scan-invasion-1/raw/nuclei-1.json",
      },
    });
  });

  it("keeps nullable finding fields as explicit nulls", () => {
    const log = buildSarif(SCAN, [
      finding({ parameter: null, evidence: null, cwe: null, remediation: null, rawRef: null }),
    ]);
    expect(log.runs[0]!.results[0]!.properties).toEqual({
      severity: "high",
      confidence: "high",
      cwe: null,
      evidence: null,
      remediation: null,
      parameter: null,
      rawRef: null,
    });
  });
});

describe("buildSarif purity", () => {
  it("does not mutate the scan or the findings it is given", () => {
    const findings = [
      finding({ id: "n1", tool: "nuclei" }),
      finding({ id: "z1", tool: "zap-baseline" }),
    ];
    const before = JSON.parse(JSON.stringify(findings)) as Finding[];

    buildSarif(SCAN, findings);

    expect(findings).toEqual(before);
  });
});