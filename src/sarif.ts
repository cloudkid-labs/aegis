import type { Confidence, Finding, ScanRecord, Severity } from "./types";

/**
 * SARIF 2.1.0 export (design spec Section 4). A pure projection of stored
 * findings: no bindings, no fetch, no clock, so the endpoint and the tests
 * exercise the same bytes.
 *
 * Only the subset the dashboard's export needs is typed. A finding has no
 * stored rule id, so each result's ruleId is derived from the title
 * (`slug(title)` prefixed by the tool slug, e.g. "nuclei-missing-csp"); the
 * same tool + title always produces the same ruleId, which is what SARIF
 * consumers group on.
 */

export type SarifLevel = "error" | "warning" | "note";

export interface SarifPhysicalLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifPhysicalLocation[];
  properties: {
    severity: Severity;
    confidence: Confidence;
    cwe: number | null;
    evidence: string | null;
    remediation: string | null;
    parameter: string | null;
    rawRef: string | null;
  };
}

export interface SarifRun {
  tool: { driver: { name: string } };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  version: "2.1.0";
  runs: SarifRun[];
}

const LEVELS: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const COMBINING_MARKS = /\p{M}/gu;
const NON_SLUG = /[^a-z0-9]+/g;

/**
 * Lowercase, hyphenated, ASCII: NFKD folds accents to their base letter, then
 * every run of other characters collapses to one hyphen. A title made only of
 * punctuation slugs to "" and the caller substitutes a fixed word, so a rule
 * id never ends in a dangling hyphen.
 */
function slug(value: string): string {
  return value
    .normalize("NFKD")
    .replace(COMBINING_MARKS, "")
    .toLowerCase()
    .replace(NON_SLUG, "-")
    .replace(/^-+|-+$/g, "");
}

function ruleIdFor(finding: Finding): string {
  return `${slug(finding.tool) || "tool"}-${slug(finding.title) || "finding"}`;
}

function toResult(finding: Finding): SarifResult {
  return {
    ruleId: ruleIdFor(finding),
    level: LEVELS[finding.severity],
    message: { text: finding.title },
    locations: [{ physicalLocation: { artifactLocation: { uri: finding.url } } }],
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      cwe: finding.cwe,
      evidence: finding.evidence,
      remediation: finding.remediation,
      parameter: finding.parameter,
      rawRef: finding.rawRef,
    },
  };
}

/**
 * `scan` is part of the endpoint's contract but contributes nothing to the
 * required log shape; SARIF scan-level fields (automationDetails, invocations)
 * are not emitted.
 */
export function buildSarif(scan: ScanRecord, findings: Finding[]): SarifLog {
  void scan;
  // Map iteration order is insertion order, so runs appear in the order each
  // tool's first finding appeared — stable for a severity-sorted input.
  const grouped = new Map<string, SarifResult[]>();
  for (const finding of findings) {
    const results = grouped.get(finding.tool);
    if (results) {
      results.push(toResult(finding));
    } else {
      grouped.set(finding.tool, [toResult(finding)]);
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [...grouped].map(([tool, results]) => ({ tool: { driver: { name: tool } }, results })),
  };
}