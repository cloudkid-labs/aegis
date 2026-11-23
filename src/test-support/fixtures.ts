/**
 * Canonical nuclei and ZAP output for the findings normalizers. Shared rather
 * than inlined so the callback ingestion tests (Task 4) feed the normalizers
 * the same records the normalizer tests pin; a fixture that only lives in one
 * test file drifts the moment the other one needs a variant.
 *
 * Shapes are copied from real tool output: nuclei `-jsonl` records and the
 * ZAP JSON report's `site[].alerts[]` entries.
 */

/** `info` block of a nuclei JSONL record; override a single field per test. */
export function nucleiInfo(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "X",
    severity: "high",
    description: "d",
    remediation: "r",
    classification: { "cwe-id": ["CWE-79"] },
    ...overrides,
  };
}

/** One nuclei JSONL record. */
export function nucleiRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    "template-id": "CVE-2024-1234",
    info: nucleiInfo(),
    "matched-at": "https://x.example/a",
    "extracted-results": ["proof"],
    ...overrides,
  };
}

/** One ZAP alert entry inside `site[].alerts[]`. */
export function zapAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginid: "10021",
    alert: "Missing CSP",
    name: "Missing CSP",
    riskdesc: "Medium",
    confidence: "Medium",
    desc: "d",
    solution: "s",
    cweid: "693",
    param: "",
    evidence: "",
    uri: "https://x.example/",
    ...overrides,
  };
}

/** A ZAP JSON report containing one site with the given alerts. */
export function zapReport(alerts: Record<string, unknown>[] = [zapAlert()]): Record<string, unknown> {
  return { site: [{ alerts }] };
}