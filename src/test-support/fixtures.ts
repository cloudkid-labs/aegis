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

/**
 * One `instances[]` entry of a ZAP alert. The traditional JSON report keeps
 * the occurrence here — uri, param, attack, evidence — not on the alert:
 * https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/
 * ZAP writes "" for "no parameter", "no attack" and "no evidence".
 */
export function zapInstance(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    uri: "https://x.example/",
    nodeName: "https://x.example/",
    method: "GET",
    param: "",
    attack: "",
    evidence: "",
    otherinfo: "",
    ...overrides,
  };
}

/**
 * One ZAP alert entry inside `site[].alerts[]`: rule metadata on the alert,
 * one entry per occurrence in `instances[]`. Default has two instances, the
 * second carrying a parameter and evidence; the first is the empty-parameter,
 * empty-evidence case.
 */
export function zapAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginid: "10021",
    alertRef: "10021",
    alert: "Missing CSP",
    name: "Missing CSP",
    riskcode: "1",
    confidence: "Medium",
    riskdesc: "Medium",
    desc: "d",
    instances: [
      zapInstance(),
      zapInstance({
        uri: "https://x.example/search",
        nodeName: "https://x.example/search (q)",
        param: "q",
        attack: "q=proof",
        evidence: "proof",
      }),
    ],
    count: "2",
    solution: "s",
    otherinfo: "",
    reference: "",
    cweid: "693",
    wascid: "15",
    sourceid: "",
    ...overrides,
  };
}

/** A second, single-instance alert, so the default report covers both shapes. */
function zapSingleInstanceAlert(): Record<string, unknown> {
  return zapAlert({
    pluginid: "10022",
    alertRef: "10022",
    alert: "Missing Anti-clickjacking Header",
    name: "Missing Anti-clickjacking Header",
    riskcode: "2",
    confidence: "High",
    riskdesc: "Low",
    desc: "d2",
    instances: [zapInstance({ uri: "https://x.example/login", nodeName: "https://x.example/login" })],
    count: "1",
    solution: "s2",
    cweid: "1021",
  });
}

/**
 * A ZAP JSON report in the real nested shape: one alert with two instances
 * (one empty param/evidence) and one alert with a single instance.
 */
export function zapReport(
  alerts: Record<string, unknown>[] = [zapAlert(), zapSingleInstanceAlert()],
): Record<string, unknown> {
  return { site: [{ alerts }] };
}