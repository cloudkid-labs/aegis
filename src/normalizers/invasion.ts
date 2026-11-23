import { sha256Hex } from "../auth";
import type { Confidence, Finding, Severity } from "../types";

/**
 * Findings normalizers. Plain functions rather than the explore record
 * factory: a Finding has no single "value" to key on, the rule id, URL and
 * parameter each come from a different field, and the tool label is supplied
 * by the callback (registry entry), not baked into the output.
 *
 * rawRef stays null here; the callback sets it to the R2 key of the raw
 * artifact once the bytes are stored.
 */

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function json(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** nuclei/zap severities, lowercased; anything unrecognised clamps to info. */
function severityFrom(value: unknown): Severity {
  const word = typeof value === "string" ? value.trim().toLowerCase() : "";
  return SEVERITIES.includes(word as Severity) ? word as Severity : "info";
}

/** `riskdesc` is a phrase like "Medium (Medium)"; risk is the first word. */
function zapSeverity(value: unknown): Severity {
  const word = typeof value === "string" ? value.trim().toLowerCase().split(/[\s(]/)[0] ?? "" : "";
  return severityFrom(word === "informational" ? "info" : word);
}

/** ZAP confidence; "False Positive" is a confidence value, not two words. */
function zapConfidence(value: unknown): Confidence {
  const word = typeof value === "string" ? value.trim().toLowerCase().replace(/\s*\(.*\)$/, "") : "";
  if (word === "confirmed" || word === "high") return "high";
  if (word === "low" || word === "false positive") return "low";
  return "medium";
}

/**
 * nuclei sends `info.classification["cwe-id"]` as an array of "CWE-79"
 * strings; ZAP sends a numeric `cweid` string. The first parseable value
 * wins, and anything absent or non-numeric is null rather than 0.
 */
function parseCwe(value: unknown): number | null {
  for (const candidate of Array.isArray(value) ? value : [value]) {
    if (typeof candidate === "number" && Number.isInteger(candidate)) return candidate;
    if (typeof candidate === "string") {
      const match = /^(?:CWE-)?(\d+)$/i.exec(candidate.trim());
      if (match) return Number(match[1]);
    }
  }
  return null;
}

interface FindingFields {
  tool: string;
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  url: string;
  parameter: string | null;
  evidence: string | null;
  cwe: number | null;
  remediation: string | null;
}

// The tool name is part of the hash on purpose: zap-baseline and zap-full
// report the same plugin at the same URL, and collapsing those ids would make
// one scan's finding silently overwrite the other's on INSERT OR REPLACE.
async function buildFinding(scanId: string, now: string, fields: FindingFields): Promise<Finding> {
  return {
    id: await sha256Hex(`${scanId}|${fields.tool}|${fields.ruleId}|${fields.url}|${fields.parameter ?? ""}`),
    scanId,
    tool: fields.tool,
    severity: fields.severity,
    confidence: fields.confidence,
    title: fields.title,
    description: fields.description,
    url: fields.url,
    parameter: fields.parameter,
    evidence: fields.evidence,
    cwe: fields.cwe,
    remediation: fields.remediation,
    rawRef: null,
    createdAt: now,
  };
}

function nucleiRecords(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data.filter(isRecord);
  if (typeof data === "string") {
    return data.split("\n").filter((line) => line.trim() !== "").map(json).filter(isRecord);
  }
  return [];
}

/** `-jsonl` records; the tool label comes from the registry entry running it. */
export async function nucleiFindings(tool: string, data: unknown, scanId: string, now: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const record of nucleiRecords(data)) {
    const info = asRecord(record.info);
    const templateId = text(record["template-id"]);
    const title = text(info.name) ?? templateId;
    const url = text(record["matched-at"]);
    // Without a URL there is nothing to point the finding at; without a
    // name/template-id there is nothing to call it. Skip rather than store "".
    if (!url || !title) continue;

    const extracted = record["extracted-results"];
    const evidence = Array.isArray(extracted) && extracted.length > 0
      ? extracted.map((entry) => String(entry)).join("; ")
      : text(record["matcher-name"]);

    out.push(await buildFinding(scanId, now, {
      tool,
      ruleId: templateId ?? title,
      severity: severityFrom(info.severity),
      // nuclei reports no confidence; medium matches the clamp ZAP gets.
      confidence: "medium",
      title,
      description: typeof info.description === "string" ? info.description : "",
      url,
      parameter: null,
      evidence,
      cwe: parseCwe(asRecord(info.classification)["cwe-id"]),
      remediation: text(info.remediation),
    }));
  }
  return out;
}

/**
 * ZAP report `site[].alerts[]`, flattened to the alert entries. The rule
 * metadata lives on the alert; the occurrence lives on each `instances[]`
 * entry beneath it. Per the traditional JSON schema
 * (https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/)
 * an alert carries pluginid/alertRef/alert/name/riskcode/confidence/riskdesc/
 * desc/instances/count/solution/otherinfo/reference/cweid/wascid/sourceid,
 * and each instance carries uri/nodeName/method/param/attack/evidence/
 * otherinfo. There is no alert.uri: reading one finds nothing and skips every
 * real alert. Do not flatten these back onto the alert.
 */
function zapAlerts(data: unknown): Record<string, unknown>[] {
  const report = typeof data === "string" ? json(data) : data;
  const sites = asRecord(report).site;
  if (!Array.isArray(sites)) return [];
  const alerts: Record<string, unknown>[] = [];
  for (const site of sites) {
    const list = asRecord(site).alerts;
    if (!Array.isArray(list)) continue;
    for (const alert of list) if (isRecord(alert)) alerts.push(alert);
  }
  return alerts;
}

/** ZAP report `site[].alerts[]`; one Finding per located instance. The tool
 *  label comes from the registry entry running the report. */
export async function zapFindings(tool: string, data: unknown, scanId: string, now: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const alert of zapAlerts(data)) {
    const title = text(alert.alert) ?? text(alert.name);
    if (!title) continue;

    const instances = Array.isArray(alert.instances) ? alert.instances.filter(isRecord) : [];
    for (const instance of instances) {
      // An instance without a uri has nothing to point the finding at; the
      // alert's other instances may still be usable.
      const url = text(instance.uri);
      if (!url) continue;

      out.push(await buildFinding(scanId, now, {
        tool,
        ruleId: text(alert.pluginid) ?? title,
        severity: zapSeverity(alert.riskdesc),
        confidence: zapConfidence(alert.confidence),
        title,
        description: typeof alert.desc === "string" ? alert.desc : "",
        url,
        // ZAP writes "" for "no parameter" and "no evidence"; the attack is
        // the concrete proof when the instance has no evidence.
        parameter: text(instance.param),
        evidence: text(instance.evidence) ?? text(instance.attack),
        cwe: parseCwe(alert.cweid),
        remediation: text(alert.solution),
      }));
    }
  }
  return out;
}

/** nuclei JSONL with the standalone tool label; the callback passes its own. */
export async function normalizeNucleiJsonl(data: unknown, scanId: string, now: string): Promise<Finding[]> {
  return nucleiFindings("nuclei", data, scanId, now);
}

/** ZAP report; zap-baseline is the default profile, so that is the label here. */
export async function normalizeZapJson(data: unknown, scanId: string, now: string): Promise<Finding[]> {
  return zapFindings("zap-baseline", data, scanId, now);
}