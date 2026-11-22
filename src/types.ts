/**
 * Shared vocabulary for the whole platform. Phase 1 only runs `explore`
 * scans, but `invasion` is part of the type surface from day one so the
 * registry, store and dashboard never need a schema change to add it.
 */
export type Phase = "explore" | "invasion";

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type ExecutorName = "github" | "selfhosted";

/**
 * The Phase 1 tool set. A new registry entry still has to be added here to be
 * usable from typed code, but the registry validates by slug at runtime so
 * `tools.json` stays the source of truth for what actually runs.
 */
export type ToolName =
  | "subfinder"
  | "dnsx"
  | "alterx"
  | "httpx"
  | "katana"
  | "naabu"
  | "nuclei"
  | "zap-baseline";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "high" | "medium" | "low";

export type OutputFormat = "json" | "jsonl" | "text" | "sarif";

/** Assets are recon output; findings are attack results. */
export type OutputType = "assets" | "findings";

export type AssetType =
  | "subdomain"
  | "host"
  | "ip"
  | "port"
  | "url"
  | "endpoint"
  | "technology";

/** One entry in tools.json. Adding a tool means adding one of these. */
export interface ToolEntry {
  name: ToolName;
  phase: Phase;
  executor: ExecutorName;
  image: string;
  args: string[];
  outputFormat: OutputFormat;
  outputType: OutputType;
  normalizer: string;
}

/**
 * Per-tool arguments. Unused by Phase 1's registry (which owns the args
 * template in tools.json); kept for the profile presets Phase 3 adds without
 * changing the scan-create contract.
 */
export interface ToolConfig {
  tool: ToolName;
  args: Record<string, string | number | boolean>;
}

export interface ScanProfile {
  name: string;
  description: string;
  timeoutSeconds: number;
  tools: ToolConfig[];
}

export interface Asset {
  id: string;
  scanId: string;
  type: AssetType;
  value: string;
  /** JSON string, e.g. `{"status_code":200,"title":"Home"}`. */
  metadata: string | null;
  createdAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  tool: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  url: string;
  parameter: string | null;
  evidence: string | null;
  cwe: number | null;
  remediation: string | null;
  /** R2 key of the raw tool output this finding was derived from. */
  rawRef: string | null;
  createdAt: string;
}

export interface ScanRecord {
  id: string;
  target: string;
  phase: Phase;
  status: ScanStatus;
  /** Set when an invasion scan consumes an explore scan's assets. */
  parentScanId: string | null;
  executor: ExecutorName;
  externalUrl: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  error: string | null;
  /** JSON string of scan options, e.g. `{"depth":2}`. */
  options: string | null;
}

export interface ScanEvent {
  event: string;
  detail: string | null;
  createdAt: string;
}