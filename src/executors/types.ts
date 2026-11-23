import type { ScanProfile, ToolEntry } from "../types";

export interface ExecutorStartRequest {
  scanId: string;
  target: string;
  phase: string;
  tools: ToolEntry[];
  callbackUrl: string;
  callbackToken: string;
  timeoutSeconds: number;
  options: Record<string, string | number | boolean>;
  /** Invasion only: the authorized URL selection, sent as a JSON-array input. */
  targets?: string[];
}

export interface ExecutorStartResult {
  externalUrl: string | null;
}

export interface ScanExecutor {
  readonly name: string;
  start(req: ExecutorStartRequest, fetchImpl?: typeof fetch): Promise<ExecutorStartResult>;
}