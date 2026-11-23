import type { Asset, Finding } from "../types";
import { normalizeAlterxResolved, normalizeDnsx, normalizeHttpx, normalizeKatana, normalizeNaabu, normalizeSubfinder } from "./explore";
import { nucleiFindings, zapFindings } from "./invasion";

type NormalizerFn = (data: unknown, scanId: string, now: string) => Promise<Asset[]>;

const NORMALIZERS: Record<string, NormalizerFn> = {
  "subfinder-json": normalizeSubfinder,
  "httpx-json": normalizeHttpx,
  "katana-jsonl": normalizeKatana,
  "dnsx-json": normalizeDnsx,
  "naabu-json": normalizeNaabu,
  "alterx-resolved": normalizeAlterxResolved,
};

export async function normalize(normalizerKey: string, data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const fn = NORMALIZERS[normalizerKey];
  if (!fn) return [];
  return fn(data, scanId, now);
}

/**
 * Findings have their own map and their own entry point: an artifact is routed
 * by its registry entry's outputType, so an invasion key can never be fed to
 * the asset path (and vice versa). `tool` is the registry name of the entry
 * that produced the artifact (zap-baseline vs zap-full), and it is hashed into
 * each finding id because the two profiles can report the same plugin at the
 * same URL.
 */
type FindingNormalizerFn = (tool: string, data: unknown, scanId: string, now: string) => Promise<Finding[]>;

const FINDING_NORMALIZERS: Record<string, FindingNormalizerFn> = {
  "nuclei-jsonl": nucleiFindings,
  "zap-json": zapFindings,
};

export async function normalizeFindings(normalizerKey: string, tool: string, data: unknown, scanId: string, now: string): Promise<Finding[]> {
  // parseRegistry only checks that the normalizer string is non-empty, so a
  // tools.json typo can reach here. A bare lookup would resolve prototype keys
  // ("toString", "constructor") to Object.prototype members and "__proto__" to
  // the prototype object itself; only the map's own keys are normalizers.
  if (!Object.hasOwn(FINDING_NORMALIZERS, normalizerKey)) return [];
  return FINDING_NORMALIZERS[normalizerKey]!(tool, data, scanId, now);
}

export function hasNormalizer(key: string): boolean {
  return Object.hasOwn(NORMALIZERS, key);
}