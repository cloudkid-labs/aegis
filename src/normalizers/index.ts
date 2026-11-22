import type { Asset } from "../types";
import { normalizeAlterx, normalizeDnsx, normalizeHttpx, normalizeKatana, normalizeNaabu, normalizeSubfinder } from "./explore";

type NormalizerFn = (data: unknown, scanId: string, now: string) => Promise<Asset[]>;

const NORMALIZERS: Record<string, NormalizerFn> = {
  "subfinder-json": normalizeSubfinder,
  "httpx-json": normalizeHttpx,
  "katana-jsonl": normalizeKatana,
  "dnsx-json": normalizeDnsx,
  "naabu-json": normalizeNaabu,
  "alterx-text": normalizeAlterx,
};

export async function normalize(normalizerKey: string, data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const fn = NORMALIZERS[normalizerKey];
  if (!fn) return [];
  return fn(data, scanId, now);
}

export function hasNormalizer(key: string): boolean {
  return Object.hasOwn(NORMALIZERS, key);
}