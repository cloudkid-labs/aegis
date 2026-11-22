import { sha256Hex } from "../auth";
import type { Asset } from "../types";

// Collision-resistant: a weak rolling hash let distinct values (e.g. /Aa and
// /BB) share an id, and INSERT OR REPLACE then silently dropped one discovery.
async function assetId(scanId: string, type: string, value: string): Promise<string> {
  return (await sha256Hex(`${scanId}|${type}|${value}`)).slice(0, 32);
}

function parseLines(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (typeof data === "string") {
    return data.split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((x): x is Record<string, unknown> => x !== null);
  }
  return [];
}

export async function normalizeSubfinder(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const out: Asset[] = [];
  for (const e of parseLines(data)) {
    const host = e.host as string | undefined;
    if (!host) continue;
    out.push({ id: await assetId(scanId, "subdomain", host), scanId, type: "subdomain", value: host, metadata: JSON.stringify({ source: (e.source as string) ?? "subfinder" }), createdAt: now });
  }
  return out;
}

export async function normalizeHttpx(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const out: Asset[] = [];
  for (const e of parseLines(data)) {
    const url = (e.url as string) ?? (e.host ? `https://${e.host}` : null);
    if (!url) continue;
    out.push({ id: await assetId(scanId, "url", url), scanId, type: "url", value: url, metadata: JSON.stringify({ status_code: e.status_code ?? null, title: e.title ?? null, tech: e.tech ?? [] }), createdAt: now });
  }
  return out;
}

export async function normalizeKatana(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const out: Asset[] = [];
  for (const e of parseLines(data)) {
    const url = (e.request as { endpoint?: string } | undefined)?.endpoint ?? (e.endpoint as string | undefined);
    if (!url) continue;
    out.push({ id: await assetId(scanId, "endpoint", url), scanId, type: "endpoint", value: url, metadata: null, createdAt: now });
  }
  return out;
}

export async function normalizeDnsx(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const out: Asset[] = [];
  for (const e of parseLines(data)) {
    const host = e.host as string | undefined;
    if (!host) continue;
    out.push({ id: await assetId(scanId, "dns", host), scanId, type: "subdomain", value: host, metadata: JSON.stringify({ a: e.a ?? [], cname: e.cname ?? [], resolved: true }), createdAt: now });
  }
  return out;
}

export async function normalizeNaabu(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const out: Asset[] = [];
  for (const e of parseLines(data)) {
    const host = e.host as string | undefined;
    const port = e.port as number | undefined;
    if (!host || !port) continue;
    const value = `${host}:${port}`;
    out.push({ id: await assetId(scanId, "port", value), scanId, type: "endpoint", value, metadata: JSON.stringify({ port, protocol: (e.protocol as string) ?? "tcp" }), createdAt: now });
  }
  return out;
}

export async function normalizeAlterx(data: unknown, scanId: string, now: string): Promise<Asset[]> {
  const lines = typeof data === "string" ? data.split("\n").filter(Boolean) : Array.isArray(data) ? data.map(String) : [];
  const out: Asset[] = [];
  for (const host of lines) {
    const trimmed = host.trim();
    if (!trimmed) continue;
    out.push({ id: await assetId(scanId, "subdomain", trimmed), scanId, type: "subdomain", value: trimmed, metadata: JSON.stringify({ source: "alterx", candidate: true }), createdAt: now });
  }
  return out;
}